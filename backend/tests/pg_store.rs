//! PgStore integration tests against real PostgreSQL. These run only when
//! `DATABASE_URL` is set (locally against the dev Postgres, and in CI against
//! the service container); otherwise they skip.

use uuid::Uuid;
use yapayapa_backend::store::pg::PgStore;
use yapayapa_backend::store::{NewUser, QueuedMessage, Store, StoreError};
use yapayapa_common::types::GroupRole;

async fn store() -> Option<PgStore> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let migrations = concat!(env!("CARGO_MANIFEST_DIR"), "/../migrations");
    Some(
        PgStore::connect(&url, migrations)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..12])
}

async fn mk_user(store: &PgStore, prefix: &str) -> yapayapa_backend::store::UserRecord {
    store
        .create_user(NewUser {
            public_id: format!("yp_{}", &Uuid::new_v4().simple().to_string()[..16]),
            username: unique(prefix),
            password_hash: "$argon2id$dummy".into(),
            sign_pub: "c2lnbg==".into(),
            dh_pub: "ZGg=".into(),
            dh_pub_sig: "c2ln".into(),
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn pg_users_sessions_contacts() {
    let Some(store) = store().await else { return };
    let alice = mk_user(&store, "alice").await;
    let bob = mk_user(&store, "bob").await;

    // Unique username enforced by the database.
    let dup = store
        .create_user(NewUser {
            public_id: format!("yp_{}", &Uuid::new_v4().simple().to_string()[..16]),
            username: alice.username.clone(),
            password_hash: "x".into(),
            sign_pub: "eA==".into(),
            dh_pub: "eA==".into(),
            dh_pub_sig: "eA==".into(),
        })
        .await;
    assert!(matches!(dup, Err(StoreError::Conflict(_))));

    // Lookups.
    assert_eq!(
        store
            .user_by_username(&alice.username)
            .await
            .unwrap()
            .unwrap()
            .id,
        alice.id
    );
    assert_eq!(
        store
            .user_by_public_id(&alice.public_id)
            .await
            .unwrap()
            .unwrap()
            .id,
        alice.id
    );

    // Sessions expire and delete.
    let hash = unique("tok");
    store
        .insert_session(
            &hash,
            alice.id,
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    assert_eq!(store.session_user(&hash).await.unwrap(), Some(alice.id));
    store.delete_session(&hash).await.unwrap();
    assert_eq!(store.session_user(&hash).await.unwrap(), None);

    let expired = unique("tok");
    store
        .insert_session(
            &expired,
            alice.id,
            chrono::Utc::now() - chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    assert_eq!(store.session_user(&expired).await.unwrap(), None);

    // Contacts.
    store.add_contact(alice.id, bob.id).await.unwrap();
    store.add_contact(alice.id, bob.id).await.unwrap(); // idempotent
    let contacts = store.list_contacts(alice.id).await.unwrap();
    assert!(contacts.iter().any(|(u, _)| u.id == bob.id));
}

#[tokio::test]
async fn pg_queue_idempotency_and_ack() {
    let Some(store) = store().await else { return };
    let alice = mk_user(&store, "qa").await;
    let bob = mk_user(&store, "qb").await;

    let msg = QueuedMessage {
        message_id: Uuid::new_v4(),
        sender_id: alice.id,
        recipient_id: bob.id,
        group_id: None,
        envelope_json: r#"{"v":1,"eph_pub":"x","nonce":"x","ct":"x","sig":"x"}"#.into(),
        sent_at: chrono::Utc::now(),
    };
    assert!(store.enqueue_message(&msg).await.unwrap());
    assert!(!store.enqueue_message(&msg).await.unwrap()); // duplicate ignored

    let pending = store.pending_messages(bob.id).await.unwrap();
    assert_eq!(
        pending
            .iter()
            .filter(|m| m.message_id == msg.message_id)
            .count(),
        1
    );

    // Only the recipient can ack; acks are idempotent.
    assert_eq!(
        store.ack_message(msg.message_id, alice.id).await.unwrap(),
        None
    );
    assert_eq!(
        store.ack_message(msg.message_id, bob.id).await.unwrap(),
        Some(alice.id)
    );
    assert_eq!(
        store.ack_message(msg.message_id, bob.id).await.unwrap(),
        None
    );
    assert!(store
        .pending_messages(bob.id)
        .await
        .unwrap()
        .iter()
        .all(|m| m.message_id != msg.message_id));

    // Receipt storage for offline senders.
    store
        .upsert_status(
            msg.message_id,
            alice.id,
            yapayapa_backend::store::MessageState::Delivered,
            false,
        )
        .await
        .unwrap();
    let receipts = store.unnotified_receipts(alice.id).await.unwrap();
    assert!(receipts.iter().any(|(id, _)| *id == msg.message_id));
    // Another user cannot confirm someone else's receipts.
    store
        .mark_receipts_notified(bob.id, &[msg.message_id])
        .await
        .unwrap();
    assert!(store
        .unnotified_receipts(alice.id)
        .await
        .unwrap()
        .iter()
        .any(|(id, _)| *id == msg.message_id));
    store
        .mark_receipts_notified(alice.id, &[msg.message_id])
        .await
        .unwrap();
    assert!(store
        .unnotified_receipts(alice.id)
        .await
        .unwrap()
        .iter()
        .all(|(id, _)| *id != msg.message_id));
}

#[tokio::test]
async fn pg_groups_cap_roles_epoch() {
    let Some(store) = store().await else { return };
    let owner = mk_user(&store, "gown").await;
    let group = store.create_group("pg test group", owner.id).await.unwrap();
    assert_eq!(group.key_epoch, 1);
    assert_eq!(
        store.member_role(group.id, owner.id).await.unwrap(),
        Some(GroupRole::Owner)
    );

    // Cap of 4 for a fast test (production passes MAX_GROUP_MEMBERS = 20).
    let mut last_epoch = group.key_epoch;
    for i in 0..3 {
        let u = mk_user(&store, &format!("gm{i}")).await;
        last_epoch = store
            .add_group_member(group.id, u.id, GroupRole::Member, 4)
            .await
            .unwrap();
    }
    assert_eq!(last_epoch, 4); // three adds bumped 1 -> 4
    let extra = mk_user(&store, "gx").await;
    assert!(matches!(
        store
            .add_group_member(group.id, extra.id, GroupRole::Member, 4)
            .await,
        Err(StoreError::GroupFull(4))
    ));

    let members = store.group_members(group.id).await.unwrap();
    assert_eq!(members.len(), 4);
    let victim = members
        .iter()
        .find(|m| m.role == GroupRole::Member)
        .unwrap();
    let epoch = store
        .remove_group_member(group.id, victim.user.id)
        .await
        .unwrap();
    assert_eq!(epoch, 5);
}

#[tokio::test]
async fn pg_attachment_authorization() {
    let Some(store) = store().await else { return };
    let owner = mk_user(&store, "aow").await;
    let granted = mk_user(&store, "agr").await;
    let stranger = mk_user(&store, "ast").await;

    let blob = vec![7u8; 1024];
    let rec = store
        .insert_attachment(owner.id, &blob, &[granted.id])
        .await
        .unwrap();
    assert_eq!(rec.size, 1024);
    assert_eq!(
        store.attachment_blob(rec.id, owner.id).await.unwrap(),
        Some(blob.clone())
    );
    assert_eq!(
        store.attachment_blob(rec.id, granted.id).await.unwrap(),
        Some(blob)
    );
    assert_eq!(
        store.attachment_blob(rec.id, stranger.id).await.unwrap(),
        None
    );
}
