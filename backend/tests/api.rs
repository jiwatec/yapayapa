//! End-to-end API and relay tests against a real listening server (in-memory
//! store). Covers registration, auth, contacts, WebSocket delivery, offline
//! queueing, idempotency, groups, attachments, and the ciphertext-only
//! storage guarantee.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use uuid::Uuid;
use yapayapa_backend::http;
use yapayapa_backend::state::AppState;
use yapayapa_backend::store::mem::MemStore;
use yapayapa_common::crypto::{open, seal, Identity};
use yapayapa_common::types::{
    AuthResponse, ClientFrame, DeliveryState, GroupInfo, ServerFrame, UserPublic, WireMessage,
};

struct TestServer {
    base: String,
    ws_base: String,
    state: Arc<AppState>,
    client: reqwest::Client,
}

async fn spawn_server() -> TestServer {
    let state =
        Arc::new(AppState::new(Box::new(MemStore::new()), 10 * 1024 * 1024).with_auth_rate(1000));
    let router = http::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    TestServer {
        base: format!("http://{addr}"),
        ws_base: format!("ws://{addr}"),
        state,
        client: reqwest::Client::new(),
    }
}

struct TestUser {
    auth: AuthResponse,
    identity: Identity,
}

impl TestServer {
    async fn register(&self, username: &str) -> TestUser {
        let identity = Identity::generate();
        let resp = self
            .client
            .post(format!("{}/api/register", self.base))
            .json(&serde_json::json!({
                "username": username,
                "password": "hunter2hunter2",
                "identity": identity.public(),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "register failed: {}",
            resp.text().await.unwrap()
        );
        TestUser {
            auth: resp.json().await.unwrap(),
            identity,
        }
    }

    async fn ws(
        &self,
        user: &TestUser,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let (stream, _) = tokio_tungstenite::connect_async(format!(
            "{}/api/ws?token={}",
            self.ws_base, user.auth.token
        ))
        .await
        .unwrap();
        stream
    }
}

fn wire_text(sender: &TestUser, recipient: &UserPublic, body: &str) -> WireMessage {
    let envelope = seal(&sender.identity, &recipient.identity, body.as_bytes()).unwrap();
    WireMessage {
        message_id: Uuid::new_v4(),
        sender_id: sender.auth.user.user_id,
        recipient_id: recipient.user_id,
        group_id: None,
        sent_at: chrono::Utc::now(),
        envelope,
    }
}

async fn next_frame<S>(stream: &mut S) -> ServerFrame
where
    S: StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for ws frame")
            .expect("ws closed")
            .expect("ws error");
        if let WsMessage::Text(t) = msg {
            return serde_json::from_str(&t).unwrap();
        }
    }
}

async fn send_frame<S>(stream: &mut S, frame: &ClientFrame)
where
    S: SinkExt<WsMessage> + Unpin,
    S::Error: std::fmt::Debug,
{
    stream
        .send(WsMessage::Text(
            serde_json::to_string(frame).unwrap().into(),
        ))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Accounts and auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_login_me_and_duplicates() {
    let s = spawn_server().await;
    let alice = s.register("Alice_01").await;
    assert_eq!(alice.auth.user.username, "alice_01");
    assert!(yapayapa_common::validate::is_public_id(
        &alice.auth.user.public_id
    ));

    // Duplicate username (different case) conflicts.
    let identity = Identity::generate();
    let resp = s
        .client
        .post(format!("{}/api/register", s.base))
        .json(&serde_json::json!({
            "username": "ALICE_01",
            "password": "hunter2hunter2",
            "identity": identity.public(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Login works, wrong password rejected.
    let resp = s
        .client
        .post(format!("{}/api/login", s.base))
        .json(&serde_json::json!({"username": "alice_01", "password": "hunter2hunter2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let login: AuthResponse = resp.json().await.unwrap();
    assert_eq!(login.user.public_id, alice.auth.user.public_id);

    let resp = s
        .client
        .post(format!("{}/api/login", s.base))
        .json(&serde_json::json!({"username": "alice_01", "password": "wrongwrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // /api/me requires a token and returns only public material.
    let resp = s
        .client
        .get(format!("{}/api/me", s.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let resp = s
        .client
        .get(format!("{}/api/me", s.base))
        .bearer_auth(&alice.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("password"));
    assert!(!body.contains("secret"));
}

#[tokio::test]
async fn register_rejects_private_key_fields_and_bad_identity() {
    let s = spawn_server().await;
    let identity = Identity::generate();

    // Unknown fields (e.g. a private key) are rejected outright.
    let resp = s
        .client
        .post(format!("{}/api/register", s.base))
        .json(&serde_json::json!({
            "username": "mallory",
            "password": "hunter2hunter2",
            "identity": identity.public(),
            "sign_secret": "AAAA",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "unexpected status {}",
        resp.status()
    );

    // Private-key field nested inside the identity bundle is also rejected.
    let mut id_json = serde_json::to_value(identity.public()).unwrap();
    id_json["dh_secret"] = serde_json::json!("AAAA");
    let resp = s
        .client
        .post(format!("{}/api/register", s.base))
        .json(&serde_json::json!({
            "username": "mallory",
            "password": "hunter2hunter2",
            "identity": id_json,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status() == 400 || resp.status() == 422);

    // An identity whose pre-key signature does not verify is rejected.
    let other = Identity::generate();
    let mut forged = identity.public();
    forged.dh_pub = other.public().dh_pub;
    let resp = s
        .client
        .post(format!("{}/api/register", s.base))
        .json(&serde_json::json!({
            "username": "mallory",
            "password": "hunter2hunter2",
            "identity": forged,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn lookup_and_contacts() {
    let s = spawn_server().await;
    let alice = s.register("alice").await;
    let bob = s.register("bob").await;

    // Lookup requires auth.
    let resp = s
        .client
        .get(format!("{}/api/users/bob", s.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // By username, by public id, and by user UUID (clients resolve unknown
    // message senders by the UUID carried on wire messages).
    let bob_uuid = bob.auth.user.user_id.to_string();
    for selector in ["bob", bob.auth.user.public_id.as_str(), bob_uuid.as_str()] {
        let resp = s
            .client
            .get(format!("{}/api/users/{selector}", s.base))
            .bearer_auth(&alice.auth.token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let user: UserPublic = resp.json().await.unwrap();
        assert_eq!(user.user_id, bob.auth.user.user_id);
        user.identity.verify_prekey().unwrap();
    }

    // Add and list contacts.
    let resp = s
        .client
        .post(format!("{}/api/contacts", s.base))
        .bearer_auth(&alice.auth.token)
        .json(&serde_json::json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = s
        .client
        .get(format!("{}/api/contacts", s.base))
        .bearer_auth(&alice.auth.token)
        .send()
        .await
        .unwrap();
    let contacts: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["user"]["username"], "bob");

    // Remove the contact; the list goes empty and stays that way.
    let resp = s
        .client
        .delete(format!("{}/api/contacts/bob", s.base))
        .bearer_auth(&alice.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = s
        .client
        .get(format!("{}/api/contacts", s.base))
        .bearer_auth(&alice.auth.token)
        .send()
        .await
        .unwrap();
    let contacts: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(contacts.is_empty());
}

// ---------------------------------------------------------------------------
// WebSocket relay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn online_delivery_ack_and_ciphertext_only_storage() {
    let s = spawn_server().await;
    let alice = s.register("alice").await;
    let bob = s.register("bob").await;

    let mut alice_ws = s.ws(&alice).await;
    let mut bob_ws = s.ws(&bob).await;

    const SECRET: &str = "the crown jewels are in the vault";
    let msg = wire_text(&alice, &bob.auth.user, SECRET);
    send_frame(
        &mut alice_ws,
        &ClientFrame::Send {
            message: msg.clone(),
        },
    )
    .await;

    // Sender gets Accepted; recipient gets Deliver and can decrypt.
    match next_frame(&mut alice_ws).await {
        ServerFrame::Accepted { message_id } => assert_eq!(message_id, msg.message_id),
        f => panic!("expected Accepted, got {f:?}"),
    }
    let delivered = match next_frame(&mut bob_ws).await {
        ServerFrame::Deliver { message } => message,
        f => panic!("expected Deliver, got {f:?}"),
    };
    assert_eq!(delivered.message_id, msg.message_id);
    let plaintext = open(
        &bob.identity,
        &alice.auth.user.identity,
        &delivered.envelope,
    )
    .unwrap();
    assert_eq!(plaintext, SECRET.as_bytes());

    // The server-side queue holds only ciphertext: the stored envelope JSON
    // must not contain the plaintext anywhere.
    let stored = s
        .state
        .store
        .pending_messages(bob.auth.user.user_id)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert!(!stored[0].envelope_json.contains(SECRET));
    assert!(!stored[0]
        .envelope_json
        .contains(&yapayapa_common::crypto::b64(SECRET.as_bytes())));

    // Ack marks delivered; sender receives a receipt.
    send_frame(
        &mut bob_ws,
        &ClientFrame::Ack {
            message_id: msg.message_id,
        },
    )
    .await;
    match next_frame(&mut alice_ws).await {
        ServerFrame::Receipt { message_id, state } => {
            assert_eq!(message_id, msg.message_id);
            assert_eq!(state, DeliveryState::Delivered);
        }
        f => panic!("expected Receipt, got {f:?}"),
    }

    // After ack the queue is drained.
    let stored = s
        .state
        .store
        .pending_messages(bob.auth.user.user_id)
        .await
        .unwrap();
    assert!(stored.is_empty());
}

#[tokio::test]
async fn offline_queue_reconnect_delivery_and_receipt_backlog() {
    let s = spawn_server().await;
    let alice = s.register("alice").await;
    let bob = s.register("bob").await;

    // Bob is offline; Alice sends and disconnects.
    let mut alice_ws = s.ws(&alice).await;
    let msg = wire_text(&alice, &bob.auth.user, "hello offline bob");
    send_frame(
        &mut alice_ws,
        &ClientFrame::Send {
            message: msg.clone(),
        },
    )
    .await;
    assert!(matches!(
        next_frame(&mut alice_ws).await,
        ServerFrame::Accepted { .. }
    ));
    drop(alice_ws);

    // Bob reconnects and receives the queued envelope, then acks.
    let mut bob_ws = s.ws(&bob).await;
    let delivered = match next_frame(&mut bob_ws).await {
        ServerFrame::Deliver { message } => message,
        f => panic!("expected Deliver, got {f:?}"),
    };
    assert_eq!(delivered.message_id, msg.message_id);
    send_frame(
        &mut bob_ws,
        &ClientFrame::Ack {
            message_id: msg.message_id,
        },
    )
    .await;

    // Wait until the ack is durably recorded (alice is offline, so the
    // receipt must be stored as unnotified).
    for _ in 0..50 {
        if s.state
            .store
            .pending_messages(bob.auth.user.user_id)
            .await
            .unwrap()
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Alice reconnects and receives the delivered receipt from the backlog.
    let mut alice_ws = s.ws(&alice).await;
    match next_frame(&mut alice_ws).await {
        ServerFrame::Receipt { message_id, state } => {
            assert_eq!(message_id, msg.message_id);
            assert_eq!(state, DeliveryState::Delivered);
        }
        f => panic!("expected Receipt, got {f:?}"),
    }

    // She disconnects WITHOUT confirming: the receipt must be re-delivered
    // on the next connection (a queued-but-unprocessed frame is not
    // delivered).
    drop(alice_ws);
    let mut alice_ws = s.ws(&alice).await;
    match next_frame(&mut alice_ws).await {
        ServerFrame::Receipt { message_id, .. } => assert_eq!(message_id, msg.message_id),
        f => panic!("expected re-delivered Receipt, got {f:?}"),
    }

    // After ReceiptAck it stops.
    send_frame(
        &mut alice_ws,
        &ClientFrame::ReceiptAck {
            message_ids: vec![msg.message_id],
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(alice_ws);
    let mut alice_ws = s.ws(&alice).await;
    send_frame(&mut alice_ws, &ClientFrame::Ping).await;
    assert!(
        matches!(next_frame(&mut alice_ws).await, ServerFrame::Pong),
        "receipt should not be re-delivered after ReceiptAck"
    );

    // Bob reconnects again: no duplicate delivery after ack.
    let mut bob_ws2 = s.ws(&bob).await;
    send_frame(&mut bob_ws2, &ClientFrame::Ping).await;
    assert!(matches!(next_frame(&mut bob_ws2).await, ServerFrame::Pong));
}

#[tokio::test]
async fn duplicate_send_is_idempotent() {
    let s = spawn_server().await;
    let alice = s.register("alice").await;
    let bob = s.register("bob").await;

    let mut alice_ws = s.ws(&alice).await;
    let mut bob_ws = s.ws(&bob).await;

    let msg = wire_text(&alice, &bob.auth.user, "only once please");
    for _ in 0..3 {
        send_frame(
            &mut alice_ws,
            &ClientFrame::Send {
                message: msg.clone(),
            },
        )
        .await;
        assert!(matches!(
            next_frame(&mut alice_ws).await,
            ServerFrame::Accepted { .. }
        ));
    }

    // Bob receives exactly one Deliver: the next frame after it must be the
    // Pong for a ping we send, not another Deliver.
    assert!(matches!(
        next_frame(&mut bob_ws).await,
        ServerFrame::Deliver { .. }
    ));
    send_frame(&mut bob_ws, &ClientFrame::Ping).await;
    assert!(matches!(next_frame(&mut bob_ws).await, ServerFrame::Pong));
}

#[tokio::test]
async fn send_validations() {
    let s = spawn_server().await;
    let alice = s.register("alice").await;
    let bob = s.register("bob").await;
    let mut alice_ws = s.ws(&alice).await;

    // Spoofed sender_id is rejected.
    let mut msg = wire_text(&alice, &bob.auth.user, "spoof");
    msg.sender_id = bob.auth.user.user_id;
    msg.recipient_id = alice.auth.user.user_id;
    send_frame(&mut alice_ws, &ClientFrame::Send { message: msg }).await;
    assert!(matches!(
        next_frame(&mut alice_ws).await,
        ServerFrame::Error { .. }
    ));

    // Unknown recipient is rejected.
    let mut msg = wire_text(&alice, &bob.auth.user, "ghost");
    msg.recipient_id = Uuid::new_v4();
    send_frame(&mut alice_ws, &ClientFrame::Send { message: msg }).await;
    assert!(matches!(
        next_frame(&mut alice_ws).await,
        ServerFrame::Error { .. }
    ));

    // Group send without membership is rejected.
    let mut msg = wire_text(&alice, &bob.auth.user, "not a member");
    msg.group_id = Some(Uuid::new_v4());
    send_frame(&mut alice_ws, &ClientFrame::Send { message: msg }).await;
    assert!(matches!(
        next_frame(&mut alice_ws).await,
        ServerFrame::Error { .. }
    ));
}

#[tokio::test]
async fn auth_endpoints_are_rate_limited_per_ip() {
    // Default server (auth_rate_max = 20).
    let state = Arc::new(AppState::new(Box::new(MemStore::new()), 1024 * 1024));
    let router = http::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::new();
    let mut saw_429 = false;
    for _ in 0..25 {
        let resp = client
            .post(format!("http://{addr}/api/login"))
            .json(&serde_json::json!({"username": "nobody", "password": "xxxxxxxxxx"}))
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "expected a 429 after repeated auth attempts");
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

async fn create_group(s: &TestServer, owner: &TestUser, name: &str) -> GroupInfo {
    let resp = s
        .client
        .post(format!("{}/api/groups", s.base))
        .bearer_auth(&owner.auth.token)
        .json(&serde_json::json!({"name": name}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

async fn add_member(
    s: &TestServer,
    actor: &TestUser,
    group_id: Uuid,
    user: &str,
) -> reqwest::Response {
    s.client
        .post(format!("{}/api/groups/{group_id}/members", s.base))
        .bearer_auth(&actor.auth.token)
        .json(&serde_json::json!({"user": user}))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn group_roles_cap_and_epoch() {
    let s = spawn_server().await;
    let owner = s.register("owner").await;
    let member = s.register("member1").await;
    let outsider = s.register("outsider").await;

    let group = create_group(&s, &owner, "Test Group").await;
    assert_eq!(group.key_epoch, 1);
    assert_eq!(group.members.len(), 1);

    // Owner adds a member; epoch bumps.
    let resp = add_member(&s, &owner, group.group_id, "member1").await;
    assert_eq!(resp.status(), 200);
    let info: GroupInfo = resp.json().await.unwrap();
    assert_eq!(info.key_epoch, 2);
    assert_eq!(info.members.len(), 2);

    // Plain members cannot add.
    let resp = add_member(&s, &member, group.group_id, "outsider").await;
    assert_eq!(resp.status(), 403);

    // Non-members cannot even view the group.
    let resp = s
        .client
        .get(format!("{}/api/groups/{}", s.base, group.group_id))
        .bearer_auth(&outsider.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Members cannot remove other members, but can leave.
    let resp = s
        .client
        .delete(format!(
            "{}/api/groups/{}/members/owner",
            s.base, group.group_id
        ))
        .bearer_auth(&member.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = s
        .client
        .delete(format!(
            "{}/api/groups/{}/members/member1",
            s.base, group.group_id
        ))
        .bearer_auth(&member.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let info: GroupInfo = resp.json().await.unwrap();
    assert_eq!(info.key_epoch, 3);
    assert_eq!(info.members.len(), 1);

    // Fill the group to the 20-member cap; the 21st add fails.
    for i in 0..19 {
        let name = format!("filler{i:02}");
        s.register(&name).await;
        let resp = add_member(&s, &owner, group.group_id, &name).await;
        assert_eq!(resp.status(), 200, "adding member {i}");
    }
    s.register("straw").await;
    let resp = add_member(&s, &owner, group.group_id, "straw").await;
    assert_eq!(resp.status(), 409);
    let text = resp.text().await.unwrap();
    assert!(text.contains("full"), "unexpected error: {text}");
}

#[tokio::test]
async fn only_owner_can_delete_group() {
    let s = spawn_server().await;
    let owner = s.register("owner").await;
    let member = s.register("member1").await;
    let outsider = s.register("outsider").await;
    let group = create_group(&s, &owner, "Doomed").await;
    add_member(&s, &owner, group.group_id, "member1").await;

    let del = |user: &TestUser| {
        s.client
            .delete(format!("{}/api/groups/{}", s.base, group.group_id))
            .bearer_auth(&user.auth.token)
            .send()
    };

    // A non-member and a plain member cannot delete.
    assert_eq!(del(&outsider).await.unwrap().status(), 403);
    assert_eq!(del(&member).await.unwrap().status(), 403);

    // The owner can; afterwards the group is gone (404/403 on view).
    assert_eq!(del(&owner).await.unwrap().status(), 204);
    let view = s
        .client
        .get(format!("{}/api/groups/{}", s.base, group.group_id))
        .bearer_auth(&owner.auth.token)
        .send()
        .await
        .unwrap();
    assert!(
        view.status() == 403 || view.status() == 404,
        "deleted group still viewable: {}",
        view.status()
    );
}

#[tokio::test]
async fn owner_leaving_transfers_to_oldest_member() {
    let s = spawn_server().await;
    let owner = s.register("owner").await;
    let m1 = s.register("member1").await;
    let m2 = s.register("member2").await;
    let group = create_group(&s, &owner, "Legacy").await;
    add_member(&s, &owner, group.group_id, "member1").await; // joins first
    add_member(&s, &owner, group.group_id, "member2").await;

    // Owner leaves (self-remove) -> ownership should pass to member1.
    let resp = s
        .client
        .delete(format!("{}/api/groups/{}/members/owner", s.base, group.group_id))
        .bearer_auth(&owner.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // member2 (not the new owner) still can't delete; member1 (new owner) can.
    let d2 = s
        .client
        .delete(format!("{}/api/groups/{}", s.base, group.group_id))
        .bearer_auth(&m2.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(d2.status(), 403);
    let d1 = s
        .client
        .delete(format!("{}/api/groups/{}", s.base, group.group_id))
        .bearer_auth(&m1.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(d1.status(), 204);
}

#[tokio::test]
async fn last_owner_leaving_deletes_the_group() {
    let s = spawn_server().await;
    let owner = s.register("solo").await;
    let group = create_group(&s, &owner, "Alone").await;

    // Owner is the only member; leaving deletes the group.
    let resp = s
        .client
        .delete(format!("{}/api/groups/{}/members/solo", s.base, group.group_id))
        .bearer_auth(&owner.auth.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let info: GroupInfo = resp.json().await.unwrap();
    assert!(info.members.is_empty());

    // The group is gone.
    let view = s
        .client
        .get(format!("{}/api/groups/{}", s.base, group.group_id))
        .bearer_auth(&owner.auth.token)
        .send()
        .await
        .unwrap();
    assert!(view.status() == 403 || view.status() == 404);
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attachment_upload_download_authorization_and_limits() {
    let s = spawn_server().await;
    let alice = s.register("alice").await;
    let bob = s.register("bob").await;
    let eve = s.register("eve").await;

    let blob = vec![0xEEu8; 4096]; // stand-in for ciphertext
    let resp = s
        .client
        .post(format!(
            "{}/api/attachments?grants={}",
            s.base, bob.auth.user.user_id
        ))
        .bearer_auth(&alice.auth.token)
        .body(blob.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let up: serde_json::Value = resp.json().await.unwrap();
    let id = up["attachment_id"].as_str().unwrap();

    // Granted recipient and owner can download; others cannot.
    for (user, expect) in [(&bob, 200), (&alice, 200), (&eve, 404)] {
        let resp = s
            .client
            .get(format!("{}/api/attachments/{id}", s.base))
            .bearer_auth(&user.auth.token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), expect);
        if expect == 200 {
            assert_eq!(resp.bytes().await.unwrap().to_vec(), blob);
        }
    }

    // Unauthenticated download is rejected.
    let resp = s
        .client
        .get(format!("{}/api/attachments/{id}", s.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Oversized upload is rejected.
    let big = vec![0u8; 10 * 1024 * 1024 + 8192];
    let resp = s
        .client
        .post(format!("{}/api/attachments", s.base))
        .bearer_auth(&alice.auth.token)
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn message_sends_do_not_consume_upload_rate_budget() {
    // Regression: the send limiter (240/10s) and the upload limiter (30/min)
    // must use separate buckets. A user who just fanned out many messages
    // (e.g. group key rotations) must still be able to upload an attachment.
    let s = spawn_server().await;
    let alice = s.register("alice").await;
    let bob = s.register("bob").await;

    let mut alice_ws = s.ws(&alice).await;
    for i in 0..40 {
        let msg = wire_text(&alice, &bob.auth.user, &format!("burst {i}"));
        send_frame(&mut alice_ws, &ClientFrame::Send { message: msg }).await;
        assert!(matches!(
            next_frame(&mut alice_ws).await,
            ServerFrame::Accepted { .. }
        ));
    }

    let resp = s
        .client
        .post(format!(
            "{}/api/attachments?grants={}",
            s.base, bob.auth.user.user_id
        ))
        .bearer_auth(&alice.auth.token)
        .body(vec![0xABu8; 512])
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "upload was rate-limited by unrelated message sends"
    );
}
