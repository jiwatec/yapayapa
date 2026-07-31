//! Client-side group key management. Group content keys are generated on the
//! client of whoever changes membership, distributed pairwise inside sealed
//! envelopes (`ChatContent::GroupKey`), and rotated on every membership
//! change (the server bumps `key_epoch`; the actor distributes a fresh key
//! for the new epoch). See docs/THREAT_MODEL.md for the limitations of this
//! design compared to MLS/Sender Keys.

use chrono::Utc;
use uuid::Uuid;
use yapayapa_common::crypto::SymmetricKey;
use yapayapa_common::types::{ChatContent, GroupInfo, UserPublic};

use crate::messaging::{group_ciphertext, seal_wire};
use crate::session::Session;
use crate::store::LocalState;

/// Cache group metadata + membership locally and pin member identities.
pub fn cache_group(session: &Session, info: &GroupInfo) -> anyhow::Result<()> {
    session
        .store
        .upsert_group(info.group_id, &info.name, info.key_epoch)?;
    let ids: Vec<Uuid> = info.members.iter().map(|m| m.user.user_id).collect();
    session.store.replace_group_members(info.group_id, &ids)?;
    for m in &info.members {
        pin_contact(session, &m.user)?;
    }
    Ok(())
}

/// Best-effort refresh of every locally-known group's membership + metadata
/// from the server, so opening the app pulls new members/keys automatically
/// instead of leaving a stale cache that reads "no other members yet" until a
/// manual `groups info`. Individual failures (offline, group removed, an
/// unverifiable member) are skipped so one bad group can't block the rest.
/// Returns how many groups synced cleanly.
pub async fn sync_all_groups(session: &Session) -> usize {
    let Ok(groups) = session.store.list_groups() else {
        return 0;
    };
    let mut synced = 0;
    for (gid, _, _) in groups {
        if let Ok(info) = session.api.group_info(gid).await {
            if cache_group(session, &info).is_ok() {
                synced += 1;
            }
        }
    }
    synced
}

fn pin_contact(session: &Session, user: &UserPublic) -> anyhow::Result<()> {
    if user.user_id == session.keystore.profile.user_id {
        return Ok(());
    }
    user.identity
        .verify_prekey()
        .map_err(|_| anyhow::anyhow!("identity of {} failed verification", user.username))?;
    session.store.upsert_contact(user, false)
}

/// Generate a fresh key for `epoch` and queue pairwise `GroupKey` envelopes
/// to every other member. Returns the number of queued key messages.
pub fn rotate_group_key(session: &Session, info: &GroupInfo) -> anyhow::Result<usize> {
    cache_group(session, info)?;
    let key = SymmetricKey::generate();
    session
        .store
        .store_group_key(info.group_id, info.key_epoch, &key)?;
    let content = ChatContent::GroupKey {
        group_id: info.group_id,
        epoch: info.key_epoch,
        key: yapayapa_common::crypto::b64(&key.0),
    };
    let mut queued = 0;
    for member in &info.members {
        if member.user.user_id == session.keystore.profile.user_id {
            continue;
        }
        seal_wire(
            session,
            Uuid::new_v4(),
            member.user.user_id,
            &member.user.identity,
            Some(info.group_id),
            &content,
            Utc::now(),
        )?;
        queued += 1;
    }
    Ok(queued)
}

/// Compose a group message: encrypt once with the group key, then seal the
/// resulting `GroupCiphertext` pairwise to each cached member. Stores a
/// single local history entry. Returns the history message id.
pub fn compose_group(
    session: &Session,
    group_id: Uuid,
    inner: &ChatContent,
) -> anyhow::Result<Uuid> {
    let Some((epoch, key)) = session.store.latest_group_key(group_id)? else {
        anyhow::bail!(
            "no group key for this group yet — ask an owner/admin to re-add you, or run `yapayapa outbox retry` to fetch pending key messages"
        );
    };
    let members = session.store.cached_group_members(group_id)?;
    let me = session.keystore.profile.user_id;
    let others: Vec<Uuid> = members.into_iter().filter(|m| *m != me).collect();
    if others.is_empty() {
        anyhow::bail!("this group has no other members yet");
    }
    let content = group_ciphertext(session, group_id, epoch, &key, inner)?;
    let sent_at = Utc::now();
    let mut history_id = None;
    for member in others {
        let contact = session
            .store
            .contact_by_id(member)?
            .ok_or_else(|| anyhow::anyhow!("member {member} missing from local contacts — run `yapayapa groups info` while online"))?;
        let wire = seal_wire(
            session,
            Uuid::new_v4(),
            contact.user_id,
            &contact.identity,
            Some(group_id),
            &content,
            sent_at,
        )?;
        // The first fan-out envelope doubles as the history entry so `sent`
        // state tracking works off relay confirmations.
        if history_id.is_none() {
            history_id = Some(wire.message_id);
        }
    }
    let history_id = history_id.unwrap();
    session.store.insert_message(
        history_id,
        &group_id.to_string(),
        me,
        "out",
        sent_at,
        LocalState::QueuedLocal,
        inner,
    )?;
    Ok(history_id)
}

/// If the server reports a newer epoch than our newest key, we cannot encrypt
/// for the current membership; surface that clearly.
pub async fn ensure_current_key(session: &Session, group_id: Uuid) -> anyhow::Result<()> {
    if let Ok(info) = session.api.group_info(group_id).await {
        cache_group(session, &info)?;
        let have = session.store.latest_group_key(group_id)?.map(|(e, _)| e);
        if have != Some(info.key_epoch) {
            anyhow::bail!(
                "group key is out of date (have epoch {:?}, group is at {}). \
                 Waiting for the member-change actor's key message — run `yapayapa outbox retry` to sync.",
                have,
                info.key_epoch
            );
        }
    }
    // Offline: proceed with the newest key we hold (documented limitation).
    Ok(())
}
