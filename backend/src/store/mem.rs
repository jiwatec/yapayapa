//! In-memory store for fast tests and database-less development. Mirrors the
//! semantics of `PgStore`, including idempotent enqueue and the group member
//! cap. All data is lost on restart.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use yapayapa_common::types::GroupRole;

use super::{
    AttachmentRecord, GroupMemberRecord, GroupRecord, MessageState, NewUser, QueuedMessage, Result,
    Store, StoreError, UserRecord,
};

#[derive(Default)]
struct Inner {
    users: HashMap<Uuid, UserRecord>,
    sessions: HashMap<String, (Uuid, DateTime<Utc>)>,
    contacts: HashMap<Uuid, Vec<(Uuid, DateTime<Utc>)>>,
    queue: Vec<QueueEntry>,
    status: HashMap<Uuid, (Uuid, MessageState, bool)>,
    groups: HashMap<Uuid, GroupRecord>,
    members: HashMap<Uuid, Vec<(Uuid, GroupRole, DateTime<Utc>)>>,
    attachments: HashMap<Uuid, (AttachmentRecord, Vec<u8>, Vec<Uuid>)>,
}

struct QueueEntry {
    msg: QueuedMessage,
    queued_at: DateTime<Utc>,
    acked: bool,
}

#[derive(Default)]
pub struct MemStore {
    inner: Mutex<Inner>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl Store for MemStore {
    async fn create_user(&self, user: NewUser) -> Result<UserRecord> {
        let mut g = self.inner.lock().unwrap();
        if g.users.values().any(|u| u.username == user.username) {
            return Err(StoreError::Conflict("username"));
        }
        if g.users.values().any(|u| u.public_id == user.public_id) {
            return Err(StoreError::Conflict("public_id"));
        }
        let rec = UserRecord {
            id: Uuid::new_v4(),
            public_id: user.public_id,
            username: user.username,
            password_hash: user.password_hash,
            sign_pub: user.sign_pub,
            dh_pub: user.dh_pub,
            dh_pub_sig: user.dh_pub_sig,
            created_at: Utc::now(),
        };
        g.users.insert(rec.id, rec.clone());
        Ok(rec)
    }

    async fn user_by_username(&self, username: &str) -> Result<Option<UserRecord>> {
        let g = self.inner.lock().unwrap();
        Ok(g.users.values().find(|u| u.username == username).cloned())
    }

    async fn user_by_public_id(&self, public_id: &str) -> Result<Option<UserRecord>> {
        let g = self.inner.lock().unwrap();
        Ok(g.users.values().find(|u| u.public_id == public_id).cloned())
    }

    async fn user_by_id(&self, id: Uuid) -> Result<Option<UserRecord>> {
        let g = self.inner.lock().unwrap();
        Ok(g.users.get(&id).cloned())
    }

    async fn insert_session(
        &self,
        token_hash: &str,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.sessions
            .insert(token_hash.to_string(), (user_id, expires_at));
        Ok(())
    }

    async fn session_user(&self, token_hash: &str) -> Result<Option<Uuid>> {
        let g = self.inner.lock().unwrap();
        Ok(g.sessions
            .get(token_hash)
            .filter(|(_, exp)| *exp > Utc::now())
            .map(|(uid, _)| *uid))
    }

    async fn delete_session(&self, token_hash: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.sessions.remove(token_hash);
        Ok(())
    }

    async fn add_contact(&self, user_id: Uuid, contact_id: Uuid) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let list = g.contacts.entry(user_id).or_default();
        if !list.iter().any(|(c, _)| *c == contact_id) {
            list.push((contact_id, Utc::now()));
        }
        Ok(())
    }

    async fn list_contacts(&self, user_id: Uuid) -> Result<Vec<(UserRecord, DateTime<Utc>)>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<(UserRecord, DateTime<Utc>)> = g
            .contacts
            .get(&user_id)
            .map(|list| {
                list.iter()
                    .filter_map(|(cid, at)| g.users.get(cid).map(|u| (u.clone(), *at)))
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by_key(|(u, _)| u.username.clone());
        Ok(out)
    }

    async fn enqueue_message(&self, msg: &QueuedMessage) -> Result<bool> {
        let mut g = self.inner.lock().unwrap();
        if g.queue.iter().any(|e| e.msg.message_id == msg.message_id) {
            return Ok(false);
        }
        g.queue.push(QueueEntry {
            msg: msg.clone(),
            queued_at: Utc::now(),
            acked: false,
        });
        Ok(true)
    }

    async fn pending_messages(&self, recipient_id: Uuid) -> Result<Vec<QueuedMessage>> {
        let g = self.inner.lock().unwrap();
        let mut entries: Vec<&QueueEntry> = g
            .queue
            .iter()
            .filter(|e| e.msg.recipient_id == recipient_id && !e.acked)
            .collect();
        entries.sort_by_key(|e| e.queued_at);
        Ok(entries.into_iter().map(|e| e.msg.clone()).collect())
    }

    async fn ack_message(&self, message_id: Uuid, recipient_id: Uuid) -> Result<Option<Uuid>> {
        let mut g = self.inner.lock().unwrap();
        for e in g.queue.iter_mut() {
            if e.msg.message_id == message_id && e.msg.recipient_id == recipient_id && !e.acked {
                e.acked = true;
                return Ok(Some(e.msg.sender_id));
            }
        }
        Ok(None)
    }

    async fn upsert_status(
        &self,
        message_id: Uuid,
        sender_id: Uuid,
        state: MessageState,
        notified: bool,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.status.insert(message_id, (sender_id, state, notified));
        Ok(())
    }

    async fn unnotified_receipts(&self, sender_id: Uuid) -> Result<Vec<(Uuid, MessageState)>> {
        let g = self.inner.lock().unwrap();
        Ok(g.status
            .iter()
            .filter(|(_, (sid, _, notified))| *sid == sender_id && !notified)
            .map(|(mid, (_, state, _))| (*mid, *state))
            .collect())
    }

    async fn mark_receipts_notified(&self, sender_id: Uuid, message_ids: &[Uuid]) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        for mid in message_ids {
            if let Some(entry) = g.status.get_mut(mid) {
                if entry.0 == sender_id {
                    entry.2 = true;
                }
            }
        }
        Ok(())
    }

    async fn create_group(&self, name: &str, owner: Uuid) -> Result<GroupRecord> {
        let mut g = self.inner.lock().unwrap();
        let rec = GroupRecord {
            id: Uuid::new_v4(),
            name: name.to_string(),
            created_by: owner,
            key_epoch: 1,
            created_at: Utc::now(),
        };
        g.groups.insert(rec.id, rec.clone());
        g.members
            .insert(rec.id, vec![(owner, GroupRole::Owner, Utc::now())]);
        Ok(rec)
    }

    async fn groups_for_user(&self, user_id: Uuid) -> Result<Vec<GroupRecord>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<GroupRecord> = g
            .groups
            .values()
            .filter(|grp| {
                g.members
                    .get(&grp.id)
                    .is_some_and(|m| m.iter().any(|(u, _, _)| *u == user_id))
            })
            .cloned()
            .collect();
        out.sort_by_key(|grp| grp.created_at);
        Ok(out)
    }

    async fn group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>> {
        let g = self.inner.lock().unwrap();
        Ok(g.groups.get(&group_id).cloned())
    }

    async fn group_members(&self, group_id: Uuid) -> Result<Vec<GroupMemberRecord>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<GroupMemberRecord> = g
            .members
            .get(&group_id)
            .map(|list| {
                list.iter()
                    .filter_map(|(uid, role, at)| {
                        g.users.get(uid).map(|u| GroupMemberRecord {
                            user: u.clone(),
                            role: *role,
                            joined_at: *at,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by_key(|m| m.joined_at);
        Ok(out)
    }

    async fn member_role(&self, group_id: Uuid, user_id: Uuid) -> Result<Option<GroupRole>> {
        let g = self.inner.lock().unwrap();
        Ok(g.members.get(&group_id).and_then(|list| {
            list.iter()
                .find(|(u, _, _)| *u == user_id)
                .map(|(_, r, _)| *r)
        }))
    }

    async fn add_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        role: GroupRole,
        max_members: usize,
    ) -> Result<i64> {
        let mut g = self.inner.lock().unwrap();
        if !g.groups.contains_key(&group_id) {
            return Err(StoreError::NotFound);
        }
        let list = g.members.entry(group_id).or_default();
        if list.iter().any(|(u, _, _)| *u == user_id) {
            return Err(StoreError::Conflict("member"));
        }
        if list.len() >= max_members {
            return Err(StoreError::GroupFull(max_members));
        }
        list.push((user_id, role, Utc::now()));
        let grp = g.groups.get_mut(&group_id).unwrap();
        grp.key_epoch += 1;
        Ok(grp.key_epoch)
    }

    async fn remove_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<i64> {
        let mut g = self.inner.lock().unwrap();
        let list = g.members.get_mut(&group_id).ok_or(StoreError::NotFound)?;
        let before = list.len();
        list.retain(|(u, _, _)| *u != user_id);
        if list.len() == before {
            return Err(StoreError::NotFound);
        }
        let grp = g.groups.get_mut(&group_id).ok_or(StoreError::NotFound)?;
        grp.key_epoch += 1;
        Ok(grp.key_epoch)
    }

    async fn insert_attachment(
        &self,
        owner_id: Uuid,
        blob: &[u8],
        grants: &[Uuid],
    ) -> Result<AttachmentRecord> {
        let mut g = self.inner.lock().unwrap();
        let rec = AttachmentRecord {
            id: Uuid::new_v4(),
            owner_id,
            size: blob.len() as i64,
            created_at: Utc::now(),
        };
        g.attachments
            .insert(rec.id, (rec.clone(), blob.to_vec(), grants.to_vec()));
        Ok(rec)
    }

    async fn attachment_blob(&self, id: Uuid, requester: Uuid) -> Result<Option<Vec<u8>>> {
        let g = self.inner.lock().unwrap();
        Ok(g.attachments.get(&id).and_then(|(rec, blob, grants)| {
            if rec.owner_id == requester || grants.contains(&requester) {
                Some(blob.clone())
            } else {
                None
            }
        }))
    }

    async fn attachments_for_user(&self, user_id: Uuid) -> Result<Vec<AttachmentRecord>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<AttachmentRecord> = g
            .attachments
            .values()
            .filter(|(rec, _, grants)| rec.owner_id == user_id || grants.contains(&user_id))
            .map(|(rec, _, _)| rec.clone())
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        Ok(out)
    }
}
