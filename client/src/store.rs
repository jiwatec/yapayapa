//! Local SQLite storage: chat history, outbox, contacts, group keys, and
//! attachment metadata. Every sensitive payload (message contents, group
//! keys, attachment keys) is encrypted with the keystore master key before it
//! touches disk; the outbox stores only already-sealed envelopes.

use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;
use yapayapa_common::crypto::{PublicIdentity, SymmetricKey};
use yapayapa_common::types::{ChatContent, UserPublic};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS contacts (
    user_id    TEXT PRIMARY KEY,
    public_id  TEXT NOT NULL,
    username   TEXT NOT NULL,
    sign_pub   TEXT NOT NULL,
    dh_pub     TEXT NOT NULL,
    dh_pub_sig TEXT NOT NULL,
    verified   INTEGER NOT NULL DEFAULT 0,
    added_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    chat_id    TEXT NOT NULL,
    sender_id  TEXT NOT NULL,
    direction  TEXT NOT NULL CHECK (direction IN ('in','out')),
    sent_at    TEXT NOT NULL,
    state      TEXT NOT NULL,
    read_local INTEGER NOT NULL DEFAULT 0,
    content    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, sent_at);
CREATE TABLE IF NOT EXISTS outbox (
    message_id   TEXT PRIMARY KEY,
    recipient_id TEXT NOT NULL,
    group_id     TEXT,
    envelope     TEXT NOT NULL,
    sent_at      TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    epoch    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_keys (
    group_id TEXT NOT NULL,
    epoch    INTEGER NOT NULL,
    key_ct   BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch)
);
CREATE TABLE IF NOT EXISTS group_members_cache (
    group_id TEXT NOT NULL,
    user_id  TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
CREATE TABLE IF NOT EXISTS attachments (
    attachment_id   TEXT PRIMARY KEY,
    message_id      TEXT NOT NULL,
    meta_ct         BLOB NOT NULL,
    downloaded_path TEXT
);
"#;

/// Message delivery state as tracked locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LocalState {
    QueuedLocal,
    Sent,
    Delivered,
    Read,
}

impl LocalState {
    pub fn as_str(self) -> &'static str {
        match self {
            LocalState::QueuedLocal => "queued_local",
            LocalState::Sent => "sent",
            LocalState::Delivered => "delivered",
            LocalState::Read => "read",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "queued_local" => Some(Self::QueuedLocal),
            "sent" => Some(Self::Sent),
            "delivered" => Some(Self::Delivered),
            "read" => Some(Self::Read),
            _ => None,
        }
    }
    pub fn symbol(self) -> &'static str {
        match self {
            LocalState::QueuedLocal => "⌛",
            LocalState::Sent => "✓",
            LocalState::Delivered => "✓✓",
            LocalState::Read => "✓✓",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalMessage {
    pub message_id: Uuid,
    pub sender_id: Uuid,
    pub direction: String,
    pub sent_at: DateTime<Utc>,
    pub state: LocalState,
    pub content: ChatContent,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub user_id: Uuid,
    pub public_id: String,
    pub username: String,
    pub identity: PublicIdentity,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct OutboxEntry {
    pub message_id: Uuid,
    pub recipient_id: Uuid,
    pub group_id: Option<Uuid>,
    pub envelope_json: String,
    pub sent_at: DateTime<Utc>,
}

/// Attachment metadata (decrypted form). Stored encrypted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachmentInfo {
    pub attachment_id: Uuid,
    pub key_b64: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub plaintext_hash: String,
}

pub struct LocalStore {
    conn: Connection,
    master: SymmetricKey,
}

impl LocalStore {
    pub fn open(path: &Path, master: &SymmetricKey) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(md) = std::fs::metadata(path) {
                let mut perms = md.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        Ok(Self {
            conn,
            master: master.clone(),
        })
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.master
            .encrypt(plaintext, aad)
            .map_err(|e| anyhow::anyhow!("local encryption failed: {e}"))
    }

    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.master
            .decrypt(ct, aad)
            .map_err(|e| anyhow::anyhow!("local decryption failed: {e}"))
    }

    // -- contacts ---------------------------------------------------------

    /// Insert or update a contact. Returns `Err` with a loud message if the
    /// stored identity key differs from the new one (possible impersonation)
    /// unless `allow_key_change` is set.
    pub fn upsert_contact(&self, user: &UserPublic, allow_key_change: bool) -> anyhow::Result<()> {
        let existing = self.contact_by_id(user.user_id)?;
        if let Some(existing) = &existing {
            if existing.identity != user.identity && !allow_key_change {
                anyhow::bail!(
                    "SECURITY WARNING: identity key for '{}' has CHANGED since you saved it.\n\
                     This can mean a new install on their side — or an impersonation attempt.\n\
                     Verify fingerprints out of band, then re-add with `contacts add --accept-new-key`.",
                    user.username
                );
            }
        }
        self.conn.execute(
            "INSERT INTO contacts (user_id, public_id, username, sign_pub, dh_pub, dh_pub_sig, verified, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, COALESCE((SELECT verified FROM contacts WHERE user_id = ?1), 0), ?7)
             ON CONFLICT(user_id) DO UPDATE SET
                 public_id = excluded.public_id,
                 username = excluded.username,
                 sign_pub = excluded.sign_pub,
                 dh_pub = excluded.dh_pub,
                 dh_pub_sig = excluded.dh_pub_sig,
                 verified = CASE WHEN contacts.sign_pub = excluded.sign_pub
                                  AND contacts.dh_pub = excluded.dh_pub
                             THEN contacts.verified ELSE 0 END",
            params![
                user.user_id.to_string(),
                user.public_id,
                user.username,
                user.identity.sign_pub,
                user.identity.dh_pub,
                user.identity.dh_pub_sig,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    fn row_to_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<Contact> {
        Ok(Contact {
            user_id: row
                .get::<_, String>(0)?
                .parse()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            public_id: row.get(1)?,
            username: row.get(2)?,
            identity: PublicIdentity {
                sign_pub: row.get(3)?,
                dh_pub: row.get(4)?,
                dh_pub_sig: row.get(5)?,
            },
            verified: row.get::<_, i64>(6)? != 0,
        })
    }

    const CONTACT_COLS: &'static str =
        "user_id, public_id, username, sign_pub, dh_pub, dh_pub_sig, verified";

    pub fn contact_by_id(&self, user_id: Uuid) -> anyhow::Result<Option<Contact>> {
        let q = format!(
            "SELECT {} FROM contacts WHERE user_id = ?1",
            Self::CONTACT_COLS
        );
        Ok(self
            .conn
            .query_row(&q, params![user_id.to_string()], Self::row_to_contact)
            .optional()?)
    }

    /// Find by username or public id.
    pub fn contact_by_selector(&self, selector: &str) -> anyhow::Result<Option<Contact>> {
        let normalized = yapayapa_common::validate::normalize_username(selector);
        let q = format!(
            "SELECT {} FROM contacts WHERE username = ?1 OR public_id = ?2",
            Self::CONTACT_COLS
        );
        Ok(self
            .conn
            .query_row(&q, params![normalized, selector], Self::row_to_contact)
            .optional()?)
    }

    pub fn list_contacts(&self) -> anyhow::Result<Vec<Contact>> {
        let q = format!(
            "SELECT {} FROM contacts ORDER BY username",
            Self::CONTACT_COLS
        );
        let mut stmt = self.conn.prepare(&q)?;
        let rows = stmt.query_map([], Self::row_to_contact)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn set_verified(&self, user_id: Uuid, verified: bool) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE contacts SET verified = ?2 WHERE user_id = ?1",
            params![user_id.to_string(), verified as i64],
        )?;
        Ok(())
    }

    // -- messages -----------------------------------------------------------

    /// Insert a message; returns false if `message_id` already exists
    /// (duplicate-delivery protection).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message(
        &self,
        message_id: Uuid,
        chat_id: &str,
        sender_id: Uuid,
        direction: &str,
        sent_at: DateTime<Utc>,
        state: LocalState,
        content: &ChatContent,
    ) -> anyhow::Result<bool> {
        let plaintext = serde_json::to_vec(content)?;
        let ct = self.encrypt(&plaintext, message_id.as_bytes())?;
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO messages
                 (message_id, chat_id, sender_id, direction, sent_at, state, read_local, content)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                message_id.to_string(),
                chat_id,
                sender_id.to_string(),
                direction,
                sent_at.to_rfc3339(),
                state.as_str(),
                (direction == "out") as i64,
                ct,
            ],
        )?;
        Ok(n == 1)
    }

    /// Advance a message's state (never downgrade).
    pub fn set_state(&self, message_id: Uuid, state: LocalState) -> anyhow::Result<()> {
        let current: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM messages WHERE message_id = ?1",
                params![message_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(current) = current.and_then(|s| LocalState::parse(&s)) else {
            return Ok(());
        };
        if state > current {
            self.conn.execute(
                "UPDATE messages SET state = ?2 WHERE message_id = ?1",
                params![message_id.to_string(), state.as_str()],
            )?;
        }
        Ok(())
    }

    pub fn history(&self, chat_id: &str, limit: usize) -> anyhow::Result<Vec<LocalMessage>> {
        let mut stmt = self.conn.prepare(
            // Order by local insertion order (rowid), not the sender's clock:
            // sent_at comes from each sender's own laptop, so clock skew between
            // two peers would cluster messages by sender instead of interleaving
            // them in true conversation order.
            "SELECT message_id, chat_id, sender_id, direction, sent_at, state, content
             FROM messages WHERE chat_id = ?1
             ORDER BY rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![chat_id, limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (mid, _chat, sender, dir, sent_at, state, ct) = row?;
            let message_id: Uuid = mid.parse()?;
            let plaintext = self.decrypt(&ct, message_id.as_bytes())?;
            out.push(LocalMessage {
                message_id,
                sender_id: sender.parse()?,
                direction: dir,
                sent_at: DateTime::parse_from_rfc3339(&sent_at)?.with_timezone(&Utc),
                state: LocalState::parse(&state).unwrap_or(LocalState::QueuedLocal),
                content: serde_json::from_slice(&plaintext)?,
            });
        }
        out.reverse();
        Ok(out)
    }

    /// Delete all locally stored messages for a chat. This is a local-only
    /// wipe — it cannot affect the other party's copy of the conversation.
    pub fn clear_chat(&self, chat_id: &str) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
        Ok(())
    }

    pub fn unread_count(&self, chat_id: &str) -> anyhow::Result<i64> {
        Ok(self.conn.query_row(
            "SELECT count(*) FROM messages WHERE chat_id = ?1 AND read_local = 0",
            params![chat_id],
            |r| r.get(0),
        )?)
    }

    pub fn mark_chat_read(&self, chat_id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE messages SET read_local = 1 WHERE chat_id = ?1",
            params![chat_id],
        )?;
        Ok(())
    }

    // -- outbox -------------------------------------------------------------

    pub fn outbox_add(&self, e: &OutboxEntry) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO outbox (message_id, recipient_id, group_id, envelope, sent_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                e.message_id.to_string(),
                e.recipient_id.to_string(),
                e.group_id.map(|g| g.to_string()),
                e.envelope_json,
                e.sent_at.to_rfc3339(),
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn outbox_remove(&self, message_id: Uuid) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM outbox WHERE message_id = ?1",
            params![message_id.to_string()],
        )?;
        Ok(())
    }

    pub fn outbox_list(&self) -> anyhow::Result<Vec<OutboxEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, recipient_id, group_id, envelope, sent_at
             FROM outbox ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (mid, rid, gid, env, sent_at) = row?;
            out.push(OutboxEntry {
                message_id: mid.parse()?,
                recipient_id: rid.parse()?,
                group_id: gid.map(|g| g.parse()).transpose()?,
                envelope_json: env,
                sent_at: DateTime::parse_from_rfc3339(&sent_at)?.with_timezone(&Utc),
            });
        }
        Ok(out)
    }

    // -- groups ---------------------------------------------------------------

    pub fn upsert_group(&self, group_id: Uuid, name: &str, epoch: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO groups (group_id, name, epoch) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id) DO UPDATE SET name = excluded.name,
                 epoch = MAX(groups.epoch, excluded.epoch)",
            params![group_id.to_string(), name, epoch],
        )?;
        Ok(())
    }

    pub fn group_name(&self, group_id: Uuid) -> anyhow::Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name FROM groups WHERE group_id = ?1",
                params![group_id.to_string()],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn list_groups(&self) -> anyhow::Result<Vec<(Uuid, String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id, name, epoch FROM groups ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (gid, name, epoch) = row?;
            out.push((gid.parse()?, name, epoch));
        }
        Ok(out)
    }

    pub fn store_group_key(
        &self,
        group_id: Uuid,
        epoch: i64,
        key: &SymmetricKey,
    ) -> anyhow::Result<()> {
        let aad = format!("group-key:{group_id}:{epoch}");
        let ct = self.encrypt(&key.0, aad.as_bytes())?;
        self.conn.execute(
            "INSERT OR REPLACE INTO group_keys (group_id, epoch, key_ct) VALUES (?1, ?2, ?3)",
            params![group_id.to_string(), epoch, ct],
        )?;
        Ok(())
    }

    pub fn group_key(&self, group_id: Uuid, epoch: i64) -> anyhow::Result<Option<SymmetricKey>> {
        let ct: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT key_ct FROM group_keys WHERE group_id = ?1 AND epoch = ?2",
                params![group_id.to_string(), epoch],
                |r| r.get(0),
            )
            .optional()?;
        let Some(ct) = ct else { return Ok(None) };
        let aad = format!("group-key:{group_id}:{epoch}");
        let plain = self.decrypt(&ct, aad.as_bytes())?;
        let bytes: [u8; 32] = plain
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad group key length"))?;
        Ok(Some(SymmetricKey(bytes)))
    }

    /// Highest epoch for which we hold a key.
    pub fn latest_group_key(&self, group_id: Uuid) -> anyhow::Result<Option<(i64, SymmetricKey)>> {
        let epoch: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(epoch) FROM group_keys WHERE group_id = ?1",
                params![group_id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        match epoch {
            Some(e) => Ok(self.group_key(group_id, e)?.map(|k| (e, k))),
            None => Ok(None),
        }
    }

    pub fn replace_group_members(&self, group_id: Uuid, members: &[Uuid]) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM group_members_cache WHERE group_id = ?1",
            params![group_id.to_string()],
        )?;
        for m in members {
            self.conn.execute(
                "INSERT OR IGNORE INTO group_members_cache (group_id, user_id) VALUES (?1, ?2)",
                params![group_id.to_string(), m.to_string()],
            )?;
        }
        Ok(())
    }

    pub fn cached_group_members(&self, group_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
        let mut stmt = self
            .conn
            .prepare("SELECT user_id FROM group_members_cache WHERE group_id = ?1")?;
        let rows = stmt.query_map(params![group_id.to_string()], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?.parse()?);
        }
        Ok(out)
    }

    // -- attachments ----------------------------------------------------------

    pub fn store_attachment(&self, message_id: Uuid, info: &AttachmentInfo) -> anyhow::Result<()> {
        let plaintext = serde_json::to_vec(info)?;
        let ct = self.encrypt(&plaintext, info.attachment_id.as_bytes())?;
        self.conn.execute(
            "INSERT OR REPLACE INTO attachments (attachment_id, message_id, meta_ct, downloaded_path)
             VALUES (?1, ?2, ?3, (SELECT downloaded_path FROM attachments WHERE attachment_id = ?1))",
            params![info.attachment_id.to_string(), message_id.to_string(), ct],
        )?;
        Ok(())
    }

    pub fn attachment(
        &self,
        attachment_id: Uuid,
    ) -> anyhow::Result<Option<(AttachmentInfo, Option<String>)>> {
        let row: Option<(Vec<u8>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT meta_ct, downloaded_path FROM attachments WHERE attachment_id = ?1",
                params![attachment_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((ct, path)) = row else {
            return Ok(None);
        };
        let plain = self.decrypt(&ct, attachment_id.as_bytes())?;
        Ok(Some((serde_json::from_slice(&plain)?, path)))
    }

    pub fn attachment_for_message(
        &self,
        message_id: Uuid,
    ) -> anyhow::Result<Option<AttachmentInfo>> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT attachment_id, meta_ct FROM attachments WHERE message_id = ?1",
                params![message_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((aid, ct)) = row else {
            return Ok(None);
        };
        let aid: Uuid = aid.parse()?;
        let plain = self.decrypt(&ct, aid.as_bytes())?;
        Ok(Some(serde_json::from_slice(&plain)?))
    }

    pub fn list_attachments(&self) -> anyhow::Result<Vec<(AttachmentInfo, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT attachment_id, meta_ct, downloaded_path FROM attachments")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (aid, ct, path) = row?;
            let aid: Uuid = aid.parse()?;
            let plain = self.decrypt(&ct, aid.as_bytes())?;
            out.push((serde_json::from_slice(&plain)?, path));
        }
        Ok(out)
    }

    pub fn set_attachment_path(&self, attachment_id: Uuid, path: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE attachments SET downloaded_path = ?2 WHERE attachment_id = ?1",
            params![attachment_id.to_string(), path],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, LocalStore) {
        let dir = tempfile::tempdir().unwrap();
        let master = SymmetricKey::generate();
        let s = LocalStore::open(&dir.path().join("local.db"), &master).unwrap();
        (dir, s)
    }

    fn text(body: &str) -> ChatContent {
        ChatContent::Text { body: body.into() }
    }

    #[test]
    fn message_roundtrip_dedupe_and_state_progression() {
        let (_d, s) = store();
        let mid = Uuid::new_v4();
        let peer = Uuid::new_v4();
        let chat = peer.to_string();
        assert!(s
            .insert_message(
                mid,
                &chat,
                peer,
                "in",
                Utc::now(),
                LocalState::Sent,
                &text("hi")
            )
            .unwrap());
        // Duplicate insert is ignored.
        assert!(!s
            .insert_message(
                mid,
                &chat,
                peer,
                "in",
                Utc::now(),
                LocalState::Sent,
                &text("hi")
            )
            .unwrap());

        let h = s.history(&chat, 50).unwrap();
        assert_eq!(h.len(), 1);
        assert!(matches!(&h[0].content, ChatContent::Text { body } if body == "hi"));

        // State advances but never regresses.
        s.set_state(mid, LocalState::Delivered).unwrap();
        s.set_state(mid, LocalState::QueuedLocal).unwrap();
        assert_eq!(
            s.history(&chat, 50).unwrap()[0].state,
            LocalState::Delivered
        );
    }

    #[test]
    fn message_content_is_encrypted_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let master = SymmetricKey::generate();
        let path = dir.path().join("local.db");
        let s = LocalStore::open(&path, &master).unwrap();
        let secret = "extremely secret plaintext body";
        s.insert_message(
            Uuid::new_v4(),
            "chat",
            Uuid::new_v4(),
            "out",
            Utc::now(),
            LocalState::QueuedLocal,
            &text(secret),
        )
        .unwrap();
        drop(s);
        let raw = std::fs::read(&path).unwrap();
        let needle = secret.as_bytes();
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "plaintext leaked into local.db"
        );

        // And a store opened with the wrong master key cannot read it.
        let wrong = LocalStore::open(&path, &SymmetricKey::generate()).unwrap();
        assert!(wrong.history("chat", 10).is_err());
    }

    #[test]
    fn outbox_persists_and_removes() {
        let (_d, s) = store();
        let e = OutboxEntry {
            message_id: Uuid::new_v4(),
            recipient_id: Uuid::new_v4(),
            group_id: None,
            envelope_json: r#"{"v":1}"#.into(),
            sent_at: Utc::now(),
        };
        s.outbox_add(&e).unwrap();
        s.outbox_add(&e).unwrap(); // idempotent
        assert_eq!(s.outbox_list().unwrap().len(), 1);
        s.outbox_remove(e.message_id).unwrap();
        assert!(s.outbox_list().unwrap().is_empty());
    }

    #[test]
    fn contact_key_pinning() {
        let (_d, s) = store();
        let id1 = yapayapa_common::crypto::Identity::generate();
        let id2 = yapayapa_common::crypto::Identity::generate();
        let mut user = UserPublic {
            user_id: Uuid::new_v4(),
            public_id: "yp_0123456789abcdef".into(),
            username: "bob".into(),
            identity: id1.public(),
            created_at: Utc::now(),
        };
        s.upsert_contact(&user, false).unwrap();
        s.set_verified(user.user_id, true).unwrap();
        assert!(s.contact_by_selector("bob").unwrap().unwrap().verified);

        // Key change is rejected unless explicitly accepted, and clears the
        // verified flag when accepted.
        user.identity = id2.public();
        assert!(s.upsert_contact(&user, false).is_err());
        s.upsert_contact(&user, true).unwrap();
        assert!(!s.contact_by_selector("bob").unwrap().unwrap().verified);
    }

    #[test]
    fn group_keys_roundtrip_encrypted() {
        let (_d, s) = store();
        let gid = Uuid::new_v4();
        let key = SymmetricKey::generate();
        s.upsert_group(gid, "team", 3).unwrap();
        s.store_group_key(gid, 3, &key).unwrap();
        let (epoch, loaded) = s.latest_group_key(gid).unwrap().unwrap();
        assert_eq!(epoch, 3);
        assert_eq!(loaded.0, key.0);
        assert!(s.group_key(gid, 2).unwrap().is_none());
    }

    #[test]
    fn attachment_meta_roundtrip() {
        let (_d, s) = store();
        let info = AttachmentInfo {
            attachment_id: Uuid::new_v4(),
            key_b64: "a2V5".into(),
            filename: "cat.png".into(),
            mime: "image/png".into(),
            size: 12345,
            plaintext_hash: "abcd".into(),
        };
        let mid = Uuid::new_v4();
        s.store_attachment(mid, &info).unwrap();
        let (loaded, path) = s.attachment(info.attachment_id).unwrap().unwrap();
        assert_eq!(loaded.filename, "cat.png");
        assert!(path.is_none());
        s.set_attachment_path(info.attachment_id, "/tmp/cat.png")
            .unwrap();
        let (_, path) = s.attachment(info.attachment_id).unwrap().unwrap();
        assert_eq!(path.as_deref(), Some("/tmp/cat.png"));
        assert_eq!(s.attachment_for_message(mid).unwrap().unwrap().size, 12345);
    }
}
