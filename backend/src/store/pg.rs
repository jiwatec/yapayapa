//! PostgreSQL store (SQLx, runtime-checked parameterized queries only).

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use yapayapa_common::types::GroupRole;

use super::{
    AttachmentRecord, GroupMemberRecord, GroupRecord, MessageState, NewUser, QueuedMessage, Result,
    Store, StoreError, UserRecord,
};

pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(database_url: &str, migrations_dir: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(database_url)
            .await?;
        let migrator = sqlx::migrate::Migrator::new(std::path::Path::new(migrations_dir)).await?;
        migrator.run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn row_to_user(row: &sqlx::postgres::PgRow) -> UserRecord {
    UserRecord {
        id: row.get("id"),
        public_id: row.get("public_id"),
        username: row.get("username"),
        password_hash: row.get("password_hash"),
        sign_pub: row.get("sign_pub"),
        dh_pub: row.get("dh_pub"),
        dh_pub_sig: row.get("dh_pub_sig"),
        created_at: row.get("created_at"),
    }
}

const USER_COLS: &str =
    "id, public_id, username, password_hash, sign_pub, dh_pub, dh_pub_sig, created_at";

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait::async_trait]
impl Store for PgStore {
    async fn create_user(&self, user: NewUser) -> Result<UserRecord> {
        let q = format!(
            "INSERT INTO users (public_id, username, password_hash, sign_pub, dh_pub, dh_pub_sig)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING {USER_COLS}"
        );
        let row = sqlx::query(&q)
            .bind(&user.public_id)
            .bind(&user.username)
            .bind(&user.password_hash)
            .bind(&user.sign_pub)
            .bind(&user.dh_pub)
            .bind(&user.dh_pub_sig)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                if is_unique_violation(&e) {
                    StoreError::Conflict("username")
                } else {
                    e.into()
                }
            })?;
        Ok(row_to_user(&row))
    }

    async fn user_by_username(&self, username: &str) -> Result<Option<UserRecord>> {
        let q = format!("SELECT {USER_COLS} FROM users WHERE username = $1");
        let row = sqlx::query(&q)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_user))
    }

    async fn user_by_public_id(&self, public_id: &str) -> Result<Option<UserRecord>> {
        let q = format!("SELECT {USER_COLS} FROM users WHERE public_id = $1");
        let row = sqlx::query(&q)
            .bind(public_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_user))
    }

    async fn user_by_id(&self, id: Uuid) -> Result<Option<UserRecord>> {
        let q = format!("SELECT {USER_COLS} FROM users WHERE id = $1");
        let row = sqlx::query(&q).bind(id).fetch_optional(&self.pool).await?;
        Ok(row.as_ref().map(row_to_user))
    }

    async fn insert_session(
        &self,
        token_hash: &str,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
            .bind(token_hash)
            .bind(user_id)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn session_user(&self, token_hash: &str) -> Result<Option<Uuid>> {
        let row = sqlx::query(
            "SELECT user_id FROM sessions WHERE token_hash = $1 AND expires_at > now()",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("user_id")))
    }

    async fn delete_session(&self, token_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn add_contact(&self, user_id: Uuid, contact_id: Uuid) -> Result<()> {
        sqlx::query(
            "INSERT INTO contacts (user_id, contact_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(contact_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_contacts(&self, user_id: Uuid) -> Result<Vec<(UserRecord, DateTime<Utc>)>> {
        let q = "SELECT u.id, u.public_id, u.username, u.password_hash, u.sign_pub, u.dh_pub,
                    u.dh_pub_sig, u.created_at, c.added_at
             FROM contacts c JOIN users u ON u.id = c.contact_id
             WHERE c.user_id = $1 ORDER BY u.username"
            .to_string();
        let rows = sqlx::query(&q).bind(user_id).fetch_all(&self.pool).await?;
        Ok(rows
            .iter()
            .map(|r| (row_to_user(r), r.get("added_at")))
            .collect())
    }

    async fn enqueue_message(&self, msg: &QueuedMessage) -> Result<bool> {
        let res = sqlx::query(
            "INSERT INTO encrypted_message_queue
                 (message_id, sender_id, recipient_id, group_id, envelope, sent_at)
             VALUES ($1, $2, $3, $4, $5::jsonb, $6)
             ON CONFLICT (message_id) DO NOTHING",
        )
        .bind(msg.message_id)
        .bind(msg.sender_id)
        .bind(msg.recipient_id)
        .bind(msg.group_id)
        .bind(&msg.envelope_json)
        .bind(msg.sent_at)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    async fn pending_messages(&self, recipient_id: Uuid) -> Result<Vec<QueuedMessage>> {
        let rows = sqlx::query(
            "SELECT message_id, sender_id, recipient_id, group_id, envelope::text AS envelope_json, sent_at
             FROM encrypted_message_queue
             WHERE recipient_id = $1 AND NOT acked
             ORDER BY queued_at ASC",
        )
        .bind(recipient_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| QueuedMessage {
                message_id: r.get("message_id"),
                sender_id: r.get("sender_id"),
                recipient_id: r.get("recipient_id"),
                group_id: r.get("group_id"),
                envelope_json: r.get("envelope_json"),
                sent_at: r.get("sent_at"),
            })
            .collect())
    }

    async fn ack_message(&self, message_id: Uuid, recipient_id: Uuid) -> Result<Option<Uuid>> {
        let row = sqlx::query(
            "UPDATE encrypted_message_queue
             SET acked = TRUE, delivered_at = now()
             WHERE message_id = $1 AND recipient_id = $2 AND NOT acked
             RETURNING sender_id",
        )
        .bind(message_id)
        .bind(recipient_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("sender_id")))
    }

    async fn upsert_status(
        &self,
        message_id: Uuid,
        sender_id: Uuid,
        state: MessageState,
        notified: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO message_status (message_id, sender_id, state, notified)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (message_id)
             DO UPDATE SET state = EXCLUDED.state, notified = EXCLUDED.notified,
                           updated_at = now()",
        )
        .bind(message_id)
        .bind(sender_id)
        .bind(state.as_str())
        .bind(notified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn unnotified_receipts(&self, sender_id: Uuid) -> Result<Vec<(Uuid, MessageState)>> {
        let rows = sqlx::query(
            "SELECT message_id, state FROM message_status
             WHERE sender_id = $1 AND NOT notified",
        )
        .bind(sender_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                MessageState::parse(r.get::<String, _>("state").as_str())
                    .map(|s| (r.get("message_id"), s))
            })
            .collect())
    }

    async fn mark_receipts_notified(&self, sender_id: Uuid, message_ids: &[Uuid]) -> Result<()> {
        sqlx::query(
            "UPDATE message_status SET notified = TRUE
             WHERE sender_id = $1 AND message_id = ANY($2)",
        )
        .bind(sender_id)
        .bind(message_ids)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_group(&self, name: &str, owner: Uuid) -> Result<GroupRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "INSERT INTO groups (name, created_by) VALUES ($1, $2)
             RETURNING id, name, created_by, key_epoch, created_at",
        )
        .bind(name)
        .bind(owner)
        .fetch_one(&mut *tx)
        .await?;
        let group = GroupRecord {
            id: row.get("id"),
            name: row.get("name"),
            created_by: row.get("created_by"),
            key_epoch: row.get("key_epoch"),
            created_at: row.get("created_at"),
        };
        sqlx::query("INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(group.id)
            .bind(owner)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(group)
    }

    async fn groups_for_user(&self, user_id: Uuid) -> Result<Vec<GroupRecord>> {
        let rows = sqlx::query(
            "SELECT g.id, g.name, g.created_by, g.key_epoch, g.created_at
             FROM groups g JOIN group_members m ON m.group_id = g.id
             WHERE m.user_id = $1 ORDER BY g.created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| GroupRecord {
                id: r.get("id"),
                name: r.get("name"),
                created_by: r.get("created_by"),
                key_epoch: r.get("key_epoch"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>> {
        let row = sqlx::query(
            "SELECT id, name, created_by, key_epoch, created_at FROM groups WHERE id = $1",
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| GroupRecord {
            id: r.get("id"),
            name: r.get("name"),
            created_by: r.get("created_by"),
            key_epoch: r.get("key_epoch"),
            created_at: r.get("created_at"),
        }))
    }

    async fn group_members(&self, group_id: Uuid) -> Result<Vec<GroupMemberRecord>> {
        let q = "SELECT u.id, u.public_id, u.username, u.password_hash, u.sign_pub, u.dh_pub,
                    u.dh_pub_sig, u.created_at, m.role, m.joined_at
             FROM group_members m JOIN users u ON u.id = m.user_id
             WHERE m.group_id = $1 ORDER BY m.joined_at"
            .to_string();
        let rows = sqlx::query(&q).bind(group_id).fetch_all(&self.pool).await?;
        Ok(rows
            .iter()
            .map(|r| GroupMemberRecord {
                user: row_to_user(r),
                role: r
                    .get::<String, _>("role")
                    .parse()
                    .unwrap_or(GroupRole::Member),
                joined_at: r.get("joined_at"),
            })
            .collect())
    }

    async fn member_role(&self, group_id: Uuid, user_id: Uuid) -> Result<Option<GroupRole>> {
        let row =
            sqlx::query("SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2")
                .bind(group_id)
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|r| r.get::<String, _>("role").parse().ok()))
    }

    async fn add_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        role: GroupRole,
        max_members: usize,
    ) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        // Lock the group row so concurrent adds cannot exceed the cap.
        let locked = sqlx::query("SELECT id FROM groups WHERE id = $1 FOR UPDATE")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
        if locked.is_none() {
            return Err(StoreError::NotFound);
        }
        let count: i64 = sqlx::query("SELECT count(*) AS n FROM group_members WHERE group_id = $1")
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await?
            .get("n");
        if count as usize >= max_members {
            return Err(StoreError::GroupFull(max_members));
        }
        let res = sqlx::query(
            "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(group_id)
        .bind(user_id)
        .bind(role.as_str())
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::Conflict("member"));
        }
        let epoch: i64 = sqlx::query(
            "UPDATE groups SET key_epoch = key_epoch + 1 WHERE id = $1 RETURNING key_epoch",
        )
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await?
        .get("key_epoch");
        tx.commit().await?;
        Ok(epoch)
    }

    async fn remove_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2")
            .bind(group_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        let epoch: i64 = sqlx::query(
            "UPDATE groups SET key_epoch = key_epoch + 1 WHERE id = $1 RETURNING key_epoch",
        )
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await?
        .get("key_epoch");
        tx.commit().await?;
        Ok(epoch)
    }

    async fn insert_attachment(
        &self,
        owner_id: Uuid,
        blob: &[u8],
        grants: &[Uuid],
    ) -> Result<AttachmentRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "INSERT INTO attachments (owner_id, size, blob) VALUES ($1, $2, $3)
             RETURNING id, owner_id, size, created_at",
        )
        .bind(owner_id)
        .bind(blob.len() as i64)
        .bind(blob)
        .fetch_one(&mut *tx)
        .await?;
        let rec = AttachmentRecord {
            id: row.get("id"),
            owner_id: row.get("owner_id"),
            size: row.get("size"),
            created_at: row.get("created_at"),
        };
        for grant in grants {
            sqlx::query(
                "INSERT INTO attachment_grants (attachment_id, user_id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(rec.id)
            .bind(grant)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(rec)
    }

    async fn attachment_blob(&self, id: Uuid, requester: Uuid) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query(
            "SELECT a.blob FROM attachments a
             WHERE a.id = $1 AND (a.owner_id = $2 OR EXISTS (
                 SELECT 1 FROM attachment_grants g
                 WHERE g.attachment_id = a.id AND g.user_id = $2))",
        )
        .bind(id)
        .bind(requester)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("blob")))
    }

    async fn attachments_for_user(&self, user_id: Uuid) -> Result<Vec<AttachmentRecord>> {
        let rows = sqlx::query(
            "SELECT DISTINCT a.id, a.owner_id, a.size, a.created_at
             FROM attachments a
             LEFT JOIN attachment_grants g ON g.attachment_id = a.id
             WHERE a.owner_id = $1 OR g.user_id = $1
             ORDER BY a.created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AttachmentRecord {
                id: r.get("id"),
                owner_id: r.get("owner_id"),
                size: r.get("size"),
                created_at: r.get("created_at"),
            })
            .collect())
    }
}
