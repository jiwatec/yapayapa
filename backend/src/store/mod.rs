//! Storage abstraction. `PgStore` is the production implementation;
//! `MemStore` backs fast tests and database-less development. Both store only
//! public key material and ciphertext envelopes — never private keys or
//! plaintext.

pub mod mem;
pub mod pg;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use yapayapa_common::types::GroupRole;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0} already exists")]
    Conflict(&'static str),
    #[error("not found")]
    NotFound,
    #[error("group is full (max {0} members)")]
    GroupFull(usize),
    #[error("storage error: {0}")]
    Backend(String),
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub public_id: String,
    pub username: String,
    pub password_hash: String,
    pub sign_pub: String,
    pub dh_pub: String,
    pub dh_pub_sig: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub public_id: String,
    pub username: String,
    pub password_hash: String,
    pub sign_pub: String,
    pub dh_pub: String,
    pub dh_pub_sig: String,
}

#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub message_id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    pub group_id: Option<Uuid>,
    /// Serialized `SealedEnvelope` JSON — opaque ciphertext to the server.
    pub envelope_json: String,
    pub sent_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct GroupRecord {
    pub id: Uuid,
    pub name: String,
    pub created_by: Uuid,
    pub key_epoch: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct GroupMemberRecord {
    pub user: UserRecord,
    pub role: GroupRole,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AttachmentRecord {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub size: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    SentToRelay,
    Delivered,
    Read,
}

impl MessageState {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageState::SentToRelay => "sent_to_relay",
            MessageState::Delivered => "delivered",
            MessageState::Read => "read",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sent_to_relay" => Some(Self::SentToRelay),
            "delivered" => Some(Self::Delivered),
            "read" => Some(Self::Read),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    // -- users ----------------------------------------------------------
    async fn create_user(&self, user: NewUser) -> Result<UserRecord>;
    async fn user_by_username(&self, username: &str) -> Result<Option<UserRecord>>;
    async fn user_by_public_id(&self, public_id: &str) -> Result<Option<UserRecord>>;
    async fn user_by_id(&self, id: Uuid) -> Result<Option<UserRecord>>;

    // -- sessions ---------------------------------------------------------
    async fn insert_session(
        &self,
        token_hash: &str,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<()>;
    async fn session_user(&self, token_hash: &str) -> Result<Option<Uuid>>;
    async fn delete_session(&self, token_hash: &str) -> Result<()>;

    // -- contacts ---------------------------------------------------------
    async fn add_contact(&self, user_id: Uuid, contact_id: Uuid) -> Result<()>;
    async fn list_contacts(&self, user_id: Uuid) -> Result<Vec<(UserRecord, DateTime<Utc>)>>;

    // -- message queue ----------------------------------------------------
    /// Insert if `message_id` is new. Returns false on duplicate (idempotent).
    async fn enqueue_message(&self, msg: &QueuedMessage) -> Result<bool>;
    /// All not-yet-acked messages for a recipient, oldest first.
    async fn pending_messages(&self, recipient_id: Uuid) -> Result<Vec<QueuedMessage>>;
    /// Recipient durably stored the message. Returns true if newly acked.
    async fn ack_message(&self, message_id: Uuid, recipient_id: Uuid) -> Result<Option<Uuid>>;

    // -- delivery receipts for senders -------------------------------------
    async fn upsert_status(
        &self,
        message_id: Uuid,
        sender_id: Uuid,
        state: MessageState,
        notified: bool,
    ) -> Result<()>;
    async fn unnotified_receipts(&self, sender_id: Uuid) -> Result<Vec<(Uuid, MessageState)>>;
    /// Mark receipts notified, scoped to `sender_id` so a client can only
    /// confirm its own receipts.
    async fn mark_receipts_notified(&self, sender_id: Uuid, message_ids: &[Uuid]) -> Result<()>;

    // -- groups -----------------------------------------------------------
    async fn create_group(&self, name: &str, owner: Uuid) -> Result<GroupRecord>;
    async fn groups_for_user(&self, user_id: Uuid) -> Result<Vec<GroupRecord>>;
    async fn group_by_id(&self, group_id: Uuid) -> Result<Option<GroupRecord>>;
    async fn group_members(&self, group_id: Uuid) -> Result<Vec<GroupMemberRecord>>;
    async fn member_role(&self, group_id: Uuid, user_id: Uuid) -> Result<Option<GroupRole>>;
    /// Adds a member and bumps the key epoch atomically; enforces the member
    /// cap. Returns the new epoch.
    async fn add_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        role: GroupRole,
        max_members: usize,
    ) -> Result<i64>;
    /// Removes a member and bumps the key epoch. Returns the new epoch.
    async fn remove_group_member(&self, group_id: Uuid, user_id: Uuid) -> Result<i64>;

    // -- attachments --------------------------------------------------------
    async fn insert_attachment(
        &self,
        owner_id: Uuid,
        blob: &[u8],
        grants: &[Uuid],
    ) -> Result<AttachmentRecord>;
    /// Returns the blob only if `requester` is the owner or has a grant.
    async fn attachment_blob(&self, id: Uuid, requester: Uuid) -> Result<Option<Vec<u8>>>;
    async fn attachments_for_user(&self, user_id: Uuid) -> Result<Vec<AttachmentRecord>>;
}
