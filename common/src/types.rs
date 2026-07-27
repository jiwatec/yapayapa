//! Wire types shared by the client and backend. Nothing here ever carries a
//! private key or plaintext message content: message bodies travel only as
//! [`crate::crypto::SealedEnvelope`] ciphertext.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{PublicIdentity, SealedEnvelope};

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub identity: PublicIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserPublic,
}

/// Publicly visible user record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub user_id: Uuid,
    /// Immutable, shareable public ID (e.g. `yp_1a2b3c4d5e6f7a8b`). Never an
    /// authentication secret.
    pub public_id: String,
    pub username: String,
    pub identity: PublicIdentity,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactEntry {
    pub user: UserPublic,
    pub added_at: DateTime<Utc>,
    /// Set by the local client after out-of-band fingerprint verification.
    #[serde(default)]
    pub verified: bool,
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

pub const MAX_GROUP_MEMBERS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
}

impl GroupRole {
    pub fn can_manage_members(self) -> bool {
        matches!(self, GroupRole::Owner | GroupRole::Admin)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            GroupRole::Owner => "owner",
            GroupRole::Admin => "admin",
            GroupRole::Member => "member",
        }
    }
}

impl std::str::FromStr for GroupRole {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(GroupRole::Owner),
            "admin" => Ok(GroupRole::Admin),
            "member" => Ok(GroupRole::Member),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub user: UserPublic,
    pub role: GroupRole,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// Increments on every membership change; clients rotate the group key
    /// when they observe a new epoch.
    pub key_epoch: i64,
    pub members: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberRequest {
    pub user: String, // username or public id
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentUploadResponse {
    pub attachment_id: Uuid,
    pub size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub attachment_id: Uuid,
    pub size: i64,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Message envelopes (relay payload)
// ---------------------------------------------------------------------------

/// Ciphertext envelope plus the minimum routing metadata the relay needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    /// Client-generated, globally unique. Used for idempotency everywhere.
    pub message_id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    /// Present for group messages (fan-out is client-side pairwise for key
    /// distribution, group-key encrypted for content).
    pub group_id: Option<Uuid>,
    pub sent_at: DateTime<Utc>,
    pub envelope: SealedEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    QueuedLocal,
    SentToRelay,
    Delivered,
    Read,
}

// ---------------------------------------------------------------------------
// WebSocket protocol
// ---------------------------------------------------------------------------

/// Client -> server WebSocket frames (JSON text frames).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    /// Send an encrypted envelope to a recipient (relay or queue).
    Send { message: WireMessage },
    /// Recipient acknowledges it durably stored `message_id`.
    Ack { message_id: Uuid },
    /// Sender acknowledges it durably recorded delivery receipts, so the
    /// server can stop re-sending them on reconnect.
    ReceiptAck { message_ids: Vec<Uuid> },
    /// Keepalive.
    Ping,
}

/// Server -> client WebSocket frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// An envelope for this client (live or drained from the offline queue).
    Deliver {
        message: WireMessage,
    },
    /// The relay durably accepted `message_id` from this client.
    Accepted {
        message_id: Uuid,
    },
    /// Delivery receipt for a message this client sent earlier.
    Receipt {
        message_id: Uuid,
        state: DeliveryState,
    },
    /// Error tied to a frame this client sent.
    Error {
        message_id: Option<Uuid>,
        error: String,
    },
    Pong,
}

// ---------------------------------------------------------------------------
// Encrypted message content (INSIDE the sealed envelope; the server never
// sees this structure).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChatContent {
    Text {
        body: String,
    },
    /// Encrypted image attachment: blob is stored server-side, but the key
    /// travels only here, inside the sealed envelope.
    Image {
        attachment_id: Uuid,
        /// base64 one-time ChaCha20-Poly1305 key.
        key: String,
        filename: String,
        mime: String,
        size: u64,
        /// BLAKE3 hex digest of the plaintext image for integrity.
        plaintext_hash: String,
    },
    /// Pairwise distribution of a group content key.
    GroupKey {
        group_id: Uuid,
        epoch: i64,
        /// base64 group content key.
        key: String,
    },
    /// Group message: body encrypted separately with the group key of
    /// `epoch`; this variant is itself sealed pairwise OR carried with group
    /// AEAD — in this MVP group messages are sealed with the group key and
    /// wrapped as `GroupCiphertext` sent pairwise-signed via relay fan-out.
    GroupCiphertext {
        group_id: Uuid,
        epoch: i64,
        /// nonce||ciphertext of a serialized `GroupBody`, base64.
        ct: String,
    },
}

/// Plaintext of a group message, encrypted with the group symmetric key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupBody {
    pub sender_username: String,
    pub sent_at: DateTime<Utc>,
    pub content: Box<ChatContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}
