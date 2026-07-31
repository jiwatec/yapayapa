//! REST API handlers. Every handler works exclusively with public key
//! material, password hashes, and ciphertext blobs — plaintext and private
//! keys never appear in any request or response schema.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;
use yapayapa_common::crypto::PublicIdentity;
use yapayapa_common::types::{
    ApiError, AttachmentMeta, AttachmentUploadResponse, AuthResponse, ContactEntry,
    CreateGroupRequest, GroupInfo, GroupMember, GroupMemberRequest, GroupRole, LoginRequest,
    RegisterRequest, UserPublic, MAX_GROUP_MEMBERS,
};
use yapayapa_common::validate;

use crate::auth::{create_session, hash_password, verify_password, AuthUser};
use crate::state::{AppState, RateKey};
use crate::store::{StoreError, UserRecord};

pub struct ApiErr(pub StatusCode, pub String);

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(ApiError { error: self.1 })).into_response()
    }
}

impl From<StoreError> for ApiErr {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Conflict(what) => {
                ApiErr(StatusCode::CONFLICT, format!("{what} already exists"))
            }
            StoreError::NotFound => ApiErr(StatusCode::NOT_FOUND, "not found".into()),
            StoreError::GroupFull(n) => ApiErr(
                StatusCode::CONFLICT,
                format!("group is full (max {n} members)"),
            ),
            StoreError::Backend(e) => {
                tracing::error!(error = %e, "storage error");
                ApiErr(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        }
    }
}

fn bad(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::BAD_REQUEST, msg.into())
}

pub fn user_public(u: &UserRecord) -> UserPublic {
    UserPublic {
        user_id: u.id,
        public_id: u.public_id.clone(),
        username: u.username.clone(),
        identity: PublicIdentity {
            sign_pub: u.sign_pub.clone(),
            dh_pub: u.dh_pub.clone(),
            dh_pub_sig: u.dh_pub_sig.clone(),
        },
        created_at: u.created_at,
    }
}

fn new_public_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("yp_{}", hex::encode(b))
}

/// Resolve a username, `yp_...` public ID, or user UUID to a user record.
/// UUID resolution lets clients pin the identity of an unknown message
/// sender (wire messages carry sender UUIDs, not usernames).
pub async fn resolve_user(state: &AppState, selector: &str) -> Result<UserRecord, ApiErr> {
    let user = if validate::is_public_id(selector) {
        state.store.user_by_public_id(selector).await?
    } else if let Ok(id) = selector.parse::<uuid::Uuid>() {
        state.store.user_by_id(id).await?
    } else {
        let normalized = validate::normalize_username(selector);
        state.store.user_by_username(&normalized).await?
    };
    user.ok_or(ApiErr(StatusCode::NOT_FOUND, "user not found".into()))
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, ApiErr> {
    if !state.rate_allow(
        RateKey::AuthIp(addr.ip()),
        state.auth_rate_max,
        Duration::from_secs(300),
    ) {
        return Err(ApiErr(StatusCode::TOO_MANY_REQUESTS, "slow down".into()));
    }
    let username = validate::normalize_username(&req.username);
    validate::validate_username(&username).map_err(bad)?;
    validate::validate_password(&req.password).map_err(bad)?;
    // The identity bundle must be self-consistent public material: a DH
    // pre-key signed by the Ed25519 identity. Reject anything else.
    req.identity
        .verify_prekey()
        .map_err(|_| bad("invalid identity bundle: pre-key signature does not verify"))?;

    let password_hash = hash_password(&req.password)
        .map_err(|_| ApiErr(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed".into()))?;
    let user = state
        .store
        .create_user(crate::store::NewUser {
            public_id: new_public_id(),
            username,
            password_hash,
            sign_pub: req.identity.sign_pub,
            dh_pub: req.identity.dh_pub,
            dh_pub_sig: req.identity.dh_pub_sig,
        })
        .await?;
    let token = create_session(&state, user.id).await?;
    tracing::info!(username = %user.username, public_id = %user.public_id, "user registered");
    Ok(Json(AuthResponse {
        token,
        user: user_public(&user),
    }))
}

async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiErr> {
    if !state.rate_allow(
        RateKey::AuthIp(addr.ip()),
        state.auth_rate_max,
        Duration::from_secs(300),
    ) {
        return Err(ApiErr(StatusCode::TOO_MANY_REQUESTS, "slow down".into()));
    }
    let username = validate::normalize_username(&req.username);
    let user = state.store.user_by_username(&username).await?;
    // Constant-shaped flow: verify against a dummy hash when the user does
    // not exist so response timing does not reveal valid usernames cheaply.
    const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ok = match &user {
        Some(u) => verify_password(&u.password_hash, &req.password),
        None => {
            let _ = verify_password(DUMMY, &req.password);
            false
        }
    };
    let user = match (ok, user) {
        (true, Some(u)) => u,
        _ => {
            return Err(ApiErr(
                StatusCode::UNAUTHORIZED,
                "invalid username or password".into(),
            ))
        }
    };
    let token = create_session(&state, user.id).await?;
    Ok(Json(AuthResponse {
        token,
        user: user_public(&user),
    }))
}

async fn logout(State(state): State<Arc<AppState>>, auth: AuthUser) -> Result<StatusCode, ApiErr> {
    state.store.delete_session(&auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<Json<UserPublic>, ApiErr> {
    let user = state
        .store
        .user_by_id(auth.user_id)
        .await?
        .ok_or(ApiErr(StatusCode::NOT_FOUND, "user not found".into()))?;
    Ok(Json(user_public(&user)))
}

async fn lookup(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
    Path(selector): Path<String>,
) -> Result<Json<UserPublic>, ApiErr> {
    let user = resolve_user(&state, &selector).await?;
    Ok(Json(user_public(&user)))
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

async fn add_contact(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<GroupMemberRequest>,
) -> Result<Json<UserPublic>, ApiErr> {
    let contact = resolve_user(&state, &req.user).await?;
    if contact.id == auth.user_id {
        return Err(bad("cannot add yourself as a contact"));
    }
    state.store.add_contact(auth.user_id, contact.id).await?;
    Ok(Json(user_public(&contact)))
}

async fn remove_contact(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(selector): Path<String>,
) -> Result<StatusCode, ApiErr> {
    let contact = resolve_user(&state, &selector).await?;
    state.store.remove_contact(auth.user_id, contact.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_contacts(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<Json<Vec<ContactEntry>>, ApiErr> {
    let contacts = state.store.list_contacts(auth.user_id).await?;
    Ok(Json(
        contacts
            .iter()
            .map(|(u, at)| ContactEntry {
                user: user_public(u),
                added_at: *at,
                verified: false,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

async fn create_group(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupInfo>, ApiErr> {
    validate::validate_group_name(&req.name).map_err(bad)?;
    let group = state
        .store
        .create_group(req.name.trim(), auth.user_id)
        .await?;
    group_info(&state, group.id).await.map(Json)
}

async fn group_info(state: &AppState, group_id: Uuid) -> Result<GroupInfo, ApiErr> {
    let group = state
        .store
        .group_by_id(group_id)
        .await?
        .ok_or(StoreError::NotFound)?;
    let members = state.store.group_members(group_id).await?;
    Ok(GroupInfo {
        group_id: group.id,
        name: group.name,
        created_at: group.created_at,
        key_epoch: group.key_epoch,
        members: members
            .iter()
            .map(|m| GroupMember {
                user: user_public(&m.user),
                role: m.role,
                joined_at: m.joined_at,
            })
            .collect(),
    })
}

async fn list_groups(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<Json<Vec<GroupInfo>>, ApiErr> {
    let groups = state.store.groups_for_user(auth.user_id).await?;
    let mut out = Vec::with_capacity(groups.len());
    for g in groups {
        out.push(group_info(&state, g.id).await?);
    }
    Ok(Json(out))
}

/// Membership is required even to view group info.
async fn require_member(
    state: &AppState,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<GroupRole, ApiErr> {
    state
        .store
        .member_role(group_id, user_id)
        .await?
        .ok_or(ApiErr(
            StatusCode::FORBIDDEN,
            "not a member of this group".into(),
        ))
}

async fn get_group(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupInfo>, ApiErr> {
    require_member(&state, group_id, auth.user_id).await?;
    group_info(&state, group_id).await.map(Json)
}

async fn add_member(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
    Json(req): Json<GroupMemberRequest>,
) -> Result<Json<GroupInfo>, ApiErr> {
    let role = require_member(&state, group_id, auth.user_id).await?;
    if !role.can_manage_members() {
        return Err(ApiErr(
            StatusCode::FORBIDDEN,
            "only owners and admins can add members".into(),
        ));
    }
    let user = resolve_user(&state, &req.user).await?;
    state
        .store
        .add_group_member(group_id, user.id, GroupRole::Member, MAX_GROUP_MEMBERS)
        .await?;
    group_info(&state, group_id).await.map(Json)
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path((group_id, selector)): Path<(Uuid, String)>,
) -> Result<Json<GroupInfo>, ApiErr> {
    let requester_role = require_member(&state, group_id, auth.user_id).await?;
    let target = resolve_user(&state, &selector).await?;
    let target_role = require_member(&state, group_id, target.id).await?;
    let removing_self = target.id == auth.user_id;
    if !removing_self {
        if !requester_role.can_manage_members() {
            return Err(ApiErr(
                StatusCode::FORBIDDEN,
                "only owners and admins can remove members".into(),
            ));
        }
        if target_role == GroupRole::Owner {
            return Err(ApiErr(
                StatusCode::FORBIDDEN,
                "cannot remove the group owner".into(),
            ));
        }
    }
    state.store.remove_group_member(group_id, target.id).await?;
    // When the owner leaves, hand ownership to the oldest remaining member so
    // the group stays manageable; if nobody's left, the group is deleted.
    if target_role == GroupRole::Owner {
        let mut remaining = state.store.group_members(group_id).await?;
        remaining.sort_by_key(|m| m.joined_at);
        match remaining.first() {
            Some(next) => state.store.set_group_owner(group_id, next.user.id).await?,
            None => {
                let rec = state.store.group_by_id(group_id).await?;
                state.store.delete_group(group_id).await?;
                if let Some(rec) = rec {
                    return Ok(Json(GroupInfo {
                        group_id,
                        name: rec.name,
                        created_at: rec.created_at,
                        key_epoch: rec.key_epoch,
                        members: vec![],
                    }));
                }
            }
        }
    }
    group_info(&state, group_id).await.map(Json)
}

async fn delete_group(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
) -> Result<StatusCode, ApiErr> {
    let role = require_member(&state, group_id, auth.user_id).await?;
    if role != GroupRole::Owner {
        return Err(ApiErr(
            StatusCode::FORBIDDEN,
            "only the group owner can delete the group".into(),
        ));
    }
    state.store.delete_group(group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Attachments (opaque encrypted blobs)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UploadQuery {
    /// Comma-separated user UUIDs allowed to download this blob.
    #[serde(default)]
    grants: String,
}

async fn upload_attachment(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Query(q): Query<UploadQuery>,
    body: Bytes,
) -> Result<Json<AttachmentUploadResponse>, ApiErr> {
    if !state.rate_allow(
        RateKey::UserUpload(auth.user_id),
        30,
        Duration::from_secs(60),
    ) {
        return Err(ApiErr(StatusCode::TOO_MANY_REQUESTS, "slow down".into()));
    }
    // The blob is ciphertext (nonce + AEAD tag overhead); allow a small
    // margin over the plaintext limit.
    let max = state.max_attachment_bytes + 4096;
    if body.is_empty() {
        return Err(bad("empty attachment"));
    }
    if body.len() as u64 > max {
        return Err(ApiErr(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("attachment exceeds {} bytes", state.max_attachment_bytes),
        ));
    }
    let mut grants = Vec::new();
    for part in q.grants.split(',').filter(|s| !s.is_empty()) {
        let uid: Uuid = part.parse().map_err(|_| bad("invalid grant user id"))?;
        if state.store.user_by_id(uid).await?.is_none() {
            return Err(bad("grant user not found"));
        }
        grants.push(uid);
    }
    let rec = state
        .store
        .insert_attachment(auth.user_id, &body, &grants)
        .await?;
    Ok(Json(AttachmentUploadResponse {
        attachment_id: rec.id,
        size: rec.size,
    }))
}

async fn list_attachments(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<Json<Vec<AttachmentMeta>>, ApiErr> {
    let recs = state.store.attachments_for_user(auth.user_id).await?;
    Ok(Json(
        recs.into_iter()
            .map(|r| AttachmentMeta {
                attachment_id: r.id,
                size: r.size,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

async fn download_attachment(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Vec<u8>, ApiErr> {
    state
        .store
        .attachment_blob(id, auth.user_id)
        .await?
        .ok_or(ApiErr(StatusCode::NOT_FOUND, "attachment not found".into()))
}

async fn health() -> &'static str {
    "ok"
}

pub fn router(state: Arc<AppState>) -> Router {
    let attachment_body_limit = (state.max_attachment_bytes + 64 * 1024) as usize;
    Router::new()
        .route("/health", get(health))
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/users/{selector}", get(lookup))
        .route("/api/contacts", post(add_contact).get(list_contacts))
        .route("/api/contacts/{selector}", delete(remove_contact))
        .route("/api/groups", post(create_group).get(list_groups))
        .route(
            "/api/groups/{group_id}",
            get(get_group).delete(delete_group),
        )
        .route("/api/groups/{group_id}/members", post(add_member))
        .route(
            "/api/groups/{group_id}/members/{selector}",
            delete(remove_member),
        )
        .route(
            "/api/attachments",
            post(upload_attachment)
                .get(list_attachments)
                .layer(DefaultBodyLimit::max(attachment_body_limit)),
        )
        .route("/api/attachments/{id}", get(download_attachment))
        .route("/api/ws", get(crate::ws::ws_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}
