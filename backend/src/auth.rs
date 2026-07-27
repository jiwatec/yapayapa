//! Password hashing (Argon2id PHC strings), opaque session tokens (stored
//! only as BLAKE3 hashes), and the `AuthUser` request extractor.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use uuid::Uuid;

use crate::http::ApiErr;
use crate::state::AppState;

pub const SESSION_DAYS: i64 = 30;

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?
        .to_string())
}

pub fn verify_password(phc: &str, password: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Returns `(token, token_hash)`. Only the hash is persisted.
pub fn new_session_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    use base64::Engine;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hash = token_hash(&token);
    (token, hash)
}

pub fn token_hash(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

pub async fn create_session(state: &AppState, user_id: Uuid) -> Result<String, ApiErr> {
    let (token, hash) = new_session_token();
    state
        .store
        .insert_session(&hash, user_id, Utc::now() + Duration::days(SESSION_DAYS))
        .await?;
    Ok(token)
}

/// Authenticated user, extracted from `Authorization: Bearer <token>` or,
/// for WebSocket handshakes where headers are awkward, `?token=<token>`.
pub struct AuthUser {
    pub user_id: Uuid,
    pub token_hash: String,
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let bearer = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_string);
        let query_token = parts.uri.query().and_then(|q| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("token=").map(str::to_string))
        });
        let token = bearer
            .or(query_token)
            .ok_or_else(|| ApiErr(StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
        let hash = token_hash(&token);
        match state.store.session_user(&hash).await? {
            Some(user_id) => Ok(AuthUser {
                user_id,
                token_hash: hash,
            }),
            None => Err(ApiErr(
                StatusCode::UNAUTHORIZED,
                "invalid or expired session".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let phc = hash_password("correct horse").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password(&phc, "correct horse"));
        assert!(!verify_password(&phc, "wrong"));
        assert!(!verify_password("not-a-phc", "x"));
    }

    #[test]
    fn tokens_are_unique_and_hash_stably() {
        let (t1, h1) = new_session_token();
        let (t2, _) = new_session_token();
        assert_ne!(t1, t2);
        assert_eq!(h1, token_hash(&t1));
        assert_ne!(h1, token_hash(&t2));
    }
}
