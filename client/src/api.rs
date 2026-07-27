//! Thin typed wrapper over the backend REST API. Only public key material,
//! password (over TLS in deployment), and ciphertext blobs ever travel here.

use uuid::Uuid;
use yapayapa_common::crypto::PublicIdentity;
use yapayapa_common::types::{
    ApiError, AttachmentUploadResponse, AuthResponse, ContactEntry, GroupInfo, UserPublic,
};

pub struct Api {
    base: String,
    client: reqwest::Client,
    token: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiErr {
    #[error("cannot reach server ({0}) — you appear to be offline")]
    Offline(String),
    #[error("{0}")]
    Server(String),
}

impl Api {
    pub fn new(base: &str, token: Option<String>) -> Self {
        Self {
            // After logout the keystore holds an empty token; don't send an
            // empty Authorization header, so 401s stay meaningful.
            token: token.filter(|t| !t.is_empty()),
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                // Generous limits so a free-tier cold start (~50s wake-up)
                // is not misreported as being offline.
                .connect_timeout(std::time::Duration::from_secs(15))
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut rb = self.client.request(method, format!("{}{path}", self.base));
        if let Some(token) = &self.token {
            rb = rb.bearer_auth(token);
        }
        rb
    }

    async fn handle<T: serde::de::DeserializeOwned>(
        resp: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<T, ApiErr> {
        let resp = resp.map_err(|e| ApiErr::Offline(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>()
                .await
                .map_err(|e| ApiErr::Server(format!("malformed server response: {e}")))
        } else {
            let msg = match resp.json::<ApiError>().await {
                Ok(e) => e.error,
                Err(_) => format!("server returned {status}"),
            };
            let msg = if status == reqwest::StatusCode::UNAUTHORIZED {
                format!("{msg} — your session is missing or expired; run `yapayapa login`")
            } else {
                msg
            };
            Err(ApiErr::Server(msg))
        }
    }

    /// True when the relay is reachable.
    pub async fn health(&self) -> bool {
        matches!(
            self.req(reqwest::Method::GET, "/health").send().await,
            Ok(resp) if resp.status().is_success()
        )
    }

    pub async fn register(
        &self,
        username: &str,
        password: &str,
        identity: &PublicIdentity,
    ) -> Result<AuthResponse, ApiErr> {
        Self::handle(
            self.req(reqwest::Method::POST, "/api/register")
                .json(&serde_json::json!({
                    "username": username,
                    "password": password,
                    "identity": identity,
                }))
                .send()
                .await,
        )
        .await
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<AuthResponse, ApiErr> {
        Self::handle(
            self.req(reqwest::Method::POST, "/api/login")
                .json(&serde_json::json!({"username": username, "password": password}))
                .send()
                .await,
        )
        .await
    }

    pub async fn logout(&self) -> Result<(), ApiErr> {
        let resp = self
            .req(reqwest::Method::POST, "/api/logout")
            .send()
            .await
            .map_err(|e| ApiErr::Offline(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ApiErr::Server(format!("logout failed: {}", resp.status())))
        }
    }

    pub async fn me(&self) -> Result<UserPublic, ApiErr> {
        Self::handle(self.req(reqwest::Method::GET, "/api/me").send().await).await
    }

    pub async fn lookup(&self, selector: &str) -> Result<UserPublic, ApiErr> {
        Self::handle(
            self.req(reqwest::Method::GET, &format!("/api/users/{selector}"))
                .send()
                .await,
        )
        .await
    }

    pub async fn add_contact(&self, selector: &str) -> Result<UserPublic, ApiErr> {
        Self::handle(
            self.req(reqwest::Method::POST, "/api/contacts")
                .json(&serde_json::json!({"user": selector}))
                .send()
                .await,
        )
        .await
    }

    pub async fn list_contacts(&self) -> Result<Vec<ContactEntry>, ApiErr> {
        Self::handle(self.req(reqwest::Method::GET, "/api/contacts").send().await).await
    }

    // -- groups -------------------------------------------------------------

    pub async fn create_group(&self, name: &str) -> Result<GroupInfo, ApiErr> {
        Self::handle(
            self.req(reqwest::Method::POST, "/api/groups")
                .json(&serde_json::json!({"name": name}))
                .send()
                .await,
        )
        .await
    }

    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>, ApiErr> {
        Self::handle(self.req(reqwest::Method::GET, "/api/groups").send().await).await
    }

    pub async fn group_info(&self, group_id: Uuid) -> Result<GroupInfo, ApiErr> {
        Self::handle(
            self.req(reqwest::Method::GET, &format!("/api/groups/{group_id}"))
                .send()
                .await,
        )
        .await
    }

    pub async fn add_group_member(&self, group_id: Uuid, user: &str) -> Result<GroupInfo, ApiErr> {
        Self::handle(
            self.req(
                reqwest::Method::POST,
                &format!("/api/groups/{group_id}/members"),
            )
            .json(&serde_json::json!({"user": user}))
            .send()
            .await,
        )
        .await
    }

    pub async fn remove_group_member(
        &self,
        group_id: Uuid,
        user: &str,
    ) -> Result<GroupInfo, ApiErr> {
        Self::handle(
            self.req(
                reqwest::Method::DELETE,
                &format!("/api/groups/{group_id}/members/{user}"),
            )
            .send()
            .await,
        )
        .await
    }

    // -- attachments ----------------------------------------------------------

    pub async fn upload_attachment(
        &self,
        ciphertext: Vec<u8>,
        grants: &[Uuid],
    ) -> Result<AttachmentUploadResponse, ApiErr> {
        let grants: Vec<String> = grants.iter().map(|g| g.to_string()).collect();
        Self::handle(
            self.req(
                reqwest::Method::POST,
                &format!("/api/attachments?grants={}", grants.join(",")),
            )
            .body(ciphertext)
            .send()
            .await,
        )
        .await
    }

    pub async fn download_attachment(&self, id: Uuid) -> Result<Vec<u8>, ApiErr> {
        let resp = self
            .req(reqwest::Method::GET, &format!("/api/attachments/{id}"))
            .send()
            .await
            .map_err(|e| ApiErr::Offline(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ApiErr::Server(format!(
                "download failed: {}",
                resp.status()
            )));
        }
        Ok(resp
            .bytes()
            .await
            .map_err(|e| ApiErr::Server(e.to_string()))?
            .to_vec())
    }
}
