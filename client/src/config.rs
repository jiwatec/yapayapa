//! Client configuration: server URL and per-profile data directory layout.

use std::path::PathBuf;

use crate::keystore::Keystore;

/// Server used when nothing else selects one (fresh install, no account yet).
pub const DEFAULT_SERVER: &str = "https://yapayapa-backend.onrender.com";

#[derive(Debug, Clone)]
pub struct Config {
    pub server: String,
    pub data_dir: PathBuf,
    pub max_attachment_bytes: u64,
}

impl Config {
    pub fn resolve(server_flag: Option<String>, data_dir_flag: Option<PathBuf>) -> Self {
        let data_dir = data_dir_flag
            .or_else(|| std::env::var("YAPAYAPA_DATA_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| {
                dirs::data_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("yapayapa")
            });
        let server = server_flag
            .or_else(|| std::env::var("YAPAYAPA_SERVER").ok())
            .or_else(|| {
                // An existing account knows which server it was registered on.
                Keystore::peek_profile(&data_dir.join("keystore.json")).map(|p| p.server)
            })
            .unwrap_or_else(|| DEFAULT_SERVER.into());
        let max_attachment_bytes = std::env::var("YAPAYAPA_MAX_ATTACHMENT_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(yapayapa_common::validate::DEFAULT_MAX_ATTACHMENT_BYTES);
        Self {
            server: server.trim_end_matches('/').to_string(),
            data_dir,
            max_attachment_bytes,
        }
    }

    pub fn ws_url(&self) -> String {
        let ws = self
            .server
            .replacen("http://", "ws://", 1)
            .replacen("https://", "wss://", 1);
        format!("{ws}/api/ws")
    }

    pub fn keystore_path(&self) -> PathBuf {
        self.data_dir.join("keystore.json")
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("local.db")
    }

    pub fn downloads_dir(&self) -> PathBuf {
        self.data_dir.join("downloads")
    }

    /// Create the data directory with owner-only permissions.
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(self.downloads_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.data_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}
