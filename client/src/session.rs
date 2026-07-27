//! An unlocked client session: keystore + local store + API handle.

use crate::api::Api;
use crate::config::Config;
use crate::keystore::{read_password, Keystore};
use crate::store::LocalStore;

pub struct Session {
    pub config: Config,
    pub keystore: Keystore,
    pub store: LocalStore,
    pub api: Api,
}

impl Session {
    /// Unlock the keystore (prompting for the password) and open local
    /// storage. Works fully offline.
    pub fn load(config: Config) -> anyhow::Result<Self> {
        let path = config.keystore_path();
        if !path.exists() {
            anyhow::bail!(
                "no account found in {} — run `yapayapa register` or `yapayapa login` first",
                config.data_dir.display()
            );
        }
        let password = read_password("Password: ")?;
        Self::unlock_with(config, &password)
    }

    /// Unlock with an already-collected password (e.g. from a TUI prompt).
    pub fn unlock_with(config: Config, password: &str) -> anyhow::Result<Self> {
        let keystore = Keystore::unlock(&config.keystore_path(), password)?;
        let store = LocalStore::open(&config.db_path(), &keystore.master_key)?;
        let api = Api::new(&config.server, Some(keystore.token.clone()));
        Ok(Self {
            config,
            keystore,
            store,
            api,
        })
    }

    pub fn ws_url_with_token(&self) -> String {
        format!("{}?token={}", self.config.ws_url(), self.keystore.token)
    }
}
