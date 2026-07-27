//! Encrypted local keystore. Private identity keys, the local master key
//! (which encrypts chat history at rest), and the session token are stored in
//! a single file, encrypted with ChaCha20-Poly1305 under a key derived from
//! the user's password with Argon2id. Nothing in this file ever leaves the
//! machine.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use yapayapa_common::crypto::{
    b64, b64_arr, b64_vec, derive_password_key, random_salt, CryptoError, Identity, SymmetricKey,
};
use zeroize::Zeroize;

const KEYSTORE_AAD: &[u8] = b"yapayapa-keystore-v1";

/// Cleartext header + encrypted secret payload, as stored on disk.
#[derive(Serialize, Deserialize)]
struct KeystoreFile {
    v: u8,
    /// Argon2id salt, base64.
    salt: String,
    /// nonce||ciphertext of the serialized [`Secrets`], base64.
    sealed: String,
    /// Public, non-secret profile info (readable without the password so the
    /// CLI can show who is logged in).
    pub profile: Profile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub user_id: Uuid,
    pub public_id: String,
    pub username: String,
    pub server: String,
}

#[derive(Serialize, Deserialize)]
struct Secrets {
    sign_secret: String,
    dh_secret: String,
    master_key: String,
    /// Backend session token (bearer). Kept inside the encrypted blob so a
    /// stolen data directory does not yield a usable session.
    token: String,
}

/// An unlocked keystore.
pub struct Keystore {
    pub profile: Profile,
    pub identity: Identity,
    pub master_key: SymmetricKey,
    pub token: String,
    path: PathBuf,
    /// Password-derived file key, kept to re-seal on updates.
    file_key: SymmetricKey,
    salt: [u8; 16],
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("no keystore found at {0} — run `yapayapa register` or `yapayapa login` first")]
    NotFound(PathBuf),
    #[error("wrong password or corrupted keystore")]
    WrongPassword,
    #[error("keystore file is malformed")]
    Malformed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<CryptoError> for KeystoreError {
    fn from(_: CryptoError) -> Self {
        KeystoreError::WrongPassword
    }
}

impl Keystore {
    /// Create a brand-new keystore with a fresh identity and master key.
    pub fn create(
        path: &Path,
        password: &str,
        profile: Profile,
        identity: Identity,
        token: String,
    ) -> Result<Self, KeystoreError> {
        let salt = random_salt();
        let mut key_bytes =
            derive_password_key(password, &salt).map_err(|_| KeystoreError::Malformed)?;
        let file_key = SymmetricKey(key_bytes);
        key_bytes.zeroize();
        let ks = Keystore {
            profile,
            identity,
            master_key: SymmetricKey::generate(),
            token,
            path: path.to_path_buf(),
            file_key,
            salt,
        };
        ks.save()?;
        Ok(ks)
    }

    /// Read the public profile without unlocking (may be absent).
    pub fn peek_profile(path: &Path) -> Option<Profile> {
        let data = std::fs::read_to_string(path).ok()?;
        let file: KeystoreFile = serde_json::from_str(&data).ok()?;
        Some(file.profile)
    }

    pub fn unlock(path: &Path, password: &str) -> Result<Self, KeystoreError> {
        let data = std::fs::read_to_string(path)
            .map_err(|_| KeystoreError::NotFound(path.to_path_buf()))?;
        let file: KeystoreFile =
            serde_json::from_str(&data).map_err(|_| KeystoreError::Malformed)?;
        if file.v != 1 {
            return Err(KeystoreError::Malformed);
        }
        let salt = b64_arr::<16>(&file.salt).ok_or(KeystoreError::Malformed)?;
        let sealed = b64_vec(&file.sealed).ok_or(KeystoreError::Malformed)?;
        let mut key_bytes =
            derive_password_key(password, &salt).map_err(|_| KeystoreError::Malformed)?;
        let file_key = SymmetricKey(key_bytes);
        key_bytes.zeroize();
        let plain = file_key
            .decrypt(&sealed, KEYSTORE_AAD)
            .map_err(|_| KeystoreError::WrongPassword)?;
        let secrets: Secrets =
            serde_json::from_slice(&plain).map_err(|_| KeystoreError::Malformed)?;
        let sign = b64_arr::<32>(&secrets.sign_secret).ok_or(KeystoreError::Malformed)?;
        let dh = b64_arr::<32>(&secrets.dh_secret).ok_or(KeystoreError::Malformed)?;
        let master = b64_arr::<32>(&secrets.master_key).ok_or(KeystoreError::Malformed)?;
        Ok(Keystore {
            profile: file.profile,
            identity: Identity::from_secret_bytes(sign, dh),
            master_key: SymmetricKey(master),
            token: secrets.token,
            path: path.to_path_buf(),
            file_key,
            salt,
        })
    }

    /// Re-encrypt and atomically rewrite the keystore (e.g. after a new
    /// session token).
    pub fn save(&self) -> Result<(), KeystoreError> {
        let (sign, dh) = self.identity.secret_bytes();
        let secrets = Secrets {
            sign_secret: b64(&sign),
            dh_secret: b64(&dh),
            master_key: b64(&self.master_key.0),
            token: self.token.clone(),
        };
        let mut plain = serde_json::to_vec(&secrets).map_err(|_| KeystoreError::Malformed)?;
        let sealed = self
            .file_key
            .encrypt(&plain, KEYSTORE_AAD)
            .map_err(|_| KeystoreError::Malformed)?;
        plain.zeroize();
        let file = KeystoreFile {
            v: 1,
            salt: b64(&self.salt),
            sealed: b64(&sealed),
            profile: self.profile.clone(),
        };
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&file).map_err(|_| KeystoreError::Malformed)?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn set_token(&mut self, token: String) -> Result<(), KeystoreError> {
        self.token = token;
        self.save()
    }
}

/// Read a password from `$YAPAYAPA_PASSWORD` (scripting/tests) or prompt on
/// the terminal.
pub fn read_password(prompt: &str) -> anyhow::Result<String> {
    if let Ok(pw) = std::env::var("YAPAYAPA_PASSWORD") {
        return Ok(pw);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            user_id: Uuid::new_v4(),
            public_id: "yp_0123456789abcdef".into(),
            username: "alice".into(),
            server: "http://127.0.0.1:8080".into(),
        }
    }

    #[test]
    fn create_unlock_roundtrip_and_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        let identity = Identity::generate();
        let public = identity.public();
        let ks =
            Keystore::create(&path, "pass-phrase", profile(), identity, "tok123".into()).unwrap();
        let master = ks.master_key.0;

        let unlocked = Keystore::unlock(&path, "pass-phrase").unwrap();
        assert_eq!(unlocked.identity.public(), public);
        assert_eq!(unlocked.master_key.0, master);
        assert_eq!(unlocked.token, "tok123");

        assert!(matches!(
            Keystore::unlock(&path, "wrong"),
            Err(KeystoreError::WrongPassword)
        ));
    }

    #[test]
    fn private_keys_are_not_readable_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        let identity = Identity::generate();
        let (sign, dh) = identity.secret_bytes();
        let ks = Keystore::create(&path, "pw123456", profile(), identity, "tok".into()).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        // Neither secret key nor master key appears in the file in the clear.
        assert!(!raw.contains(&b64(&sign)));
        assert!(!raw.contains(&b64(&dh)));
        assert!(!raw.contains(&b64(&ks.master_key.0)));
        assert!(!raw.contains("tok\""));
        // But the public profile is readable.
        assert!(raw.contains("alice"));
    }

    #[test]
    fn token_update_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        let mut ks = Keystore::create(
            &path,
            "pw123456",
            profile(),
            Identity::generate(),
            "old".into(),
        )
        .unwrap();
        ks.set_token("new-token".into()).unwrap();
        let unlocked = Keystore::unlock(&path, "pw123456").unwrap();
        assert_eq!(unlocked.token, "new-token");
    }
}
