//! MVP encryption for YapaYapa.
//!
//! Construction summary (non-audited MVP design, audited primitives only):
//!
//! * Every user has a long-term identity: an Ed25519 signing key and an
//!   X25519 static Diffie-Hellman key. The X25519 public key is signed with
//!   the Ed25519 key and published as the user's pre-key bundle.
//! * Sealing a message to a recipient ("sealed envelope"):
//!   1. Generate an ephemeral X25519 key pair.
//!   2. `s1 = DH(ephemeral, recipient_static)`, `s2 = DH(sender_static,
//!      recipient_static)`.
//!   3. `key = HKDF-SHA256(ikm = s1 || s2, info = domain || eph_pub ||
//!      sender_dh_pub || recipient_dh_pub)`.
//!   4. Encrypt with ChaCha20-Poly1305 and a random 96-bit nonce.
//!   5. Sign `domain || eph_pub || nonce || sender_dh_pub ||
//!      recipient_dh_pub || ciphertext` with the sender's Ed25519 key.
//! * Opening verifies the signature against the *expected* sender identity
//!   before deriving the key and decrypting.
//!
//! Known limitations (see docs/THREAT_MODEL.md): no double ratchet, no
//! per-message forward secrecy for the recipient, signatures make sender
//! participation publicly provable, no post-compromise security.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ENVELOPE_DOMAIN: &[u8] = b"yapayapa-envelope-v1";
pub const PREKEY_DOMAIN: &[u8] = b"yapayapa-prekey-v1";
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong key or corrupted data)")]
    Decrypt,
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed cryptographic material: {0}")]
    Malformed(&'static str),
    #[error("key derivation failed")]
    Kdf,
}

/// Long-term private identity. Never serialized except by the client
/// keystore, which encrypts it at rest.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    sign_secret: [u8; 32],
    dh_secret: [u8; 32],
}

/// Public half of an identity, safe to publish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    /// Ed25519 verifying key, base64.
    pub sign_pub: String,
    /// X25519 public key, base64.
    pub dh_pub: String,
    /// Ed25519 signature over `PREKEY_DOMAIN || dh_pub`, base64. Proves the
    /// DH pre-key belongs to the signing identity.
    pub dh_pub_sig: String,
}

impl Identity {
    pub fn generate() -> Self {
        let sign = SigningKey::generate(&mut OsRng);
        let dh = StaticSecret::random_from_rng(OsRng);
        Self {
            sign_secret: sign.to_bytes(),
            dh_secret: dh.to_bytes(),
        }
    }

    pub fn from_secret_bytes(sign_secret: [u8; 32], dh_secret: [u8; 32]) -> Self {
        Self {
            sign_secret,
            dh_secret,
        }
    }

    pub fn secret_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (self.sign_secret, self.dh_secret)
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.sign_secret)
    }

    fn dh_key(&self) -> StaticSecret {
        StaticSecret::from(self.dh_secret)
    }

    pub fn public(&self) -> PublicIdentity {
        let sign = self.signing_key();
        let dh_pub = XPublicKey::from(&self.dh_key());
        let mut msg = Vec::with_capacity(PREKEY_DOMAIN.len() + 32);
        msg.extend_from_slice(PREKEY_DOMAIN);
        msg.extend_from_slice(dh_pub.as_bytes());
        let sig = sign.sign(&msg);
        PublicIdentity {
            sign_pub: b64(sign.verifying_key().as_bytes()),
            dh_pub: b64(dh_pub.as_bytes()),
            dh_pub_sig: b64(&sig.to_bytes()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key().sign(message).to_bytes()
    }
}

impl PublicIdentity {
    pub fn sign_pub_bytes(&self) -> Result<[u8; 32], CryptoError> {
        b64_arr::<32>(&self.sign_pub).ok_or(CryptoError::Malformed("sign_pub"))
    }

    pub fn dh_pub_bytes(&self) -> Result<[u8; 32], CryptoError> {
        b64_arr::<32>(&self.dh_pub).ok_or(CryptoError::Malformed("dh_pub"))
    }

    fn verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_bytes(&self.sign_pub_bytes()?)
            .map_err(|_| CryptoError::Malformed("sign_pub"))
    }

    /// Verify that the DH pre-key is signed by the signing identity. Must be
    /// checked whenever a bundle is fetched from the server.
    pub fn verify_prekey(&self) -> Result<(), CryptoError> {
        let vk = self.verifying_key()?;
        let dh = self.dh_pub_bytes()?;
        let sig_bytes = b64_arr::<64>(&self.dh_pub_sig).ok_or(CryptoError::Malformed("sig"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let mut msg = Vec::with_capacity(PREKEY_DOMAIN.len() + 32);
        msg.extend_from_slice(PREKEY_DOMAIN);
        msg.extend_from_slice(&dh);
        vk.verify(&msg, &sig).map_err(|_| CryptoError::BadSignature)
    }

    /// Human-comparable fingerprint of this identity (BLAKE3 of both public
    /// keys), rendered as 8 groups of 5 hex chars.
    pub fn fingerprint(&self) -> Result<String, CryptoError> {
        let mut hasher = blake3::Hasher::new_derive_key("yapayapa fingerprint v1");
        hasher.update(&self.sign_pub_bytes()?);
        hasher.update(&self.dh_pub_bytes()?);
        let digest = hasher.finalize();
        let hexstr = hex::encode(&digest.as_bytes()[..20]);
        Ok(hexstr
            .as_bytes()
            .chunks(5)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" "))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let vk = self.verifying_key()?;
        vk.verify(message, &Signature::from_bytes(signature))
            .map_err(|_| CryptoError::BadSignature)
    }
}

/// A sealed (encrypted + signed) envelope. This is the ONLY message form
/// that ever leaves a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub v: u8,
    /// Ephemeral X25519 public key, base64.
    pub eph_pub: String,
    /// 96-bit nonce, base64.
    pub nonce: String,
    /// ChaCha20-Poly1305 ciphertext, base64.
    pub ct: String,
    /// Ed25519 signature by the sender, base64.
    pub sig: String,
}

fn transcript(
    eph_pub: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    sender_dh: &[u8; 32],
    recipient_dh: &[u8; 32],
    ct: &[u8],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(ENVELOPE_DOMAIN.len() + 32 * 3 + NONCE_LEN + ct.len());
    t.extend_from_slice(ENVELOPE_DOMAIN);
    t.extend_from_slice(eph_pub);
    t.extend_from_slice(nonce);
    t.extend_from_slice(sender_dh);
    t.extend_from_slice(recipient_dh);
    t.extend_from_slice(ct);
    t
}

fn derive_envelope_key(
    s1: &[u8; 32],
    s2: &[u8; 32],
    eph_pub: &[u8; 32],
    sender_dh: &[u8; 32],
    recipient_dh: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(s1);
    ikm[32..].copy_from_slice(s2);
    let mut info = Vec::with_capacity(ENVELOPE_DOMAIN.len() + 96);
    info.extend_from_slice(ENVELOPE_DOMAIN);
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(sender_dh);
    info.extend_from_slice(recipient_dh);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).map_err(|_| CryptoError::Kdf)?;
    ikm.zeroize();
    Ok(key)
}

/// Encrypt and sign `plaintext` from `sender` to `recipient`.
pub fn seal(
    sender: &Identity,
    recipient: &PublicIdentity,
    plaintext: &[u8],
) -> Result<SealedEnvelope, CryptoError> {
    let recipient_dh = recipient.dh_pub_bytes()?;
    let recipient_pub = XPublicKey::from(recipient_dh);

    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_pub = XPublicKey::from(&eph_secret);

    let sender_dh_pub = XPublicKey::from(&sender.dh_key());

    let s1 = eph_secret.diffie_hellman(&recipient_pub);
    let s2 = sender.dh_key().diffie_hellman(&recipient_pub);

    let mut key = derive_envelope_key(
        s1.as_bytes(),
        s2.as_bytes(),
        eph_pub.as_bytes(),
        sender_dh_pub.as_bytes(),
        &recipient_dh,
    )?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    key.zeroize();

    let t = transcript(
        eph_pub.as_bytes(),
        &nonce,
        sender_dh_pub.as_bytes(),
        &recipient_dh,
        &ct,
    );
    let sig = sender.sign(&t);

    Ok(SealedEnvelope {
        v: 1,
        eph_pub: b64(eph_pub.as_bytes()),
        nonce: b64(&nonce),
        ct: b64(&ct),
        sig: b64(&sig),
    })
}

/// Verify and decrypt an envelope. `expected_sender` MUST be the identity
/// the recipient believes sent this message (from their contact store); the
/// signature and the KDF both bind to it.
pub fn open(
    recipient: &Identity,
    expected_sender: &PublicIdentity,
    envelope: &SealedEnvelope,
) -> Result<Vec<u8>, CryptoError> {
    if envelope.v != 1 {
        return Err(CryptoError::Malformed("version"));
    }
    let eph_pub = b64_arr::<32>(&envelope.eph_pub).ok_or(CryptoError::Malformed("eph_pub"))?;
    let nonce = b64_arr::<NONCE_LEN>(&envelope.nonce).ok_or(CryptoError::Malformed("nonce"))?;
    let sig = b64_arr::<64>(&envelope.sig).ok_or(CryptoError::Malformed("sig"))?;
    let ct = b64_vec(&envelope.ct).ok_or(CryptoError::Malformed("ct"))?;

    let sender_dh = expected_sender.dh_pub_bytes()?;
    let recipient_dh_pub = XPublicKey::from(&recipient.dh_key());

    // Authenticate first.
    let t = transcript(
        &eph_pub,
        &nonce,
        &sender_dh,
        recipient_dh_pub.as_bytes(),
        &ct,
    );
    expected_sender.verify(&t, &sig)?;

    let s1 = recipient
        .dh_key()
        .diffie_hellman(&XPublicKey::from(eph_pub));
    let s2 = recipient
        .dh_key()
        .diffie_hellman(&XPublicKey::from(sender_dh));

    let mut key = derive_envelope_key(
        s1.as_bytes(),
        s2.as_bytes(),
        &eph_pub,
        &sender_dh,
        recipient_dh_pub.as_bytes(),
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| CryptoError::Decrypt)?;
    key.zeroize();
    Ok(pt)
}

/// A random 256-bit symmetric key (local storage, group keys, attachment
/// keys) used with ChaCha20-Poly1305.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// Encrypt with a random nonce; output is `nonce || ciphertext`.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < NONCE_LEN {
            return Err(CryptoError::Malformed("ciphertext too short"));
        }
        let (nonce, ct) = data.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                chacha20poly1305::aead::Payload { msg: ct, aad },
            )
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// Derive a 256-bit key from a password with Argon2id. Used only on the
/// client, to protect the local keystore. (The backend hashes passwords
/// separately with salted Argon2id PHC strings.)
pub fn derive_password_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

pub fn random_salt() -> [u8; 16] {
    let mut s = [0u8; 16];
    OsRng.fill_bytes(&mut s);
    s
}

pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_vec(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

pub fn b64_arr<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = b64_vec(s)?;
    v.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seal_open() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let env = seal(&alice, &bob.public(), b"hello bob").unwrap();
        let pt = open(&bob, &alice.public(), &env).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn open_rejects_wrong_sender() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();
        let env = seal(&alice, &bob.public(), b"hi").unwrap();
        assert!(open(&bob, &mallory.public(), &env).is_err());
    }

    #[test]
    fn open_rejects_wrong_recipient() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let env = seal(&alice, &bob.public(), b"hi").unwrap();
        assert!(open(&eve, &alice.public(), &env).is_err());
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mut env = seal(&alice, &bob.public(), b"hi").unwrap();
        let mut ct = b64_vec(&env.ct).unwrap();
        ct[0] ^= 0xff;
        env.ct = b64(&ct);
        assert!(open(&bob, &alice.public(), &env).is_err());
    }

    #[test]
    fn prekey_signature_verifies() {
        let id = Identity::generate();
        id.public().verify_prekey().unwrap();
    }

    #[test]
    fn prekey_signature_rejects_swapped_dh_key() {
        let a = Identity::generate();
        let b = Identity::generate();
        let mut pubid = a.public();
        pubid.dh_pub = b.public().dh_pub;
        assert!(pubid.verify_prekey().is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_eq!(
            a.public().fingerprint().unwrap(),
            a.public().fingerprint().unwrap()
        );
        assert_ne!(
            a.public().fingerprint().unwrap(),
            b.public().fingerprint().unwrap()
        );
    }

    #[test]
    fn symmetric_roundtrip_and_tamper() {
        let k = SymmetricKey::generate();
        let ct = k.encrypt(b"secret", b"aad").unwrap();
        assert_eq!(k.decrypt(&ct, b"aad").unwrap(), b"secret");
        assert!(k.decrypt(&ct, b"other-aad").is_err());
        let mut bad = ct.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(k.decrypt(&bad, b"aad").is_err());
    }

    #[test]
    fn password_key_derivation_deterministic() {
        let salt = random_salt();
        let k1 = derive_password_key("pw", &salt).unwrap();
        let k2 = derive_password_key("pw", &salt).unwrap();
        let k3 = derive_password_key("pw2", &salt).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn identity_secret_roundtrip() {
        let id = Identity::generate();
        let (s, d) = id.secret_bytes();
        let id2 = Identity::from_secret_bytes(s, d);
        assert_eq!(id.public(), id2.public());
    }
}
