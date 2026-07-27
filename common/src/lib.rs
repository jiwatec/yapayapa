//! Shared types and cryptography for the YapaYapa client and backend.
//!
//! SECURITY NOTE: the message encryption in [`crypto`] is a non-audited MVP
//! design built strictly from audited primitives (x25519-dalek,
//! ed25519-dalek, ChaCha20-Poly1305, HKDF-SHA256, Argon2id, BLAKE3). It is
//! NOT the Signal protocol and provides no per-message forward secrecy or
//! post-compromise security. See docs/THREAT_MODEL.md.

pub mod attachment;
pub mod crypto;
pub mod types;
pub mod validate;
