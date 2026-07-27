//! Encrypted image attachments. Every image is encrypted with a fresh
//! one-time ChaCha20-Poly1305 key on the sender's machine; the server stores
//! only the ciphertext blob, and the key travels exclusively inside the
//! sealed chat envelope.

use std::path::{Path, PathBuf};

use uuid::Uuid;
use yapayapa_common::attachment::sniff_image;
use yapayapa_common::crypto::{b64, b64_arr, SymmetricKey};
use yapayapa_common::types::ChatContent;

use crate::session::Session;
use crate::store::AttachmentInfo;

const ATTACHMENT_AAD: &[u8] = b"yapayapa-attachment-v1";

/// Validate, encrypt, and upload an image. Returns the `ChatContent::Image`
/// to embed in a sealed chat message. `grants` are the recipients allowed to
/// download the ciphertext blob.
pub async fn encrypt_and_upload(
    session: &Session,
    path: &Path,
    grants: &[Uuid],
) -> anyhow::Result<ChatContent> {
    let data =
        std::fs::read(path).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let max = session.config.max_attachment_bytes;
    if data.len() as u64 > max {
        anyhow::bail!(
            "image is {} bytes; the limit is {max} bytes (set YAPAYAPA_MAX_ATTACHMENT_BYTES to change)",
            data.len()
        );
    }
    let kind = sniff_image(&data).ok_or_else(|| {
        anyhow::anyhow!("unsupported or corrupted image: only PNG, JPEG and WebP are allowed (checked by file signature, not extension)")
    })?;

    let key = SymmetricKey::generate();
    let ciphertext = key
        .encrypt(&data, ATTACHMENT_AAD)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    let plaintext_hash = blake3::hash(&data).to_hex().to_string();

    let uploaded = session
        .api
        .upload_attachment(ciphertext, grants)
        .await
        .map_err(|e| anyhow::anyhow!("upload failed: {e}"))?;

    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("image.{}", kind.extension()));

    Ok(ChatContent::Image {
        attachment_id: uploaded.attachment_id,
        key: b64(&key.0),
        filename: sanitize_filename(&filename, kind.extension()),
        mime: kind.mime().to_string(),
        size: data.len() as u64,
        plaintext_hash,
    })
}

/// Download, decrypt, verify, and save an attachment into the local
/// downloads directory. Returns the saved path.
pub async fn download_and_decrypt(
    session: &Session,
    info: &AttachmentInfo,
) -> anyhow::Result<PathBuf> {
    let ciphertext = session
        .api
        .download_attachment(info.attachment_id)
        .await
        .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;
    let key_bytes =
        b64_arr::<32>(&info.key_b64).ok_or_else(|| anyhow::anyhow!("malformed attachment key"))?;
    let key = SymmetricKey(key_bytes);
    let plaintext = key
        .decrypt(&ciphertext, ATTACHMENT_AAD)
        .map_err(|_| anyhow::anyhow!("attachment failed to decrypt (corrupted or tampered)"))?;

    // Integrity + signature checks before anything touches disk.
    let hash = blake3::hash(&plaintext).to_hex().to_string();
    if hash != info.plaintext_hash {
        anyhow::bail!("attachment hash mismatch — refusing to save");
    }
    let kind = sniff_image(&plaintext).ok_or_else(|| {
        anyhow::anyhow!("decrypted data is not a supported image — refusing to save")
    })?;
    if plaintext.len() as u64 > session.config.max_attachment_bytes {
        anyhow::bail!("decrypted attachment exceeds the size limit — refusing to save");
    }

    let dir = session.config.downloads_dir();
    std::fs::create_dir_all(&dir)?;
    let safe_name = sanitize_filename(&info.filename, kind.extension());
    // Prefix with the attachment id to avoid collisions and overwrites.
    let short = &info.attachment_id.simple().to_string()[..8];
    let path = dir.join(format!("{short}_{safe_name}"));
    std::fs::write(&path, &plaintext)?;
    session
        .store
        .set_attachment_path(info.attachment_id, &path.to_string_lossy())?;
    Ok(path)
}

/// Strip path separators and control characters; force a known-good image
/// extension so a malicious filename cannot escape the downloads directory
/// or masquerade as an executable.
fn sanitize_filename(name: &str, extension: &str) -> String {
    let stem: String = Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "image".into())
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        .take(64)
        .collect();
    let stem = if stem.trim().is_empty() {
        "image".to_string()
    } else {
        stem
    };
    format!("{stem}.{extension}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_hostile_filenames() {
        assert_eq!(
            sanitize_filename("../../../etc/passwd", "png"),
            "passwd.png"
        );
        assert_eq!(sanitize_filename("cat.jpg", "jpg"), "cat.jpg");
        // '/' is a separator everywhere; on Windows '\' is one too (so the
        // stem starts after it), while on Unix '\' is an ordinary character
        // removed by the filter. Control chars are filtered on both.
        let expected = if cfg!(windows) { "c.png" } else { "bc.png" };
        assert_eq!(sanitize_filename("a/b\\c\u{7}.png", "png"), expected);
        assert_eq!(sanitize_filename("", "webp"), "image.webp");
        assert_eq!(sanitize_filename("run.sh", "png"), "run.png");
    }
}
