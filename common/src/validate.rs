//! Input validation shared by client and backend.

pub const USERNAME_MIN: usize = 3;
pub const USERNAME_MAX: usize = 32;
pub const PASSWORD_MIN: usize = 8;
pub const PASSWORD_MAX: usize = 128;
pub const GROUP_NAME_MAX: usize = 64;
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
/// Maximum serialized envelope payload the relay accepts (base64 inflation
/// over the 10 MB attachment limit is not needed: attachments upload via
/// HTTP, so WS envelopes stay small).
pub const MAX_WS_FRAME_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;

/// Normalize a username: trim + lowercase (ASCII).
pub fn normalize_username(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// A valid username is 3-32 chars of `[a-z0-9_]` after normalization and
/// must start with a letter.
pub fn validate_username(normalized: &str) -> Result<(), String> {
    if normalized.len() < USERNAME_MIN || normalized.len() > USERNAME_MAX {
        return Err(format!(
            "username must be {USERNAME_MIN}-{USERNAME_MAX} characters"
        ));
    }
    let mut chars = normalized.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return Err("username must start with a letter".into()),
    }
    if !normalized
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err("username may only contain a-z, 0-9 and _".into());
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < PASSWORD_MIN {
        return Err(format!(
            "password must be at least {PASSWORD_MIN} characters"
        ));
    }
    if password.len() > PASSWORD_MAX {
        return Err(format!(
            "password must be at most {PASSWORD_MAX} characters"
        ));
    }
    Ok(())
}

pub fn validate_group_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("group name cannot be empty".into());
    }
    if trimmed.len() > GROUP_NAME_MAX {
        return Err(format!(
            "group name must be at most {GROUP_NAME_MAX} characters"
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("group name cannot contain control characters".into());
    }
    Ok(())
}

/// Public IDs look like `yp_` + 16 hex chars.
pub fn is_public_id(s: &str) -> bool {
    s.len() == 19 && s.starts_with("yp_") && s[3..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        assert!(validate_username(&normalize_username("  Alice_01 ")).is_ok());
        assert!(validate_username(&normalize_username("ab")).is_err());
        assert!(validate_username(&normalize_username("1abc")).is_err());
        assert!(validate_username(&normalize_username("a b")).is_err());
        assert!(validate_username(&normalize_username("a".repeat(33).as_str())).is_err());
        assert_eq!(normalize_username(" Bob "), "bob");
    }

    #[test]
    fn passwords() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("longenough").is_ok());
        assert!(validate_password(&"x".repeat(200)).is_err());
    }

    #[test]
    fn public_ids() {
        assert!(is_public_id("yp_0123456789abcdef"));
        assert!(!is_public_id("yp_0123"));
        assert!(!is_public_id("xx_0123456789abcdef"));
        assert!(!is_public_id("yp_0123456789abcdeg"));
    }
}
