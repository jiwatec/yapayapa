//! Image attachment validation: real file-signature sniffing, never
//! extension-based.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Jpeg,
    Webp,
}

impl ImageKind {
    pub fn mime(self) -> &'static str {
        match self {
            ImageKind::Png => "image/png",
            ImageKind::Jpeg => "image/jpeg",
            ImageKind::Webp => "image/webp",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ImageKind::Png => "png",
            ImageKind::Jpeg => "jpg",
            ImageKind::Webp => "webp",
        }
    }
}

/// Detect a supported image type from its magic bytes.
pub fn sniff_image(data: &[u8]) -> Option<ImageKind> {
    if data.len() >= 8 && data[..8] == [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a] {
        return Some(ImageKind::Png);
    }
    if data.len() >= 3 && data[..3] == [0xff, 0xd8, 0xff] {
        return Some(ImageKind::Jpeg);
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some(ImageKind::Webp);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_png() {
        let mut d = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        d.extend_from_slice(&[0; 16]);
        assert_eq!(sniff_image(&d), Some(ImageKind::Png));
    }

    #[test]
    fn sniffs_jpeg() {
        assert_eq!(
            sniff_image(&[0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0]),
            Some(ImageKind::Jpeg)
        );
    }

    #[test]
    fn sniffs_webp() {
        let mut d = b"RIFF".to_vec();
        d.extend_from_slice(&[0, 0, 0, 0]);
        d.extend_from_slice(b"WEBP");
        d.extend_from_slice(&[0; 8]);
        assert_eq!(sniff_image(&d), Some(ImageKind::Webp));
    }

    #[test]
    fn rejects_non_images() {
        assert_eq!(sniff_image(b"GIF89a...."), None);
        assert_eq!(sniff_image(b"plain text"), None);
        assert_eq!(sniff_image(b""), None);
        // RIFF but not WEBP (e.g. WAV)
        let mut d = b"RIFF".to_vec();
        d.extend_from_slice(&[0, 0, 0, 0]);
        d.extend_from_slice(b"WAVE");
        assert_eq!(sniff_image(&d), None);
    }
}
