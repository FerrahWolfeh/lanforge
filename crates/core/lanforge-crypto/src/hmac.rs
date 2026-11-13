//! HMAC-SHA256 (RFC 2104) from the compiled-in crypto provider, the same one rustls uses.

#[cfg(all(feature = "aws-lc", not(feature = "ring")))]
use aws_lc_rs::hmac;
#[cfg(feature = "ring")]
use ring::hmac;

/// Length of an HMAC-SHA256 tag.
pub const TAG_LEN: usize = 32;

/// An HMAC-SHA256 key.
#[derive(Clone)]
pub struct HmacSha256(hmac::Key);

impl HmacSha256 {
    #[must_use]
    pub fn new(secret: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    /// The tag of `data`.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> [u8; TAG_LEN] {
        let mut out = [0; TAG_LEN];
        out.copy_from_slice(hmac::sign(&self.0, data).as_ref());
        out
    }

    /// Whether `tag` is the tag of `data`, compared in constant time.
    #[must_use]
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        hmac::verify(&self.0, data, tag).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::HmacSha256;

    /// RFC 4231 §4.3, test case 2.
    #[test]
    fn rfc4231_vector() {
        let key = HmacSha256::new(b"Jefe");
        let data = b"what do ya want for nothing?";
        let tag = key.sign(data);
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(key.verify(data, &tag));
    }

    #[test]
    fn verify_rejects_other_data_keys_and_truncated_tags() {
        let key = HmacSha256::new(b"k");
        let tag = key.sign(b"data");
        assert!(!key.verify(b"datb", &tag));
        assert!(!HmacSha256::new(b"j").verify(b"data", &tag));
        assert!(!key.verify(b"data", &tag[..16]));
        assert!(!key.verify(b"data", &[]));
    }
}
