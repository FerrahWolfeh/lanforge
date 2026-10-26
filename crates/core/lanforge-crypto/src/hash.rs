//! Fast, deterministic content hashing and slug generation for Lanforge.
//!
//! Uses XXH3 (64-bit and 128-bit) for ultra-fast, platform-independent deterministic
//! hashing of configuration sections, blocklists, and stable entity IDs.

use xxhash_rust::xxh3::{xxh3_64, xxh3_128};

/// Computes a deterministic 64-bit XXH3 content hash of the input bytes.
#[must_use]
#[inline]
pub fn content_hash64(bytes: &[u8]) -> u64 {
    xxh3_64(bytes)
}

/// Computes a deterministic 128-bit XXH3 content hash of the input bytes.
#[must_use]
#[inline]
pub fn content_hash128(bytes: &[u8]) -> u128 {
    xxh3_128(bytes)
}

/// Computes a deterministic 16-character hexadecimal representation of the 64-bit content hash.
#[must_use]
pub fn content_hash_hex(bytes: &[u8]) -> String {
    format!("{:016x}", content_hash64(bytes))
}

/// Computes a deterministic 8-character hexadecimal representation (lower 32 bits) of the content hash.
#[must_use]
pub fn content_hash_short_hex(bytes: &[u8]) -> String {
    format!("{:08x}", content_hash64(bytes) as u32)
}

/// Normalizes a human-readable label or URL into a clean, URL/TOML-friendly slug.
///
/// Rules:
/// - Converts to lowercase.
/// - Replaces non-alphanumeric characters (spaces, punctuation, slashes) with hyphens.
/// - Collapses multiple consecutive hyphens into a single hyphen.
/// - Trims leading and trailing hyphens.
#[must_use]
pub fn slugify(input: &str) -> String {
    let mut slug = String::with_capacity(input.len());
    let mut last_was_hyphen = false;

    for c in input.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            last_was_hyphen = false;
        } else if !last_was_hyphen && !slug.is_empty() {
            slug.push('-');
            last_was_hyphen = true;
        }
    }

    if slug.ends_with('-') {
        slug.pop();
    }

    slug
}

/// Resolves a stable identifier from an optional user-defined slug, falling back to a deterministic content hash.
///
/// If `explicit_slug` is provided and non-empty after slugifying, it is returned.
/// Otherwise, returns `{prefix}-{hash_short}` (or just `{hash_short}` if `prefix` is empty).
#[must_use]
pub fn stable_id_or_hash(
    explicit_slug: Option<&str>,
    content_bytes: &[u8],
    prefix: &str,
) -> String {
    if let Some(slug) = explicit_slug {
        let normalized = slugify(slug);
        if !normalized.is_empty() {
            return normalized;
        }
    }

    let hash_short = content_hash_short_hex(content_bytes);
    if prefix.is_empty() {
        hash_short
    } else {
        format!("{prefix}-{hash_short}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash64_deterministic() {
        let data = b"https://v.firebog.net/hosts/AdguardDNS.txt";
        let h1 = content_hash64(data);
        let h2 = content_hash64(data);
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
    }

    #[test]
    fn test_content_hash_hex() {
        let data = b"domain.test:A:1.2.3.4";
        let hex = content_hash_hex(data);
        assert_eq!(hex.len(), 16);
        let short = content_hash_short_hex(data);
        assert_eq!(short.len(), 8);
        assert_eq!(&hex[8..], short);
    }

    #[test]
    fn test_slugify() {
        assert_eq!(
            slugify("Steven Black's Ad-block!"),
            "steven-black-s-ad-block"
        );
        assert_eq!(slugify("  AdGuard Home Mobile  "), "adguard-home-mobile");
        assert_eq!(slugify("---multiple---hyphens---"), "multiple-hyphens");
        assert_eq!(
            slugify("1.1.1.1 (Cloudflare DNS)"),
            "1-1-1-1-cloudflare-dns"
        );
        assert_eq!(slugify(""), "");
    }

    #[test]
    fn test_stable_id_or_hash() {
        let data = b"rule:block:analytics.google.com";
        assert_eq!(
            stable_id_or_hash(Some("my-custom-rule"), data, "rule"),
            "my-custom-rule"
        );
        let fallback = stable_id_or_hash(None, data, "rule");
        assert!(fallback.starts_with("rule-"));
        assert_eq!(fallback.len(), 5 + 8); // "rule-" + 8 hex
    }
}
