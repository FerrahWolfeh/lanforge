use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

/// A duration that can be parsed from and serialized to human-friendly strings like "12h", "30m", "1d", "86400s",
/// while also supporting deserialization from raw integer seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HumanDuration(pub u64);

impl HumanDuration {
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.0
    }
}

impl Deref for HumanDuration {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u64> for HumanDuration {
    fn from(secs: u64) -> Self {
        Self(secs)
    }
}

impl From<u32> for HumanDuration {
    fn from(secs: u32) -> Self {
        Self(u64::from(secs))
    }
}

impl From<HumanDuration> for u64 {
    fn from(d: HumanDuration) -> Self {
        d.0
    }
}

impl From<HumanDuration> for u32 {
    fn from(d: HumanDuration) -> Self {
        d.0 as u32
    }
}

impl FromStr for HumanDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("Empty duration string".to_string());
        }

        // Check suffixes: 'd', 'h', 'm', 's'
        let (num_str, multiplier) = if let Some(n) = trimmed.strip_suffix(['d', 'D']) {
            (n, 86_400u64)
        } else if let Some(n) = trimmed.strip_suffix(['h', 'H']) {
            (n, 3_600u64)
        } else if let Some(n) = trimmed.strip_suffix(['m', 'M']) {
            (n, 60u64)
        } else if let Some(n) = trimmed.strip_suffix(['s', 'S']) {
            (n, 1u64)
        } else {
            (trimmed, 1u64)
        };

        let val: u64 = num_str
            .trim()
            .parse()
            .map_err(|e| format!("Invalid duration '{s}': {e}"))?;

        val.checked_mul(multiplier)
            .map(HumanDuration)
            .ok_or_else(|| format!("Duration '{s}' overflowed u64"))
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0;
        if secs == 0 {
            return write!(f, "0s");
        }
        if secs.is_multiple_of(86_400) {
            write!(f, "{}d", secs / 86_400)
        } else if secs.is_multiple_of(3_600) {
            write!(f, "{}h", secs / 3_600)
        } else if secs.is_multiple_of(60) {
            write!(f, "{}m", secs / 60)
        } else {
            write!(f, "{}s", secs)
        }
    }
}

impl Serialize for HumanDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = HumanDuration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a duration string (e.g. '12h', '30m', '86400s') or an integer of seconds",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<HumanDuration, E>
            where
                E: de::Error,
            {
                FromStr::from_str(value).map_err(de::Error::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<HumanDuration, E>
            where
                E: de::Error,
            {
                Ok(HumanDuration(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<HumanDuration, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    return Err(de::Error::custom("duration cannot be negative"));
                }
                Ok(HumanDuration(value as u64))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_duration_parsing() {
        assert_eq!(
            HumanDuration::from_str("12h").unwrap(),
            HumanDuration(43200)
        );
        assert_eq!(HumanDuration::from_str("30m").unwrap(), HumanDuration(1800));
        assert_eq!(
            HumanDuration::from_str("2d").unwrap(),
            HumanDuration(172800)
        );
        assert_eq!(HumanDuration::from_str("45s").unwrap(), HumanDuration(45));
        assert_eq!(
            HumanDuration::from_str("86400").unwrap(),
            HumanDuration(86400)
        );
    }

    #[test]
    fn test_human_duration_display() {
        assert_eq!(HumanDuration(43200).to_string(), "12h");
        assert_eq!(HumanDuration(1800).to_string(), "30m");
        assert_eq!(HumanDuration(172800).to_string(), "2d");
        assert_eq!(HumanDuration(45).to_string(), "45s");
        assert_eq!(HumanDuration(0).to_string(), "0s");
    }

    #[test]
    fn test_human_duration_serde() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct S {
            lease: HumanDuration,
        }

        let s1: S = toml::from_str("lease = \"12h\"").unwrap();
        assert_eq!(s1.lease, HumanDuration(43200));

        let s2: S = toml::from_str("lease = 43200").unwrap();
        assert_eq!(s2.lease, HumanDuration(43200));

        let encoded = toml::to_string(&s1).unwrap();
        assert_eq!(encoded.trim(), "lease = \"12h\"");
    }
}
