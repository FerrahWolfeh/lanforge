//! Common DNS query types for hot-path routing.

/// Common DNS Query Types (`QType`) used for optimized hot-path routing.
///
/// Only the most frequently encountered types are enumerated explicitly.
/// All other types fall into `Other(u16)` and are routed to the slow path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(clippy::upper_case_acronyms)]
pub enum QType {
    /// Host address (IPv4) — type 1
    A = 1,
    /// Authoritative name server — type 2
    NS = 2,
    /// Domain name pointer (Reverse DNS) — type 12
    PTR = 12,
    /// Mail exchange — type 15
    MX = 15,
    /// Host address (IPv6) — type 28
    AAAA = 28,
    /// Request for all available records — type 255
    Any = 255,
    /// Any other DNS record type not explicitly handled.
    Other(u16),
}

impl From<u16> for QType {
    #[inline]
    fn from(v: u16) -> Self {
        match v {
            1 => Self::A,
            2 => Self::NS,
            12 => Self::PTR,
            15 => Self::MX,
            28 => Self::AAAA,
            255 => Self::Any,
            n => Self::Other(n),
        }
    }
}

impl std::fmt::Display for QType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::NS => write!(f, "NS"),
            Self::PTR => write!(f, "PTR"),
            Self::MX => write!(f, "MX"),
            Self::AAAA => write!(f, "AAAA"),
            Self::Any => write!(f, "ANY"),
            Self::Other(n) => write!(f, "TYPE{n}"),
        }
    }
}
