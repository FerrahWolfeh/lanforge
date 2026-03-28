/// Common DNS Query Types (QType) used for optimized hot-path routing.
///
/// This enum is non-exhaustive, falling back to `Other(u16)` for any
/// types not explicitly handled in the fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(clippy::upper_case_acronyms)]
pub enum QType {
    /// Host address (IPv4)
    A = 1,
    /// Name server
    NS = 2,
    /// Domain name pointer (Reverse DNS)
    PTR = 12,
    /// Mail exchange
    MX = 15,
    /// IPv6 address
    AAAA = 28,
    /// Request for all records
    Any = 255,
    /// Any other DNS record type (as u16)
    Other(u16),
}

impl From<u16> for QType {
    #[inline(always)]
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
