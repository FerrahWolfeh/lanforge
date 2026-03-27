#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(clippy::upper_case_acronyms)]
pub enum QType {
    A = 1,
    NS = 2,
    PTR = 12,
    MX = 15,
    AAAA = 28,
    Any = 255,
    Other(u16), // não-exaustivo sem panic
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
