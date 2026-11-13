//! Why a socket could not be opened: what the supervisor acts on and what the status shows.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

/// The class of a bind failure, decided by the transport that saw the OS error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindErrorKind {
    /// Another process holds the address (`EADDRINUSE`).
    AddrInUse,
    /// The interface does not exist (yet): `ENODEV`, or a name that resolves to no index.
    NoDevice,
    /// Missing privilege (`EACCES`/`EPERM`): a low port or a raw socket without the capability.
    PermissionDenied,
    /// The address is not on any interface (`EADDRNOTAVAIL`).
    AddrNotAvailable,
    Other,
}

impl Display for BindErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AddrInUse => "address in use",
            Self::NoDevice => "no such interface",
            Self::PermissionDenied => "permission denied",
            Self::AddrNotAvailable => "address not available",
            Self::Other => "bind failed",
        })
    }
}

/// A socket the transport could not open: the class, what it tried to bind (an address or an
/// interface) and the OS error.
#[derive(Debug)]
pub struct BindError {
    pub kind: BindErrorKind,
    pub target: String,
    pub source: io::Error,
}

impl BindError {
    #[must_use]
    pub const fn new(kind: BindErrorKind, target: String, source: io::Error) -> Self {
        Self {
            kind,
            target,
            source,
        }
    }
}

impl Display for BindError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} ({})", self.kind, self.target, self.source)
    }
}

impl Error for BindError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Callers that speak `io::Error` keep the kind and can still find the `BindError` inside
/// (`get_ref` + `downcast_ref`).
impl From<BindError> for io::Error {
    fn from(e: BindError) -> Self {
        Self::new(e.source.kind(), e)
    }
}
