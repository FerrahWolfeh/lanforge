//! Classifies the OS errors of opening a socket into [`BindError`]s.

use std::io;

use lanforge_types::network::bind::{BindError, BindErrorKind};

/// The class of `e`, as the supervisor acts on it.
pub(crate) fn classify(e: &io::Error) -> BindErrorKind {
    match e.kind() {
        io::ErrorKind::AddrInUse => BindErrorKind::AddrInUse,
        io::ErrorKind::PermissionDenied => BindErrorKind::PermissionDenied,
        io::ErrorKind::AddrNotAvailable => BindErrorKind::AddrNotAvailable,
        _ if e.raw_os_error() == Some(libc::ENODEV) => BindErrorKind::NoDevice,
        _ => BindErrorKind::Other,
    }
}

/// `e`, raised while opening `target` (an address or an interface): for sockets a library opens
/// itself (quinn's endpoint).
pub fn bind_error(target: String, e: io::Error) -> BindError {
    BindError::new(classify(&e), target, e)
}

/// Both families of a dual-stack bind failed: classified by the IPv4 error, both kept in the
/// message.
pub(crate) fn dual_bind_error(target: String, e4: &io::Error, e6: &io::Error) -> BindError {
    BindError::new(
        classify(e4),
        target,
        io::Error::new(e4.kind(), format!("IPv4: {e4}; IPv6: {e6}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_errors_map_to_their_class() {
        let enodev = io::Error::from_raw_os_error(libc::ENODEV);
        assert_eq!(classify(&enodev), BindErrorKind::NoDevice);
        let in_use = io::Error::from_raw_os_error(libc::EADDRINUSE);
        assert_eq!(classify(&in_use), BindErrorKind::AddrInUse);
        let eacces = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(classify(&eacces), BindErrorKind::PermissionDenied);
        let eperm = io::Error::from_raw_os_error(libc::EPERM);
        assert_eq!(classify(&eperm), BindErrorKind::PermissionDenied);
    }
}
