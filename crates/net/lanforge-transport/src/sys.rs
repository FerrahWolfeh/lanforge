//! Safe wrappers over the raw Linux syscalls the network services need.
//!
//! Each function holds one `unsafe` block whose `// SAFETY:` comment names the invariant that makes it
//! sound. Sockets come back as [`OwnedFd`], so error paths close them on drop instead of by hand.

use std::array;
use std::env;
use std::ffi::{CStr, c_int};
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::process;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use socket2::{SockAddr, Socket};
use tokio::io::unix::AsyncFd;

/// `libc::socket`: a new socket owned by the caller.
pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall with integer arguments; no memory is passed.
    let fd = unsafe { libc::socket(domain, ty, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by socket(2), is open, and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Registers an owned descriptor with the tokio reactor.
pub fn register_fd(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: `OwnedFd` keeps the descriptor open until the `AsyncFd` drops it, and its
    // `as_raw_fd()` always returns that same descriptor.
    unsafe { AsyncFd::register(fd) }.map_err(Into::into)
}

/// Registers a `socket2::Socket` with the tokio reactor.
pub fn register_socket(sock: Socket) -> io::Result<AsyncFd<Socket>> {
    // SAFETY: `Socket` owns its descriptor (closed on drop) and `as_raw_fd()` always returns it.
    unsafe { AsyncFd::register(sock) }.map_err(Into::into)
}

/// A link-layer address for `AF_PACKET` sockets. `protocol` is an `ETH_P_*` value in host order.
fn sockaddr_ll(
    ifindex: u32,
    protocol: u16,
    dst_mac: Option<[u8; 6]>,
) -> io::Result<libc::sockaddr_ll> {
    let sll_ifindex = c_int::try_from(ifindex)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ifindex out of range"))?;
    let mut sll_addr = [0u8; 8];
    let mut sll_halen = 0;
    if let Some(mac) = dst_mac {
        sll_addr[..6].copy_from_slice(&mac);
        sll_halen = 6;
    }
    Ok(libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::c_ushort,
        sll_protocol: protocol.to_be(),
        sll_ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen,
        sll_addr,
    })
}

/// Binds an `AF_PACKET` socket to `ifindex`, receiving only frames of `protocol` (`ETH_P_*`, host order).
pub fn bind_packet(fd: BorrowedFd<'_>, ifindex: u32, protocol: u16) -> io::Result<()> {
    let addr = sockaddr_ll(ifindex, protocol, None)?;
    // SAFETY: `addr` is a valid `sockaddr_ll` that outlives the call; the length passed is its size.
    let res = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            socklen_of::<libc::sockaddr_ll>(),
        )
    };
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Sends `frame` (a full Ethernet frame) out of `ifindex` on an `AF_PACKET` socket.
pub fn send_packet(
    fd: BorrowedFd<'_>,
    frame: &[u8],
    ifindex: u32,
    protocol: u16,
    dst_mac: [u8; 6],
) -> io::Result<usize> {
    let addr = sockaddr_ll(ifindex, protocol, Some(dst_mac))?;
    // SAFETY: `frame` is readable for `frame.len()` bytes; `addr` is a valid `sockaddr_ll` that
    // outlives the call and the length passed is its size.
    let n = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            socklen_of::<libc::sockaddr_ll>(),
        )
    };
    byte_count(n)
}

/// `read(2)` into `buf`.
pub fn read(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is writable for `buf.len()` bytes and exclusively borrowed for the call.
    let n = unsafe {
        libc::read(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    byte_count(n)
}

/// `write(2)` of `buf`.
pub fn write(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is readable for `buf.len()` bytes for the duration of the call.
    let n = unsafe {
        libc::write(
            fd.as_raw_fd(),
            buf.as_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    byte_count(n)
}

/// `recv_from` into an initialized buffer (socket2 only takes `MaybeUninit` slices).
pub fn recv_from(sock: &Socket, buf: &mut [u8]) -> io::Result<(usize, SockAddr)> {
    // SAFETY: `[u8]` and `[MaybeUninit<u8>]` have the same layout, and recvfrom(2) only writes
    // initialized bytes, so `buf` stays fully initialized.
    let uninit = unsafe { &mut *(ptr::from_mut(buf) as *mut [MaybeUninit<u8>]) };
    sock.recv_from(uninit)
}

/// `recvfrom(2)` on an `AF_INET6` socket, returning the IPv6 source address.
pub fn recv_from_v6(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV6)> {
    let mut src = MaybeUninit::<libc::sockaddr_in6>::zeroed();
    let mut len = socklen_of::<libc::sockaddr_in6>();
    // SAFETY: `buf` is writable for `buf.len()` bytes; `src` is writable storage of `len` bytes, and
    // the kernel writes at most `len` bytes there.
    let n = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            0,
            src.as_mut_ptr().cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    let n = byte_count(n)?;
    // SAFETY: zero-initialized above, and every bit pattern is a valid `sockaddr_in6`.
    let sa = unsafe { src.assume_init() };
    let addr = SocketAddrV6::new(
        Ipv6Addr::from(sa.sin6_addr.s6_addr),
        u16::from_be(sa.sin6_port),
        sa.sin6_flowinfo,
        sa.sin6_scope_id,
    );
    Ok((n, addr))
}

/// `setsockopt(2)` with a raw byte value.
pub fn set_sockopt_bytes(
    fd: BorrowedFd<'_>,
    level: c_int,
    opt: c_int,
    val: &[u8],
) -> io::Result<()> {
    let len = libc::socklen_t::try_from(val.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket option too long"))?;
    // SAFETY: `val` is readable for `len` bytes for the duration of the call.
    let res = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            opt,
            val.as_ptr().cast::<libc::c_void>(),
            len,
        )
    };
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `setsockopt(2)` with a `c_int` value.
pub fn set_sockopt_int(fd: BorrowedFd<'_>, level: c_int, opt: c_int, val: c_int) -> io::Result<()> {
    set_sockopt_bytes(fd, level, opt, &val.to_ne_bytes())
}

/// The kernel index of interface `name`, or `None` if it does not exist (or the name is not valid).
#[must_use]
pub fn if_name_to_index(name: &str) -> Option<u32> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IF_NAMESIZE || bytes.contains(&0) {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: `buf` is NUL-terminated (the name is shorter than IF_NAMESIZE and the rest is zero).
    let index = unsafe { libc::if_nametoindex(buf.as_ptr().cast::<libc::c_char>()) };
    (index != 0).then_some(index)
}

/// The name of interface `ifindex`, or `None` if no interface has that index.
#[must_use]
pub fn if_index_to_name(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, the size if_indextoname(3) requires; it writes a
    // NUL-terminated name there on success.
    let res = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr().cast::<libc::c_char>()) };
    if res.is_null() {
        return None;
    }
    CStr::from_bytes_until_nul(&buf)
        .ok()?
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// The hardware (MAC) address of interface `name`, via `SIOCGIFHWADDR`.
#[must_use]
pub fn if_hwaddr(name: &str) -> Option<[u8; 6]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IF_NAMESIZE || bytes.contains(&0) {
        return None;
    }
    let sock = socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0).ok()?;
    // SAFETY: `ifreq` is plain data (integers, arrays and unions of them): all-zero is valid.
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    for (dst, &b) in ifr.ifr_name.iter_mut().zip(bytes) {
        *dst = b as libc::c_char;
    }
    // SAFETY: SIOCGIFHWADDR reads the NUL-terminated `ifr_name` and writes `ifr_ifru.ifru_hwaddr`
    // inside the `ifreq` we own.
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR, &raw mut ifr) };
    if res < 0 {
        return None;
    }
    // SAFETY: SIOCGIFHWADDR succeeded, so `ifru_hwaddr` is the active union field.
    let hw = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Some(array::from_fn(|i| hw[i] as u8))
}

/// First descriptor the service manager passes (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: RawFd = 3;

/// The descriptors the service manager passed at start (`sd_listen_fds_with_names(3)`): socket
/// activation or the unit's fd store, each with its `FDNAME`. Marked close-on-exec. Only the first
/// call returns them (each descriptor has one owner); later calls, or a process not started with
/// `LISTEN_PID` = its own PID, get an empty list.
#[must_use]
pub fn take_inherited_fds() -> Vec<(String, OwnedFd)> {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    let ours = env::var("LISTEN_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
        == Some(process::id());
    if !ours || TAKEN.swap(true, Ordering::AcqRel) {
        return Vec::new();
    }
    let count = env::var("LISTEN_FDS")
        .ok()
        .and_then(|n| n.parse::<RawFd>().ok())
        .unwrap_or(0)
        .clamp(0, 1024);
    let names = env::var("LISTEN_FDNAMES").unwrap_or_default();
    let mut names = names.split(':');
    (LISTEN_FDS_START..LISTEN_FDS_START + count)
        .filter_map(|fd| {
            let name = names.next().unwrap_or("unknown").to_owned();
            // SAFETY: fcntl(2) on an integer descriptor; F_SETFD only changes its flags. One that
            // is not open fails with EBADF and is skipped.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
                return None;
            }
            // SAFETY: the service manager passed `fd` open to this process (LISTEN_PID matches,
            // fcntl just succeeded on it), and `TAKEN` makes this the only place that owns it.
            Some((name, unsafe { OwnedFd::from_raw_fd(fd) }))
        })
        .collect()
}

/// Whether the process runs with effective UID 0.
#[must_use]
pub fn is_root() -> bool {
    // SAFETY: geteuid(2) takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn socklen_of<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(mem::size_of::<T>()).expect("socket address types are a few bytes")
}

fn byte_count(n: isize) -> io::Result<usize> {
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn loopback_name_and_index_round_trip() {
        let index = if_name_to_index("lo").expect("every network namespace has lo");
        assert_eq!(if_index_to_name(index).as_deref(), Some("lo"));
        assert_eq!(if_hwaddr("lo"), Some([0; 6]), "lo has an all-zero MAC");
    }

    #[test]
    fn invalid_interface_names_are_none() {
        assert_eq!(if_name_to_index(""), None);
        assert_eq!(if_name_to_index("bad\0name"), None);
        assert_eq!(if_name_to_index("a-name-longer-than-ifnamsiz"), None);
        assert_eq!(if_name_to_index("lanforge-nope0"), None);
        assert_eq!(if_index_to_name(u32::MAX), None);
        assert_eq!(if_hwaddr("lanforge-nope0"), None);
    }

    #[test]
    #[ignore = "needs CAP_NET_RAW (run inside `unshare -rn`)"]
    fn packet_socket_receives_only_its_ethertype() {
        const PROTO: u16 = 0x88b5; // IEEE 802 local experimental EtherType
        let lo = if_name_to_index("lo").unwrap();
        let open = || {
            socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                c_int::from(PROTO.to_be()),
            )
            .unwrap()
        };
        let rx = open();
        bind_packet(rx.as_fd(), lo, PROTO).unwrap();
        let tx = open();
        bind_packet(tx.as_fd(), lo, PROTO).unwrap();

        let mut frame = [0u8; 60];
        frame[12..14].copy_from_slice(&PROTO.to_be_bytes());
        frame[14..18].copy_from_slice(b"lfrg");
        assert_eq!(
            send_packet(tx.as_fd(), &frame, lo, PROTO, [0xff; 6]).unwrap(),
            60
        );

        let mut buf = [0u8; 128];
        let n = read(rx.as_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], &frame[..]);
    }
}
