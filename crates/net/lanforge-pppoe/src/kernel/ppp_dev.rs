use crate::error::PppoeError;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use tracing::{debug, info};

nix::ioctl_readwrite!(pppiocnewunit, 't', 62, libc::c_int);
nix::ioctl_read!(pppiocgchan, 't', 55, libc::c_int);
nix::ioctl_write_ptr!(pppiocattchan, 't', 56, libc::c_int);
nix::ioctl_write_ptr!(pppiocconnect, 't', 58, libc::c_int);
nix::ioctl_write_ptr!(pppiocsmru, 't', 82, libc::c_int);
nix::ioctl_write_ptr!(pppiocsflags, 't', 89, libc::c_int);
nix::ioctl_read!(pppiocgunit, 't', 86, libc::c_int);

pub struct KernelSession {
    pub session_fd: OwnedFd,
    pub ppp_unit_fd: OwnedFd,
    pub ppp_chan_fd: OwnedFd,
    pub interface_name: String,
    pub unit_id: i32,
}

pub fn handoff_to_kernel(session_fd: OwnedFd, mru: u16) -> Result<KernelSession, PppoeError> {
    if !Path::new("/dev/ppp").exists() {
        return Err(PppoeError::DevPppUnavailable);
    }

    debug!("Handoff step 1: Opening /dev/ppp for unit creation");
    let ppp_unit_fd = open(
        Path::new("/dev/ppp"),
        OFlag::O_RDWR | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;

    debug!("Handoff step 2: PPPIOCNEWUNIT");
    let mut unit_id: libc::c_int = -1;
    // SAFETY: PPPIOCNEWUNIT reads and writes one `c_int` (`unit_id`, owned here) on an open /dev/ppp fd.
    unsafe { pppiocnewunit(ppp_unit_fd.as_raw_fd(), &raw mut unit_id) }?;

    debug!(unit_id, "Handoff step 3: PPPIOCGCHAN on session_fd");
    let mut chan_num: libc::c_int = 0;
    // SAFETY: PPPIOCGCHAN writes one `c_int` (`chan_num`, owned here); `session_fd` is a connected
    // AF_PPPOX socket owned by the caller.
    unsafe { pppiocgchan(session_fd.as_raw_fd(), &raw mut chan_num) }?;

    debug!(
        chan_num,
        "Handoff step 4: Opening second /dev/ppp for channel"
    );
    let ppp_chan_fd = open(
        Path::new("/dev/ppp"),
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?;

    debug!("Handoff step 5: PPPIOCATTCHAN");
    // SAFETY: PPPIOCATTCHAN reads one `c_int` (`chan_num`) on an open /dev/ppp fd.
    unsafe { pppiocattchan(ppp_chan_fd.as_raw_fd(), &raw const chan_num) }?;

    debug!("Handoff step 6: PPPIOCCONNECT");
    // SAFETY: PPPIOCCONNECT reads one `c_int` (`unit_id`) on an open /dev/ppp fd.
    unsafe { pppiocconnect(ppp_chan_fd.as_raw_fd(), &raw const unit_id) }?;

    debug!("Handoff step 7: PPPIOCSMRU");
    let mru_val = libc::c_int::from(mru);
    // SAFETY: PPPIOCSMRU reads one `c_int` (`mru_val`) on an open /dev/ppp fd.
    unsafe { pppiocsmru(ppp_unit_fd.as_raw_fd(), &raw const mru_val) }?;

    debug!("Handoff step 8: PPPIOCSFLAGS");
    let flags: libc::c_int = 0;
    // SAFETY: PPPIOCSFLAGS reads one `c_int` (`flags`) on an open /dev/ppp fd.
    unsafe { pppiocsflags(ppp_unit_fd.as_raw_fd(), &raw const flags) }?;

    let interface_name = format!("ppp{unit_id}");
    info!(
        unit = unit_id,
        interface = %interface_name,
        "Successfully handed off PPPoE session to kernel ppp_generic"
    );

    Ok(KernelSession {
        session_fd,
        ppp_unit_fd,
        ppp_chan_fd,
        interface_name,
        unit_id,
    })
}

/// The PPP unit number behind an open `/dev/ppp` unit descriptor (`PPPIOCGUNIT`).
pub fn unit_of(ppp_unit_fd: &OwnedFd) -> Result<i32, PppoeError> {
    let mut unit_id: libc::c_int = -1;
    // SAFETY: PPPIOCGUNIT writes one `c_int` (`unit_id`, owned here) on an open /dev/ppp fd.
    unsafe { pppiocgunit(ppp_unit_fd.as_raw_fd(), &raw mut unit_id) }?;
    Ok(unit_id)
}
