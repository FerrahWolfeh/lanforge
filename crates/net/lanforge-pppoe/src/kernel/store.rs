//! The service manager's fd store (systemd `FDSTORE=1`) as the keeper of a live session while
//! the daemon restarts.
//!
//! When a session comes up, copies of its descriptors and its [`SessionRecord`] (in a memfd) go
//! to the store under fixed names. systemd keeps them across a restart of the unit and passes
//! them to the next process, which takes them back with [`adopt_inherited`]; a full stop of the
//! unit closes them. This process keeps the same copies in [`KEPT`] so a restarted service task
//! takes the session over the same way.

use super::ppp_dev::{KernelSession, unit_of};
use crate::handoff::SessionRecord;
use lanforge_transport::sys;
use nix::sys::memfd::{MFdFlags, memfd_create};
use parking_lot::Mutex;
use sd_notify::NotifyState;
use std::env;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsFd, OwnedFd};
use tracing::{debug, info, warn};

/// Store names: the `AF_PPPOX` socket, the `/dev/ppp` unit and channel, and the record.
const PPPOX: &str = "pppoe-pppox";
const UNIT: &str = "pppoe-unit";
const CHAN: &str = "pppoe-chan";
const RECORD: &str = "pppoe-record";
const NAMES: [&str; 4] = [PPPOX, UNIT, CHAN, RECORD];

/// The descriptors that keep the link up.
struct Link {
    pppox: OwnedFd,
    unit: OwnedFd,
    chan: OwnedFd,
}

struct Kept {
    record: SessionRecord,
    /// `None`: the record came back without (all) its descriptors, the link is gone. The record
    /// still names the session, so the service ends it with a PADT instead of leaving it
    /// half-open on the concentrator.
    link: Option<Link>,
}

/// This process's copies of what the store holds.
static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

/// Takes back the session a previous process left in the store.
///
/// Call once at start, before anything else takes the inherited descriptors. Without a readable
/// record nothing is taken and the store is cleared.
pub fn adopt_inherited() {
    let fds: Vec<(String, OwnedFd)> = sys::take_inherited_fds()
        .into_iter()
        .filter(|(name, _)| NAMES.contains(&name.as_str()))
        .collect();
    if fds.is_empty() {
        return;
    }
    let kept = from_inherited(fds);
    match &kept {
        Some(Kept {
            record,
            link: Some(_),
        }) => info!(
            interface = %record.interface,
            session_id = record.session_id,
            "PPPoE session kept across the restart; taking it over"
        ),
        Some(Kept { link: None, .. }) => {}
        None => remove_from_store(),
    }
    *KEPT.lock() = kept;
}

/// The kept session in the descriptors the store passed (`(FDNAME, fd)`, ours only).
fn from_inherited(mut fds: Vec<(String, OwnedFd)>) -> Option<Kept> {
    let names: Vec<String> = fds.iter().map(|(n, _)| n.clone()).collect();
    let mut take = |name: &str| {
        let at = fds.iter().position(|(n, _)| n == name)?;
        Some(fds.swap_remove(at).1)
    };
    let (pppox, unit, chan, record) = (take(PPPOX), take(UNIT), take(CHAN), take(RECORD));
    let record = match record.map(read_record) {
        Some(Ok(record)) => record,
        Some(Err(e)) => {
            warn!(error = %e, "Kept PPPoE session record unreadable");
            return None;
        }
        None => {
            warn!(received = ?names, "Kept PPPoE descriptors came back without their record");
            return None;
        }
    };
    let link = if let (Some(pppox), Some(unit), Some(chan)) = (pppox, unit, chan) {
        match unit_of(&unit) {
            Ok(id) if id == record.unit_id => Some(Link { pppox, unit, chan }),
            other => {
                warn!(expected = record.unit_id, found = ?other, "Kept PPPoE session's PPP unit is gone");
                None
            }
        }
    } else {
        warn!(
            received = ?names,
            session_id = record.session_id,
            "Kept PPPoE session came back without all its descriptors (refused by the fd store?)"
        );
        None
    };
    Some(Kept { record, link })
}

/// The kept session's record, with copies of its descriptors (`None` once the link is gone).
pub fn kept() -> Option<(SessionRecord, Option<KernelSession>)> {
    let dup = |fd: &OwnedFd| {
        fd.try_clone()
            .inspect_err(|e| warn!(error = %e, "Cannot copy a kept PPPoE descriptor"))
            .ok()
    };
    KEPT.lock().as_ref().map(|k| {
        let kernel = k.link.as_ref().and_then(|l| {
            Some(KernelSession {
                session_fd: dup(&l.pppox)?,
                ppp_unit_fd: dup(&l.unit)?,
                ppp_chan_fd: dup(&l.chan)?,
                interface_name: k.record.interface.clone(),
                unit_id: k.record.unit_id,
            })
        });
        (k.record.clone(), kernel)
    })
}

/// Hands copies of `session` and `record` to the store.
///
/// `false` when the unit has no fd store (not under systemd, no `FileDescriptorStoreMax=`,
/// systemd older than 254) or sending failed: the session then ends with this process.
pub fn keep(session: &KernelSession, record: &SessionRecord) -> bool {
    let capacity = env::var("FDSTORE")
        .ok()
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    if env::var_os("NOTIFY_SOCKET").is_none() || capacity < NAMES.len() {
        debug!(
            capacity,
            "No fd store for the PPPoE session; it ends with this process"
        );
        return false;
    }
    match store(session, record) {
        Ok(kept) => {
            *KEPT.lock() = Some(kept);
            debug!(interface = %record.interface, "PPPoE session kept in the fd store");
            true
        }
        Err(e) => {
            warn!(error = %e, "Cannot keep the PPPoE session in the fd store; it ends with this process");
            remove_from_store();
            false
        }
    }
}

/// Drops the kept session: the store closes its copies.
pub fn release() {
    if KEPT.lock().take().is_some() {
        remove_from_store();
    }
}

fn store(session: &KernelSession, record: &SessionRecord) -> io::Result<Kept> {
    // A set left by an earlier session must not mix with this one.
    remove_from_store();
    let mut memfd = File::from(memfd_create(
        "lanforge-pppoe-session",
        MFdFlags::MFD_CLOEXEC,
    )?);
    memfd.write_all(&record.encode())?;
    let link = Link {
        pppox: session.session_fd.try_clone()?,
        unit: session.ppp_unit_fd.try_clone()?,
        chan: session.ppp_chan_fd.try_clone()?,
    };
    let memfd = OwnedFd::from(memfd);
    for (name, fd) in NAMES
        .into_iter()
        .zip([&link.pppox, &link.unit, &link.chan, &memfd])
    {
        sd_notify::notify_with_fds(
            &[NotifyState::FdStore, NotifyState::FdName(name)],
            &[fd.as_fd()],
        )?;
    }
    Ok(Kept {
        record: record.clone(),
        link: Some(link),
    })
}

fn read_record(fd: OwnedFd) -> io::Result<SessionRecord> {
    let mut file = File::from(fd);
    file.rewind()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    SessionRecord::decode(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown record version or damaged record",
        )
    })
}

fn remove_from_store() {
    for name in NAMES {
        let _ = sd_notify::notify(&[NotifyState::FdStoreRemove, NotifyState::FdName(name)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PppoeConfig;
    use crate::discovery::DiscoveryResult;
    use crate::ipcp::IpcpNegotiated;
    use crate::lcp::LcpNegotiated;
    use lanforge_types::identifiers::MacAddr;
    use lanforge_types::network::pppoe::AuthMethod;
    use smallvec::smallvec;

    fn record_fd(bytes: &[u8]) -> OwnedFd {
        let mut f = File::from(memfd_create("test-record", MFdFlags::MFD_CLOEXEC).unwrap());
        f.write_all(bytes).unwrap();
        OwnedFd::from(f)
    }

    fn record() -> SessionRecord {
        SessionRecord::new(
            &PppoeConfig::default(),
            MacAddr([2, 0, 0, 0, 0, 2]),
            &DiscoveryResult {
                ac_mac: MacAddr([2, 0, 0, 0xac, 0, 1]),
                ac_name: None,
                session_id: 0x0077,
            },
            &LcpNegotiated {
                mru: 1492,
                local_magic: 1,
                peer_magic: 2,
                auth_method: AuthMethod::ChapMd5,
                early_frames: Vec::new(),
            },
            &IpcpNegotiated {
                local_ip: None,
                peer_ip: None,
                dns: smallvec![],
                local_v6_ll: None,
                peer_v6_ll: None,
            },
            "ppp0",
            0,
            0,
        )
    }

    /// What the store on the box passed back under `SELinux`: the record alone. The record is kept
    /// (so the session gets its PADT), without a link.
    #[test]
    fn a_record_without_its_descriptors_is_kept_to_end_the_session() {
        let rec = record();
        let kept = from_inherited(vec![(RECORD.into(), record_fd(&rec.encode()))])
            .expect("the record is kept");
        assert_eq!(kept.record, rec);
        assert!(kept.link.is_none());
    }

    /// Descriptors that are not a PPP unit (the unit died, or a stray fd) give no link either.
    #[test]
    fn descriptors_without_a_live_ppp_unit_give_no_link() {
        let rec = record();
        let other = || record_fd(b"x");
        let kept = from_inherited(vec![
            (PPPOX.into(), other()),
            (UNIT.into(), other()),
            (CHAN.into(), other()),
            (RECORD.into(), record_fd(&rec.encode())),
        ])
        .expect("the record is kept");
        assert!(kept.link.is_none());
    }

    #[test]
    fn descriptors_without_a_readable_record_are_dropped() {
        assert!(from_inherited(vec![(UNIT.into(), record_fd(b"x"))]).is_none());
        assert!(from_inherited(vec![(RECORD.into(), record_fd(b"garbage"))]).is_none());
    }
}
