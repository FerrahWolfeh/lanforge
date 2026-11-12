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

struct Kept {
    record: SessionRecord,
    pppox: OwnedFd,
    unit: OwnedFd,
    chan: OwnedFd,
}

/// This process's copies of what the store holds.
static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

/// Takes back the session a previous process left in the store.
///
/// Call once at start, before anything else takes the inherited descriptors. A partial or
/// unreadable set is dropped from the store: its link goes down and the service dials anew.
pub fn adopt_inherited() {
    let mut fds: Vec<(String, OwnedFd)> = sys::take_inherited_fds()
        .into_iter()
        .filter(|(name, _)| NAMES.contains(&name.as_str()))
        .collect();
    if fds.is_empty() {
        return;
    }
    let mut take = |name: &str| {
        let at = fds.iter().position(|(n, _)| n == name)?;
        Some(fds.swap_remove(at).1)
    };
    let (pppox, unit, chan, record) = (take(PPPOX), take(UNIT), take(CHAN), take(RECORD));
    let kept = match (pppox, unit, chan, record.map(read_record)) {
        (Some(pppox), Some(unit), Some(chan), Some(Ok(record))) => match unit_of(&unit) {
            Ok(id) if id == record.unit_id => Some(Kept {
                record,
                pppox,
                unit,
                chan,
            }),
            other => {
                warn!(expected = record.unit_id, found = ?other, "Kept PPPoE session's PPP unit is gone");
                None
            }
        },
        (_, _, _, Some(Err(e))) => {
            warn!(error = %e, "Kept PPPoE session record unreadable");
            None
        }
        _ => {
            warn!("Kept PPPoE session is incomplete in the fd store");
            None
        }
    };
    if let Some(k) = kept {
        info!(
            interface = %k.record.interface,
            session_id = k.record.session_id,
            "PPPoE session kept across the restart; taking it over"
        );
        *KEPT.lock() = Some(k);
    } else {
        remove_from_store();
    }
}

/// Copies of the kept session's descriptors, with its record.
pub fn kept() -> Option<(SessionRecord, KernelSession)> {
    let dup = |fd: &OwnedFd| {
        fd.try_clone()
            .inspect_err(|e| warn!(error = %e, "Cannot copy a kept PPPoE descriptor"))
            .ok()
    };
    KEPT.lock().as_ref().and_then(|k| {
        Some((
            k.record.clone(),
            KernelSession {
                session_fd: dup(&k.pppox)?,
                ppp_unit_fd: dup(&k.unit)?,
                ppp_chan_fd: dup(&k.chan)?,
                interface_name: k.record.interface.clone(),
                unit_id: k.record.unit_id,
            },
        ))
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
    let kept = Kept {
        record: record.clone(),
        pppox: session.session_fd.try_clone()?,
        unit: session.ppp_unit_fd.try_clone()?,
        chan: session.ppp_chan_fd.try_clone()?,
    };
    let memfd = OwnedFd::from(memfd);
    for (name, fd) in NAMES
        .into_iter()
        .zip([&kept.pppox, &kept.unit, &kept.chan, &memfd])
    {
        sd_notify::notify_with_fds(
            &[NotifyState::FdStore, NotifyState::FdName(name)],
            &[fd.as_fd()],
        )?;
    }
    Ok(kept)
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
