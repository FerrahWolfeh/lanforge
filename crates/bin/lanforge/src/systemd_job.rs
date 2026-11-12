//! Whether systemd stops the daemon to start it again or for good.
//!
//! `systemctl restart` and `systemctl stop` (or a shutdown) send the same SIGTERM; the job
//! systemd runs for the unit tells them apart (`restart` vs `stop`).

use std::fs;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, info};

/// Asks systemd whether a `restart` job runs for this daemon's unit. Anything unexpected (not
/// under systemd, `systemctl` missing or slow) reads as a stop, which tears everything down as
/// before.
pub async fn restart_pending() -> bool {
    let Some(unit) = own_unit() else {
        return false;
    };
    let query = Command::new("systemctl")
        .args(["list-jobs", "--no-legend", "--", &unit])
        .output();
    let jobs = match timeout(Duration::from_secs(3), query).await {
        Ok(Ok(out)) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        other => {
            debug!(
                ?other,
                "systemd job query failed; treating the shutdown as a stop"
            );
            return false;
        }
    };
    let restarting = restart_job_in(&jobs, &unit);
    if restarting {
        info!(unit = %unit, "systemd is restarting the daemon");
    }
    restarting
}

/// The systemd unit of this process, from its cgroup (`0::/system.slice/lanforge.service`).
fn own_unit() -> Option<String> {
    let cgroup = fs::read_to_string("/proc/self/cgroup").ok()?;
    unit_of_cgroup(&cgroup)
}

fn unit_of_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .rsplit('/')
        .next()
        .filter(|u| u.ends_with(".service"))
        .map(str::to_owned)
}

/// Whether `systemctl list-jobs --no-legend` output holds a `restart` job for `unit`
/// (`<id> <unit> <type> <state>` per line).
fn restart_job_in(jobs: &str, unit: &str) -> bool {
    jobs.lines().any(|line| {
        let mut cols = line.split_whitespace().skip(1);
        cols.next() == Some(unit) && cols.next() == Some("restart")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_comes_from_the_unified_cgroup() {
        assert_eq!(
            unit_of_cgroup("0::/system.slice/lanforge.service\n").as_deref(),
            Some("lanforge.service")
        );
        assert_eq!(
            unit_of_cgroup("0::/user.slice/user-1000.slice/session-2.scope\n"),
            None
        );
        assert_eq!(unit_of_cgroup(""), None);
    }

    /// Captured on systemd 262 from a unit's SIGTERM handler: `restart` then `stop`.
    #[test]
    fn only_a_restart_job_of_the_unit_counts() {
        let unit = "lanforge.service";
        assert!(restart_job_in(
            "1060 lanforge.service restart running\n",
            unit
        ));
        assert!(!restart_job_in(
            "1080 lanforge.service stop running\n",
            unit
        ));
        assert!(!restart_job_in(
            "1090 other.service restart running\n",
            unit
        ));
        assert!(!restart_job_in("", unit));
    }
}
