//! The interfaces snapshot reports the real carrier (IFF_LOWER_UP), not the admin flag.

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::synthetic::interfaces::InterfacesService;

fn ip(args: &str) {
    let ok = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "ip {args}");
}

fn carrier(name: &str) -> bool {
    InterfacesService::scan_interfaces(1)
        .find_by_name(name)
        .unwrap_or_else(|| panic!("{name} missing from the snapshot"))
        .carrier
}

/// A port that is administratively up but has no link partner (cable out, ONT off) has no
/// carrier: a veth whose peer is down is exactly that.
#[test]
#[ignore = "needs CAP_NET_ADMIN (run inside `unshare -rn`)"]
fn an_admin_up_port_without_link_has_no_carrier() {
    ip("link add lfwan type veth peer name lfont");
    ip("link set lfwan up");
    assert!(!carrier("lfwan"), "admin up, peer down: no carrier");

    ip("link set lfont up");
    // The kernel flips the carrier asynchronously once both ends are up.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !carrier("lfwan") {
        assert!(Instant::now() < deadline, "carrier never came up");
        thread::sleep(Duration::from_millis(20));
    }

    ip("link set lfont down");
    assert!(!carrier("lfwan"), "peer down again: carrier lost");
    ip("link del lfwan");
}
