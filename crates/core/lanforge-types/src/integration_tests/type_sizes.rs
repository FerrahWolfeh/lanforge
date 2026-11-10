//! Size budgets for the types copied on hot paths: every bus publish clones a `TimedEvent` into
//! each subscriber's slot, `ctx.apply` moves a `DeviceUpdate` and returns an `EventVec`, the state
//! copies `Device` records on write, and the DNS engine builds `DnsMessage`/`DnsRecord` per query.
//! A field or variant that makes one of them grow fails here: box the large payload, or raise the
//! budget on purpose. Budgets are the 64-bit sizes with every feature on, as the daemon ships;
//! slimmer builds come in under them.
#![cfg(target_pointer_width = "64")]

use std::mem::size_of;

use crate::device::Device;
use crate::events::{EventVec, LanforgeEvent, TimedEvent};
use crate::identifiers::{DeviceIdentifier, Duid, MacAddr};
use crate::network::Hostname;
use crate::network::dns::{DnsMessage, DnsRecord, QueryLogEntry};
use crate::update::DeviceUpdate;

#[test]
fn hot_types_stay_within_their_size_budget() {
    let sizes = [
        ("MacAddr", size_of::<MacAddr>(), 6),
        ("Duid", size_of::<Duid>(), 16),
        ("DeviceIdentifier", size_of::<DeviceIdentifier>(), 24),
        ("Hostname", size_of::<Hostname>(), 32),
        ("Device", size_of::<Device>(), 104),
        ("DeviceUpdate", size_of::<DeviceUpdate>(), 32),
        ("LanforgeEvent", size_of::<LanforgeEvent>(), 40),
        ("TimedEvent", size_of::<TimedEvent>(), 56),
        ("EventVec", size_of::<EventVec>(), 168),
        ("DnsMessage", size_of::<DnsMessage>(), 120),
        ("DnsRecord", size_of::<DnsRecord>(), 64),
        ("QueryLogEntry", size_of::<QueryLogEntry>(), 112),
    ];
    let over: Vec<String> = sizes
        .iter()
        .filter(|(_, size, budget)| size > budget)
        .map(|(name, size, budget)| format!("{name}: {size} B, budget {budget} B"))
        .collect();
    assert!(
        over.is_empty(),
        "types grew past their budget:\n{}",
        over.join("\n")
    );
}
