use crate::error::PppoeError;
use aya::maps::HashMap;
use aya::programs::tc::{qdisc_add_clsact, SchedClassifierLinkId, TcAttachType};
use aya::programs::xdp::XdpLinkId;
use aya::programs::{SchedClassifier, Xdp, XdpFlags};
use aya::{Ebpf, Pod};
use std::net::Ipv4Addr;
use tracing::{debug, info};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PppoeSessionMapValue {
    pub session_id: u16,
    pub mss_clamp: u16,
    pub ac_mac: [u8; 6],
    pub local_mac: [u8; 6],
    pub local_ip: u32,
    pub peer_ip: u32,
    pub active: u8,
    pub pad: [u8; 3],
}

// SAFETY: PppoeSessionMapValue is a plain-old-data repr(C) struct with no pointers or padding traps.
unsafe impl Pod for PppoeSessionMapValue {}

pub struct EbpfSession {
    bpf: Ebpf,
    pub ifindex: u32,
    pub ifname: String,
    pub session_id: u16,
    xdp_link: Option<XdpLinkId>,
    tc_link: Option<SchedClassifierLinkId>,
}

#[repr(C, align(8))]
struct AlignedBytecode([u8; include_bytes!(concat!(env!("OUT_DIR"), "/pppoe_fastpath.bpf.o")).len()]);

static BYTECODE: AlignedBytecode =
    AlignedBytecode(*include_bytes!(concat!(env!("OUT_DIR"), "/pppoe_fastpath.bpf.o")));

impl EbpfSession {
    #[allow(clippy::too_many_arguments)]
    pub fn attach(
        ifindex: u32,
        ifname: &str,
        session_id: u16,
        ac_mac: [u8; 6],
        local_mac: [u8; 6],
        local_ip: Option<Ipv4Addr>,
        peer_ip: Option<Ipv4Addr>,
        mru: u16,
    ) -> Result<Self, PppoeError> {
        // PPPOE_BPF_HASH is emitted by build.rs as a hash of the compiled .o content.
        // Referencing it here ensures cargo recompiles this file — and re-runs
        // include_bytes! — whenever the BPF bytecode changes.
        let _ = env!("PPPOE_BPF_HASH");
        let mut bpf = Ebpf::load(&BYTECODE.0).map_err(|e| {
            PppoeError::NegotiationFailed(format!("Failed to load eBPF bytecode: {e:#?}"))
        })?;

        debug!(ifname, "Attaching XDP PPPoE ingress decapsulator");
        let xdp_link = if let Some(prog) = bpf.program_mut("pppoe_ingress_decap") {
            let xdp: &mut Xdp = prog
                .try_into()
                .map_err(|e| PppoeError::NegotiationFailed(format!("Invalid XDP ingress program: {e}")))?;
            xdp.load().map_err(|e| {
                PppoeError::NegotiationFailed(format!("Failed to load XDP ingress program: {e}"))
            })?;
            let link_id = xdp.attach(ifname, XdpFlags::SKB_MODE).map_err(|e| {
                PppoeError::NegotiationFailed(format!(
                    "Failed to attach XDP ingress decapsulator to {ifname}: {e}"
                ))
            })?;
            info!(ifname, "XDP PPPoE ingress decapsulator successfully attached");
            Some(link_id)
        } else {
            return Err(PppoeError::NegotiationFailed(
                "XDP program pppoe_ingress_decap not found in bytecode".into(),
            ));
        };

        // Add clsact qdisc if not already present
        let _ = qdisc_add_clsact(ifname);

        debug!(ifname, "Attaching TC PPPoE egress encapsulator and MSS clamper");
        let tc_link = if let Some(prog) = bpf.program_mut("pppoe_egress_encap") {
            let tc_out: &mut SchedClassifier = prog
                .try_into()
                .map_err(|e| PppoeError::NegotiationFailed(format!("Invalid TC egress program: {e}")))?;
            tc_out.load().map_err(|e| {
                PppoeError::NegotiationFailed(format!("Failed to load TC egress program: {e}"))
            })?;
            let link_id = tc_out.attach(ifname, TcAttachType::Egress).map_err(|e| {
                PppoeError::NegotiationFailed(format!(
                    "Failed to attach TC egress classifier to {ifname}: {e}"
                ))
            })?;
            info!(ifname, "TC PPPoE egress encapsulator successfully attached");
            Some(link_id)
        } else {
            return Err(PppoeError::NegotiationFailed(
                "TC program pppoe_egress_encap not found in bytecode".into(),
            ));
        };

        // Compute MSS clamp (1492 - 40 = 1452 by default)
        let mss_clamp = mru.saturating_sub(40);
        let val = PppoeSessionMapValue {
            session_id,
            mss_clamp,
            ac_mac,
            local_mac,
            local_ip: local_ip.map_or(0, |ip| u32::from_ne_bytes(ip.octets())),
            peer_ip: peer_ip.map_or(0, |ip| u32::from_ne_bytes(ip.octets())),
            active: 1,
            pad: [0; 3],
        };

        if let Some(map_obj) = bpf.map_mut("pppoe_sessions") {
            let mut map: HashMap<_, u32, PppoeSessionMapValue> =
                HashMap::try_from(map_obj).map_err(|e| {
                    PppoeError::NegotiationFailed(format!("Invalid map pppoe_sessions: {e}"))
                })?;
            map.insert(ifindex, val, 0).map_err(|e| {
                PppoeError::NegotiationFailed(format!(
                    "Failed to insert session into BPF map: {e}"
                ))
            })?;
            // Also populate key 0 as fallback for TC egress packets where skb->ifindex may be 0
            let _ = map.insert(0u32, val, 0);
            info!(
                ifindex,
                session_id, mss_clamp, "Populated BPF session map for PPPoE fast-path"
            );
        }

        Ok(Self {
            bpf,
            ifindex,
            ifname: ifname.to_string(),
            session_id,
            xdp_link,
            tc_link,
        })
    }

    pub fn detach(&mut self) {
        debug!(
            ifname = %self.ifname,
            ifindex = self.ifindex,
            "Detaching eBPF session and clearing BPF map"
        );
        if let Some(map_obj) = self.bpf.map_mut("pppoe_sessions")
            && let Ok(mut map) = HashMap::<_, u32, PppoeSessionMapValue>::try_from(map_obj)
        {
            let _ = map.remove(&self.ifindex);
            let _ = map.remove(&0u32);
        }

        if let Some(link_id) = self.xdp_link.take()
            && let Some(prog) = self.bpf.program_mut("pppoe_ingress_decap")
            && let Ok(xdp) = <&mut Xdp>::try_from(prog)
        {
            let _ = xdp.detach(link_id);
        }

        if let Some(link_id) = self.tc_link.take()
            && let Some(prog) = self.bpf.program_mut("pppoe_egress_encap")
            && let Ok(tc) = <&mut SchedClassifier>::try_from(prog)
        {
            let _ = tc.detach(link_id);
        }

        // Restore standard hardware TSO/GSO/TX offloads via native kernel ioctl
        crate::kernel::sysctl::restore_interface_offloads(&self.ifname);
    }
}

impl Drop for EbpfSession {
    fn drop(&mut self) {
        self.detach();
    }
}
