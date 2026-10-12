# Service Specification: Auxiliary Services (`tftp`, `wol`, `discovery`)

## 1. Overview & System Role

Lanforge incorporates several specialized auxiliary services under `crates/net/` to provide full-fledged homelab and network management capabilities:

- **`lanforge-tftp`**: Trivial File Transfer Protocol server for PXE network booting.
- **`lanforge-wol`**: Wake-on-LAN (WOL) Magic Packet generator and target management.
- **`lanforge-discovery`**: Passive and active network host discovery (mDNS, ARP, NDP scan, Netlink interface address and carrier monitoring).

---

## 2. Inbound Reaction & Processing Flow

### A. TFTP Boot Server (`lanforge-tftp`)
- **PXE Integration:** Works alongside `lanforge-dhcp` (which advertises Option 66/67 boot file parameters).
- **File Transfer Processing:** Serves bootloaders (e.g. iPXE, GRUB, netboot.xyz) over UDP port 69, emitting file transfer events to the system log.

### B. Wake-on-LAN Engine (`lanforge-wol`)
- **Magic Packet Transmission:** Sends raw Ethernet / UDP broadcast Magic Packets (6x `0xFF` + 16x MAC address) to wake sleeping devices.
- **API & Event Trigger:** Executed via API calls or automated schedules, publishing `LanforgeEvent` notifications when a wake signal is dispatched.

### C. Network Discovery & Interface Monitor (`lanforge-discovery`)
- **Passive Sniffing & Link State:** Listens for mDNS (`.local` queries), ARP requests, IPv6 NDP messages, and Netlink interface carrier changes to discover un-leased or statically configured devices and monitor interface states.
- **Proactive Inventory Updates:** Dispatches `DeviceUpdate::Discovered` to `LanforgeContext` so non-DHCP devices still appear in Lanforge's device map.
- **Event Bus Alerts:** Broadcasts `LanforgeEvent::Network` on link status changes, allowing dependent services (such as RA, Firewall or DHCP) to adapt in-place.

---

## 3. System Invariants

1. **Integrated Device Visibility:** Devices discovered via passive network sniffing (`lanforge-discovery`) are tracked in the same central inventory as DHCP and PPPoE clients.
2. **Resilient Network Binding:** Link up/down state changes captured by `lanforge-discovery` trigger automatic in-place socket updates across active network daemons.
