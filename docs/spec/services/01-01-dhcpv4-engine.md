# Sub-System Specification: DHCPv4 Engine (`01-01`)

## 1. Overview & Packet Loop

The DHCPv4 server module (`crates/net/lanforge-dhcp/src/v4/`) handles IPv4 dynamic host configuration over raw UDP sockets (port 67/68).

```
   Client Packet (DHCPDISCOVER / DHCPREQUEST)
                      |
                      v
        +----------------------------+
        | Raw UDP Socket / io.rs     |
        +----------------------------+
                      |
                      v
        +----------------------------+
        | Server Engine (server.rs)  |
        | - Option Parsing           |
        | - Identity Extraction      |
        +----------------------------+
         /                          \
        /                            \
   (Discovered Update)          (Address Pool Check)
        |                            |
        v                            v
LanforgeContext State          Pool Allocation (pool.rs)
                                     |
                                     v
                        DHCP OFFER / ACK Packet Sent
                                     |
                                     v
                       LanforgeEvent::Dhcp Broadcast
```

---

## 2. Inbound Reaction & Processing Flow

### A. Option Extraction & Identity Identification (`options.rs`, `identity.rs`)
- Extracts client MAC address (`MacAddr`), Option 12 (Hostname), Option 60 (Vendor Class Identifier), Option 61 (Client Identifier), and Option 55 (Parameter Request List).
- Instantly updates global memory state with `DeviceUpdate::Discovered` and `DeviceUpdate::HostnameChanged`.

### B. Address Pool Allocation (`pool.rs`)
- Checks static MAC-to-IP reservation tables.
- If dynamic, claims an available IP from the subnet range.
- Sets lease duration parameters (T1 renewal, T2 rebinding, lease expiration).

### C. Packet Response & Event Emission
- Constructs raw IPv4 `DHCPOFFER` or `DHCPACK` packets with requested options (Gateway Option 3, DNS Option 6, Subnet Mask Option 1, Domain Name Option 15).
- Broadcasts `LanforgeEvent::Dhcp(DhcpEvent::LeaseGranted)` to trigger dynamic DNS updates and database persistence.

---

## 3. System Invariants

1. **Integrated Device Inventory:** Every discovered DHCPv4 client immediately populates Lanforge's device inventory, even prior to lease confirmation.
2. **Subnet Conflict Guard:** Address pools check active network state to prevent IP conflicts before issuing lease offers.
