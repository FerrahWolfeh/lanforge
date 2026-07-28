# Sub-System Specification: TFTP Boot Server (`05-01`)

## 1. Overview & PXE Boot Mechanics

`lanforge-tftp` (`crates/net/lanforge-tftp/`) provides a lightweight, asynchronous Trivial File Transfer Protocol (TFTP) server over UDP port 69. It serves network boot files (e.g. `ipxe.efi`, `pxelinux.0`, kernel images) for PXE network booting.

```
 Client PXE Request (UDP 69 Read Request - RRQ)
                        |
                        v
          +---------------------------+
          | lanforge-tftp Server      |
          | - Validates Requested File|
          +---------------------------+
                        |
                        v
          +---------------------------+
          | Block-by-Block Transfer   |
          | - UDP Data Packets (512B) |
          | - Awaits ACK per Block    |
          +---------------------------+
                        |
                        v
          Transfer Complete Notification
```

---

## 2. Inbound Reaction & Processing Flow

### A. Read Request (RRQ) Reaction
- Listens on UDP port 69 for `RRQ` (Read Request) packets.
- Checks configured TFTP root directory to locate the requested boot file.
- Spawns a dedicated UDP session worker on an ephemeral port to handle block transmission.

### B. Option Negotiation (OACK) & Block Transfer
- **RFC 2347 Option Negotiation:** Negotiates block size (`blksize`), transfer size (`tsize`), and timeout parameters if requested by PXE clients (e.g. iPXE).
- **Block Acknowledgment Loop:** Sends 512-byte (or negotiated blksize) data blocks and awaits `ACK` for each block before transmitting the next block.

---

## 3. System Invariants

1. **Integrated PXE Workflow:** Operates seamlessly alongside `lanforge-dhcp` (which advertises Option 66 TFTP Server IP and Option 67 Bootfile Name).
2. **Asynchronous Session Isolation:** Every active TFTP file transfer runs in an isolated asynchronous task on an ephemeral socket, preventing slow client downloads from blocking new incoming PXE boot requests.
