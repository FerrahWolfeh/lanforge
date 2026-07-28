# Sub-System Specification: DNS AdBlocker & Domain Filtering Engine (`04-02`)

## 1. Overview & Architecture

`lanforge-dns` features an embedded, memory-optimized, zero-copy domain filtering engine (`crates/net/lanforge-dns/src/resolver/filter/`). It intercepts ad-serving, tracking, and malware domains at sub-microsecond latency prior to recursive upstream lookups.

```
       Incoming Query Domain (e.g. "ad.analytics.doubleclick.net")
                                  |
                                  v
                      +------------------------+
                      |  Allowlist Check       | ---> If matched, ALLOW immediately
                      +------------------------+
                                  | (Not explicitly allowed)
                                  v
         +--------------------------------------------------+
         | 3-Tier DiskBlocklist Lookup Hierarchy            |
         |                                                  |
         |  1. LRU Cache (Fastest Hit/Miss Cache)          |
         |         | (Miss)                                 |
         |         v                                        |
         |  2. Bloom Filter (0.5% FP Rate Negative Check)  |
         |         | (Might be present)                     |
         |         v                                        |
         |  3. Mmap FST (Finite State Transducer on Disk)   |
         +--------------------------------------------------+
                       /                      \
                      /                        \
           (If Matched)                       (If Clean)
                |                                  |
                v                                  v
     Sinkhole Policy Engine               Pass to Next Middleware
   (NXDOMAIN / 0.0.0.0 / Sinkhole IP)
```

---

## 2. The 3-Tier `DiskBlocklist` Data Structure (`blocklist.rs`)

To scale to **millions of blocked domains** with minimal RAM overhead and sub-microsecond query latencies, `DiskBlocklist` combines three complementary data structures:

### Tier 1: Thread-Safe LRU Cache (`LruCache<Box<str>, bool>`)
- Stores recent query evaluation results (`domain -> is_blocked`).
- Shielded by `parking_lot::Mutex`.
- Provides instant $O(1)$ lookups for hot domains continuously requested by LAN clients.

### Tier 2: Probabilistic Bloom Filter (`Bloom<str>`)
- Formatted with a tight **0.5% false positive rate**.
- Used for fast **negative lookups**: if the Bloom filter reports `false`, the domain is **guaranteed not to be in the blocklist**, immediately short-circuiting expensive lookups without touching disk or memory-mapped files.

### Tier 3: Memory-Mapped Finite State Transducer (`Set<Mmap>`)
- The primary blocklist dictionary is compiled into a **Finite State Transducer (FST)** binary representation on disk and memory-mapped (`memmap2::Mmap`).
- **Zero-Copy Memory Footprint:** The OS kernel page cache handles paging of the FST file. Millions of domain entries occupy negligible heap RAM while providing deterministic $O(m)$ prefix string matching.

---

## 3. Self-Update & Atomic Reload Mechanics

```
        External Blocklist URLs (Hosts / AdBlock List Syntax)
                                  |
                                  v
                 +----------------------------------+
                 | Background Compilation Worker    |
                 | - Downloads list updates         |
                 | - Deduplicates & sorts domains   |
                 | - Builds FST & Bloom Filter      |
                 | - Flushes to `.fst.tmp` file     |
                 +----------------------------------+
                                  |
                                  v
                 Atomic Pointer Swap (`ArcSwap`)
       (Swaps active `DiskBlocklist` handle without query downtime)
```

### Compilation Workflow
1. **Background Fetching:** Worker task periodically downloads configured remote blocklists (e.g. StevenBlack, EasyList).
2. **Deduplication & Sorting:** In-memory domains are deduplicated into a sorted array (`Vec<String>`).
3. **FST File Creation:** Uses `fst::SetBuilder` to construct an FST stream written to a temporary file (`.fst.tmp`).
4. **Atomic Pointer Swap:** The active `AdBlocker` struct updates its `blocklist: RwLock<Option<Arc<DiskBlocklist>>>` reference. Query-processing threads seamlessly switch to the new blocklist on their next read lock without dropping packets or stalling DNS resolution.

---

## 4. Sinkhole Action Policies (`AdblockRuntimeConfig`)

When a query matches a blocklist rule and is not superseded by the allowlist, `AdBlocker` returns a response according to its configured `BlockingMode`:
- **`NXDOMAIN`:** Responds that the domain does not exist.
- **`NullIp` / `ZeroIp`:** Responds with `0.0.0.0` (IPv4) or `::` (IPv6).
- **`Refused`:** Responds with `REFUSED` (RCODE 5).
- **`CustomIp`:** Responds with a designated LAN sinkhole IPv4/IPv6 address serving a block page.

---

## 5. System Invariants

1. **Zero Downtime During Updates:** Blocklist downloads and FST compilation happen out-of-band on background threads; active DNS resolution never stalls during list updates.
2. **Deterministic Memory Bounds:** Using memory-mapped FST files guarantees that blocklists containing over 50+ million domains consume minimal resident set memory (RSS).
3. **Allowlist Precedence:** Explicit allowlists (`allowlist.rs`) take precedence over all blocklist matches and regex rules.
