use lanforge_types::network::dns::{DnsRecordType, QueryLogEntry, QueryResult};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

/// How long a burst of identical queries is folded before its line is written.
pub const REPEAT_WINDOW_SECS: u64 = 60;

/// Groups tracked at once: past it, a new key is logged line by line (nothing is dropped).
const MAX_REPEAT_GROUPS: usize = 512;

/// A fixed-size, thread-safe ring buffer for DNS query logs.
///
/// It also folds repeats: the first query of a (client, name, type, outcome) is logged at once,
/// the identical ones that follow within [`REPEAT_WINDOW_SECS`] become a single line carrying
/// their count (`repeats`), written when the window closes. A client hammering one name (an IP
/// camera asking for `:0` forever) yields one line per window, and every query is still counted.
pub struct QueryRing {
    capacity: usize,
    entries: Mutex<VecDeque<QueryLogEntry>>,
    groups: Mutex<HashMap<RepeatKey, RepeatGroup>>,
}

#[derive(PartialEq, Eq, Hash)]
struct RepeatKey {
    src_ip: IpAddr,
    domain: Arc<str>,
    qtype: DnsRecordType,
    result: QueryResult,
}

impl RepeatKey {
    fn of(entry: &QueryLogEntry) -> Self {
        Self {
            src_ip: entry.src_ip,
            domain: Arc::clone(&entry.domain),
            qtype: entry.qtype,
            result: entry.result,
        }
    }
}

struct RepeatGroup {
    window_end: u64,
    /// The latest folded query; its `repeats` is the count folded in this window.
    folded: Option<QueryLogEntry>,
}

impl QueryRing {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            groups: Mutex::new(HashMap::new()),
        }
    }

    /// Decides whether `entry` is logged now (`Some`) or folded into an open group (`None`).
    #[must_use]
    pub fn admit(&self, mut entry: QueryLogEntry) -> Option<QueryLogEntry> {
        entry.repeats = 1;
        // Coalesced batches are shown per `coalesce_id` (leader + followers): folding them would
        // merge distinct batches under one id.
        if entry.coalesce_id.is_some() {
            return Some(entry);
        }
        let key = RepeatKey::of(&entry);
        let mut groups = self.groups.lock();
        if let Some(group) = groups.get_mut(&key) {
            let count = group.folded.as_ref().map_or(0, |e| e.repeats);
            entry.repeats = count.saturating_add(1);
            group.folded = Some(entry);
            return None;
        }
        if groups.len() < MAX_REPEAT_GROUPS {
            groups.insert(
                key,
                RepeatGroup {
                    window_end: entry.timestamp.saturating_add(REPEAT_WINDOW_SECS),
                    folded: None,
                },
            );
        }
        Some(entry)
    }

    /// Closes the windows ended by `now`: returns one line per group that folded queries (the
    /// group stays open for the next window), forgets the groups that went quiet.
    #[must_use]
    pub fn flush_repeats(&self, now: u64) -> Vec<QueryLogEntry> {
        let mut out = Vec::new();
        self.groups.lock().retain(|_, group| {
            if group.window_end > now {
                return true;
            }
            match group.folded.take() {
                Some(line) => {
                    out.push(line);
                    group.window_end = now.saturating_add(REPEAT_WINDOW_SECS);
                    true
                }
                None => false,
            }
        });
        out
    }

    /// Every folded line still open, for a stop: no count is lost.
    #[must_use]
    pub fn drain_repeats(&self) -> Vec<QueryLogEntry> {
        self.groups
            .lock()
            .drain()
            .filter_map(|(_, group)| group.folded)
            .collect()
    }

    pub fn push(&self, entry: QueryLogEntry) {
        let mut entries = self.entries.lock();
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn get_recent(&self, limit: usize) -> Vec<QueryLogEntry> {
        let entries = self.entries.lock();
        entries.iter().rev().take(limit).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_types::network::dns::TransportProtocol;

    fn query(ts: u64, domain: &str, result: QueryResult) -> QueryLogEntry {
        QueryLogEntry {
            timestamp: ts,
            src_ip: "192.168.1.60".parse().unwrap(),
            domain: Arc::from(domain),
            upstream_us: 0,
            qtype: DnsRecordType::A,
            result,
            cached: false,
            src_mac: None,
            answer: None,
            protocol: TransportProtocol::Udp,
            filter: None,
            coalesce_id: None,
            repeats: 0,
            upstream: None,
        }
    }

    #[test]
    fn a_burst_is_one_line_now_and_one_counted_line_per_window() {
        let ring = QueryRing::new(16);
        // The camera asks every 2 s.
        let first = ring.admit(query(1000, ":0", QueryResult::Local));
        assert_eq!(first.map(|e| e.repeats), Some(1));
        for t in (1002..1060).step_by(2) {
            assert!(ring.admit(query(t, ":0", QueryResult::Local)).is_none());
        }
        assert!(ring.flush_repeats(1059).is_empty(), "window still open");

        let lines = ring.flush_repeats(1060);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].repeats, 29);
        assert_eq!(
            lines[0].timestamp, 1058,
            "the line carries the latest query"
        );

        // Still hammering: the next window folds again instead of logging a fresh first line.
        assert!(ring.admit(query(1062, ":0", QueryResult::Local)).is_none());
        assert_eq!(ring.flush_repeats(1120)[0].repeats, 1);

        // Quiet for a whole window: the group is forgotten, the next query logs at once.
        assert!(ring.flush_repeats(1180).is_empty());
        assert_eq!(
            ring.admit(query(1181, ":0", QueryResult::Local))
                .map(|e| e.repeats),
            Some(1)
        );
    }

    #[test]
    fn another_outcome_or_name_is_its_own_line() {
        let ring = QueryRing::new(16);
        assert!(
            ring.admit(query(1, "a.example", QueryResult::Forwarded))
                .is_some()
        );
        assert!(
            ring.admit(query(2, "a.example", QueryResult::Cached))
                .is_some()
        );
        assert!(
            ring.admit(query(3, "b.example", QueryResult::Forwarded))
                .is_some()
        );
        assert!(
            ring.admit(query(4, "a.example", QueryResult::Cached))
                .is_none()
        );
    }

    #[test]
    fn coalesced_batch_lines_are_never_folded() {
        let ring = QueryRing::new(16);
        let batch = |ts, id| QueryLogEntry {
            coalesce_id: Some(id),
            ..query(ts, "a.example", QueryResult::Coalesced)
        };
        assert!(ring.admit(batch(1, 7)).is_some());
        assert!(ring.admit(batch(1, 7)).is_some());
        assert!(ring.admit(batch(2, 8)).is_some());
        assert!(ring.drain_repeats().is_empty());
    }

    #[test]
    fn a_stop_hands_back_every_folded_count() {
        let ring = QueryRing::new(16);
        let _ = ring.admit(query(1, ":0", QueryResult::Local));
        let _ = ring.admit(query(2, ":0", QueryResult::Local));
        let _ = ring.admit(query(3, ":0", QueryResult::Local));
        let _ = ring.admit(query(4, "quiet.example", QueryResult::Forwarded));
        let lines = ring.drain_repeats();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].repeats, 2);
    }
}
