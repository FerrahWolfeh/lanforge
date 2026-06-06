use lanforge_types::network::dns::QueryLogEntry;
use parking_lot::Mutex;
use std::collections::VecDeque;

/// A fixed-size, thread-safe ring buffer for DNS query logs.
pub struct QueryRing {
    capacity: usize,
    entries: Mutex<VecDeque<QueryLogEntry>>,
}

impl QueryRing {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
        }
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
