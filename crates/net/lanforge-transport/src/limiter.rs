use parking_lot::Mutex;
use std::collections::VecDeque;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Configuration for token-bucket rate limiting.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Permitted packets per second.
    pub pps: u32,
    /// Maximum allowed burst size.
    pub burst: u32,
    /// Maximum number of distinct sources to track in memory (prevents memory inflation).
    pub max_sources: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            pps: 500,
            burst: 100,
            max_sources: 64,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_update: Instant,
}

impl Bucket {
    fn new(burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, pps: u32, burst: u32) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Replenish tokens
        self.tokens = (self.tokens + elapsed * f64::from(pps)).min(f64::from(burst));

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Bounded LRU-style token-bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter<K> {
    config: RateLimitConfig,
    // (Key, Bucket) pairs in LRU order
    state: Mutex<VecDeque<(K, Bucket)>>,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Mutex::new(VecDeque::with_capacity(config.max_sources.min(128))),
        }
    }

    /// Checks if a packet from `key` is allowed to proceed.
    ///
    /// Returns `true` if allowed, or `false` if the rate limit is exceeded (drop).
    pub fn check(&self, key: &K) -> bool {
        let mut state = self.state.lock();

        // Find existing bucket
        if let Some(pos) = state.iter().position(|(k, _)| k == key) {
            let (_, ref mut bucket) = state[pos];
            let allowed = bucket.try_consume(self.config.pps, self.config.burst);
            // Move to back (most recently used)
            if pos + 1 < state.len()
                && let Some(entry) = state.remove(pos) {
                state.push_back(entry);
            }
            return allowed;
        }

        // New bucket: evict oldest if at capacity
        if state.len() >= self.config.max_sources {
            // Evict if older than 5s, or just pop front
            let now = Instant::now();
            if let Some((_, b)) = state.front()
                && (now.duration_since(b.last_update) > Duration::from_secs(5) || state.len() >= self.config.max_sources) {
                state.pop_front();
            }
        }

        let mut bucket = Bucket::new(self.config.burst);
        let allowed = bucket.try_consume(self.config.pps, self.config.burst);
        state.push_back((key.clone(), bucket));
        allowed
    }
}
