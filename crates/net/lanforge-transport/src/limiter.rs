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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_use_sensible_default_configuration() {
        let default_cfg = RateLimitConfig::default();
        assert_eq!(default_cfg.pps, 500);
        assert_eq!(default_cfg.burst, 100);
        assert_eq!(default_cfg.max_sources, 64);
    }

    #[test]
    fn should_permit_burst_and_drop_when_depleted() {
        let config = RateLimitConfig {
            pps: 10,
            burst: 3,
            max_sources: 10,
        };
        let limiter = RateLimiter::new(config);
        let key = "192.168.1.50";

        assert!(limiter.check(&key), "1st packet within burst must pass");
        assert!(limiter.check(&key), "2nd packet within burst must pass");
        assert!(limiter.check(&key), "3rd packet within burst must pass");
        assert!(!limiter.check(&key), "4th packet must be dropped when burst is depleted");
    }

    #[test]
    fn should_isolate_limits_per_distinct_key() {
        let config = RateLimitConfig {
            pps: 1,
            burst: 1,
            max_sources: 10,
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check(&"client-a"));
        assert!(!limiter.check(&"client-a"));

        // client-b has independent bucket
        assert!(limiter.check(&"client-b"));
        assert!(!limiter.check(&"client-b"));
    }

    #[test]
    fn should_evict_oldest_source_when_capacity_reached() {
        let config = RateLimitConfig {
            pps: 0,
            burst: 1,
            max_sources: 2,
        };
        let limiter = RateLimiter::new(config);

        // Add k1 and k2, consuming their only burst token
        assert!(limiter.check(&"k1"));
        assert!(!limiter.check(&"k1"));

        assert!(limiter.check(&"k2"));
        assert!(!limiter.check(&"k2"));

        // Inserting k3 must evict the oldest key (k1)
        assert!(limiter.check(&"k3"));

        // Since k1 was evicted from the LRU cache, accessing it anew gives it a fresh bucket
        assert!(limiter.check(&"k1"), "Evicted key should receive a fresh token bucket upon re-entry");
    }

    #[test]
    fn should_refresh_lru_order_on_access_to_prevent_eviction() {
        let config = RateLimitConfig {
            pps: 0,
            burst: 2,
            max_sources: 2,
        };
        let limiter = RateLimiter::new(config);

        // Add k1 and k2 -> LRU queue is [k1, k2]
        assert!(limiter.check(&"k1"));
        assert!(limiter.check(&"k2"));

        // Access k1 again -> k1 becomes MRU, LRU queue is now [k2, k1]
        assert!(limiter.check(&"k1"));

        // Insert k3 -> must evict k2 (now the oldest), NOT k1
        assert!(limiter.check(&"k3"));

        // k1 was retained in cache and has depleted its burst (2 used out of 2)
        assert!(!limiter.check(&"k1"), "k1 was refreshed and should still be tracked with depleted burst");

        // k2 was evicted; re-adding it allocates a fresh bucket
        assert!(limiter.check(&"k2"), "k2 was evicted and should get a fresh bucket");
    }

    #[test]
    fn should_replenish_bucket_tokens_with_elapsed_time() {
        let mut bucket = Bucket {
            tokens: 0.0,
            last_update: Instant::now() - Duration::from_millis(100),
        };

        // At 100 pps, 100ms should replenish ~10 tokens
        let allowed = bucket.try_consume(100, 10);
        assert!(allowed);
        assert!(bucket.tokens >= 8.0 && bucket.tokens <= 10.0);
    }
}
