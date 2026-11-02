//! Password-guess throttling for the HTTP API (login, elevate, change-password).
//!
//! Every password check is an Argon2 run (tens of MiB, ~100 ms on an SBC). Unthrottled, any LAN
//! device could brute-force the admin password or pin the CPU with parallel logins. Two layers:
//! - failures are counted per client address; past [`SOURCE_FREE`] the address is locked out
//!   with a doubling delay. A second, looser count over all clients catches address rotation
//!   (an IPv6 host can pick any address in its /64). A lockout only ever closes the HTTP
//!   password paths: the CLI over the Unix socket is never throttled;
//! - one Argon2 verification runs at a time, on the blocking pool, so guesses cannot starve
//!   the async workers that serve DNS/DHCP/HTTP.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::ready;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use lanforge_crypto::verify_password;
use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::error::{HttpError, Result as HttpResult};

/// Failures one client gets before it is locked out.
const SOURCE_FREE: u32 = 5;
/// Failures all clients together get before every password check is locked out.
const GLOBAL_FREE: u32 = 20;
/// First lockout; each further failure doubles it.
const FIRST_LOCKOUT: Duration = Duration::from_secs(30);
const SOURCE_MAX_LOCKOUT: Duration = Duration::from_mins(15);
const GLOBAL_MAX_LOCKOUT: Duration = Duration::from_mins(5);
/// Quiet time after which a client's (or the global) failures are forgotten.
const SOURCE_FORGET: Duration = Duration::from_hours(1);
const GLOBAL_FORGET: Duration = Duration::from_mins(10);
/// Clients tracked at once; the one quiet for longest is dropped first.
const MAX_SOURCES: usize = 256;

/// The client address of a request (`None` when the server runs without connect info, as in
/// router-level tests: those clients share one entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        ready(Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_canonical()),
        )))
    }
}

/// Failure count of one client (or of all of them).
#[derive(Debug, Clone, Copy)]
struct Strikes {
    failures: u32,
    last_failure: Instant,
    locked_until: Instant,
}

impl Strikes {
    /// Seconds left of a lockout at `now`, if any.
    fn locked(&self, now: Instant) -> Option<u64> {
        (self.locked_until > now).then(|| (self.locked_until - now).as_secs().max(1))
    }

    /// Records a failure at `now`: forgets old ones, and locks out past `free`.
    fn fail(&mut self, now: Instant, free: u32, forget: Duration, max: Duration) {
        if now.duration_since(self.last_failure) > forget {
            self.failures = 0;
        }
        self.failures += 1;
        self.last_failure = now;
        if let Some(over) = self.failures.checked_sub(free + 1) {
            let lockout = FIRST_LOCKOUT
                .checked_mul(1 << over.min(16))
                .map_or(max, |d| d.min(max));
            self.locked_until = now + lockout;
        }
    }

    const fn new(now: Instant) -> Self {
        Self {
            failures: 0,
            last_failure: now,
            locked_until: now,
        }
    }
}

#[derive(Debug)]
struct Ledger {
    sources: HashMap<ClientIp, Strikes>,
    global: Strikes,
}

/// Throttles password checks; shared by every clone of the `AuthManager`.
#[derive(Debug)]
pub struct LoginThrottle {
    ledger: Mutex<Ledger>,
    argon: Semaphore,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self {
            ledger: Mutex::new(Ledger {
                sources: HashMap::new(),
                global: Strikes::new(Instant::now()),
            }),
            argon: Semaphore::new(1),
        }
    }
}

impl LoginThrottle {
    /// Refuses (429) a password attempt from `client` while it, or everyone, is locked out.
    pub fn admit(&self, client: ClientIp) -> HttpResult<()> {
        let now = Instant::now();
        let locked = {
            let ledger = self.ledger.lock();
            ledger
                .sources
                .get(&client)
                .and_then(|s| s.locked(now))
                .max(ledger.global.locked(now))
        };
        locked.map_or(Ok(()), |secs| Err(HttpError::TooManyRequests(secs)))
    }

    /// Records the outcome of an admitted attempt: a success clears the client's failures.
    pub fn record(&self, client: ClientIp, ok: bool) {
        let now = Instant::now();
        let mut ledger = self.ledger.lock();
        if ok {
            ledger.sources.remove(&client);
            return;
        }
        ledger
            .global
            .fail(now, GLOBAL_FREE, GLOBAL_FORGET, GLOBAL_MAX_LOCKOUT);
        if ledger.sources.len() >= MAX_SOURCES && !ledger.sources.contains_key(&client) {
            let oldest = ledger
                .sources
                .iter()
                .min_by_key(|(_, s)| s.last_failure)
                .map(|(k, _)| *k);
            if let Some(oldest) = oldest {
                ledger.sources.remove(&oldest);
            }
        }
        ledger
            .sources
            .entry(client)
            .or_insert_with(|| Strikes::new(now))
            .fail(now, SOURCE_FREE, SOURCE_FORGET, SOURCE_MAX_LOCKOUT);
    }

    /// Verifies `password` against an Argon2 `hash`, one at a time, off the async workers.
    pub async fn verify(&self, hash: &str, password: &str) -> bool {
        let Ok(_permit) = self.argon.acquire().await else {
            return false;
        };
        let (hash, password) = (hash.to_owned(), password.to_owned());
        tokio::task::spawn_blocking(move || verify_password(&hash, &password))
            .await
            .unwrap_or(false)
    }

    /// Runs a password-checking `attempt` for `client`: refused while locked out, and its
    /// failure (401/403) counts toward the lockout.
    pub async fn guard<T>(
        &self,
        client: ClientIp,
        attempt: impl Future<Output = HttpResult<T>>,
    ) -> HttpResult<T> {
        self.admit(client)?;
        let result = attempt.await;
        match &result {
            Ok(_) => self.record(client, true),
            Err(HttpError::Auth(_) | HttpError::Forbidden(_)) => self.record(client, false),
            Err(_) => {}
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn ip(last: u8) -> ClientIp {
        ClientIp(Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last))))
    }

    #[test]
    fn a_client_is_locked_out_after_its_free_failures_and_others_are_not() {
        let t = LoginThrottle::default();
        for _ in 0..SOURCE_FREE {
            assert!(t.admit(ip(1)).is_ok());
            t.record(ip(1), false);
        }
        assert!(t.admit(ip(1)).is_ok(), "the free failures are free");
        t.record(ip(1), false);
        assert!(matches!(t.admit(ip(1)), Err(HttpError::TooManyRequests(s)) if s >= 29));
        assert!(t.admit(ip(2)).is_ok());
    }

    #[test]
    fn a_success_clears_the_client() {
        let t = LoginThrottle::default();
        for _ in 0..SOURCE_FREE {
            t.record(ip(1), false);
        }
        t.record(ip(1), true);
        for _ in 0..SOURCE_FREE {
            t.record(ip(1), false);
        }
        assert!(t.admit(ip(1)).is_ok());
    }

    #[test]
    fn rotating_addresses_hits_the_global_lockout() {
        let t = LoginThrottle::default();
        for n in 0..=GLOBAL_FREE {
            t.record(ip(u8::try_from(n).unwrap()), false);
        }
        assert!(matches!(t.admit(ip(200)), Err(HttpError::TooManyRequests(_))));
    }

    #[test]
    fn the_lockout_doubles_and_is_capped() {
        let now = Instant::now();
        let mut s = Strikes::new(now);
        for _ in 0..=SOURCE_FREE {
            s.fail(now, SOURCE_FREE, SOURCE_FORGET, SOURCE_MAX_LOCKOUT);
        }
        assert_eq!(s.locked_until - now, FIRST_LOCKOUT);
        s.fail(now, SOURCE_FREE, SOURCE_FORGET, SOURCE_MAX_LOCKOUT);
        assert_eq!(s.locked_until - now, FIRST_LOCKOUT * 2);
        for _ in 0..40 {
            s.fail(now, SOURCE_FREE, SOURCE_FORGET, SOURCE_MAX_LOCKOUT);
        }
        assert_eq!(s.locked_until - now, SOURCE_MAX_LOCKOUT);
    }

    #[test]
    fn the_ledger_stays_bounded() {
        let t = LoginThrottle::default();
        for n in 0..MAX_SOURCES + 50 {
            let addr = IpAddr::V6(std::net::Ipv6Addr::from(u128::try_from(n).unwrap()));
            t.record(ClientIp(Some(addr)), false);
        }
        assert!(t.ledger.lock().sources.len() <= MAX_SOURCES);
    }
}
