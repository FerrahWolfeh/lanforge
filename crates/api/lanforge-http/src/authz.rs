//! Authorization: which permission a route needs, and which roles and token scopes grant it.
//!
//! One table for the whole API so the policy can be audited in one place. Unlisted writes
//! need [`Permission::Admin`]: a new route is admin-only until it is classified here.

use axum::http::Method;
use lanforge_types::auth::{ApiScope, UserRole};

use crate::auth::{AuthMethod, AuthenticatedUser};

/// What a request needs, from least to most privileged area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Any authenticated caller: own profile, own password, logout, elevation.
    Authenticated,
    /// Reads that hold no secrets.
    Read,
    /// Resolving names through the router (`/dns/query`).
    DnsQuery,
    /// Day-to-day device operations: wake-on-LAN, purge, leases, static hosts.
    DeviceWrite,
    /// Day-to-day DNS operations: allow/block, rules, rewrites, cache.
    DnsWrite,
    /// DNS upstream servers and reverse resolvers.
    UpstreamWrite,
    /// Service configuration, including reads of config that holds secrets (the `PPPoE` password).
    ConfigWrite,
    /// Users, tokens, database, daemon lifecycle.
    Admin,
}

/// A route's requirement: the permission, and whether a password session must re-authenticate
/// (an elevation token) — actions that take an account over or create lasting access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    pub permission: Permission,
    pub sensitive: bool,
}

impl Requirement {
    const fn plain(permission: Permission) -> Self {
        Self {
            permission,
            sensitive: false,
        }
    }

    const fn sensitive() -> Self {
        Self {
            permission: Permission::Admin,
            sensitive: true,
        }
    }
}

/// Strips the mount prefixes: `/api`, `/v1`, and `/system` (whose routes are also merged
/// at the root), leaving one canonical path per route.
fn canonical(path: &str) -> &str {
    let p = path.strip_prefix("/api").unwrap_or(path);
    let p = p.strip_prefix("/v1").unwrap_or(p);
    match p.strip_prefix("/system") {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
        _ => p,
    }
    .trim_end_matches('/')
}

/// The requirement of a request. `path` may carry the `/api` or `/api/v1` prefix or not.
/// The arms are ordered from specific to general, so some share a body on purpose.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn requirement(method: &Method, path: &str) -> Requirement {
    use Permission::{Admin, Authenticated, ConfigWrite, DeviceWrite, DnsQuery, DnsWrite, Read};

    let read = matches!(*method, Method::GET | Method::HEAD);
    let p = canonical(path);
    let seg: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();

    let permission = match (read, seg.as_slice()) {
        (
            _,
            [
                "auth",
                "me" | "change-password" | "elevate" | "logout" | "status" | "validate" | "login",
            ],
        ) => Authenticated,

        // Creating or renewing a token is lasting access; deleting one is not.
        (false, ["auth", "tokens"] | ["auth", "tokens", _, "renew"]) => {
            return Requirement::sensitive();
        }
        (_, ["auth", "tokens", ..]) => Admin,

        // Any user change can take an account over.
        (false, ["users", ..]) => return Requirement::sensitive(),
        (true, ["users", ..]) => Admin,

        (true, ["db", "stats"]) => Read,
        (false, ["db"]) => return Requirement::sensitive(),
        (_, ["db", ..]) => Admin,

        // Daemon lifecycle and internals.
        (_, ["reload" | "shutdown" | "context"] | ["service", ..]) => Admin,
        // Exported config holds secrets.
        (_, ["config", ..]) => ConfigWrite,

        // Holds the PPPoE password in clear.
        (true, ["pppoe", "config"]) => ConfigWrite,

        (true, ["dns", "query"]) => DnsQuery,

        (true, _) => Read,

        (false, ["devices" | "hosts", ..]) => DeviceWrite,
        (false, ["dhcp", "leases", ..] | ["dhcp", "reconcile"]) => DeviceWrite,

        (false, ["dns", "upstreams" | "reverse-resolvers", ..]) => Permission::UpstreamWrite,
        (false, ["dns", "adblock", "config" | "sources", ..]) => ConfigWrite,
        (false, ["dns", "adblock" | "cache" | "rewrites", ..]) => DnsWrite,

        (
            false,
            ["firewall" | "pppoe" | "ra" | "traffic", ..] | ["dhcp", "pools" | "options", ..],
        ) => ConfigWrite,

        (false, _) => Admin,
    };
    Requirement::plain(permission)
}

const fn role_grants(role: UserRole, permission: Permission) -> bool {
    use Permission::{Authenticated, DeviceWrite, DnsQuery, DnsWrite, Read};
    match role {
        UserRole::Admin => true,
        UserRole::Operator => matches!(
            permission,
            Authenticated | Read | DnsQuery | DeviceWrite | DnsWrite
        ),
        UserRole::Viewer => matches!(permission, Authenticated | Read | DnsQuery),
    }
}

const fn scope_grants(scope: ApiScope, permission: Permission) -> bool {
    use Permission::{Authenticated, ConfigWrite, DeviceWrite, DnsQuery, DnsWrite, Read};
    matches!(
        (scope, permission),
        (ApiScope::Admin, _)
            | (_, Authenticated)
            | (ApiScope::Monitoring, Read)
            | (ApiScope::DnsQuery, DnsQuery)
            | (ApiScope::DeviceWrite, DeviceWrite)
            | (
                ApiScope::UpstreamWrite | ApiScope::ConfigWrite,
                Permission::UpstreamWrite
            )
            | (ApiScope::ConfigWrite, ConfigWrite | DnsWrite)
    )
}

/// Whether `user` holds `permission`. A JWT user is judged by role; an API token only by
/// its scopes (its name is not a user).
#[must_use]
pub fn grants(user: &AuthenticatedUser, permission: Permission) -> bool {
    match user.method {
        AuthMethod::Jwt => user
            .role
            .parse::<UserRole>()
            .is_ok_and(|role| role_grants(role, permission)),
        AuthMethod::ApiToken => user.scopes.iter().any(|&s| scope_grants(s, permission)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_types::auth::ApiScopes;

    fn session(role: &str) -> AuthenticatedUser {
        AuthenticatedUser {
            name: "alice".into(),
            role: role.into(),
            method: AuthMethod::Jwt,
            scopes: ApiScopes::new(),
        }
    }

    fn token(scopes: &[ApiScope]) -> AuthenticatedUser {
        AuthenticatedUser {
            name: "admin".into(),
            role: String::new(),
            method: AuthMethod::ApiToken,
            scopes: ApiScopes::from_slice(scopes),
        }
    }

    fn allowed(user: &AuthenticatedUser, method: &Method, path: &str) -> bool {
        grants(user, requirement(method, path).permission)
    }

    #[test]
    fn prefixes_resolve_to_the_same_route() {
        for path in [
            "/api/v1/system/shutdown",
            "/api/v1/shutdown",
            "/v1/system/shutdown",
            "/system/shutdown",
            "/shutdown/",
        ] {
            assert_eq!(
                requirement(&Method::POST, path),
                Requirement::plain(Permission::Admin),
                "{path}"
            );
        }
        // `/systemd` is not the `/system` mount.
        assert_eq!(canonical("/api/v1/systemd"), "/systemd");
    }

    #[test]
    fn unlisted_writes_are_admin_only_and_reads_are_read() {
        let r = requirement(&Method::POST, "/api/v1/brand-new/thing");
        assert_eq!(r.permission, Permission::Admin);
        let r = requirement(&Method::GET, "/api/v1/brand-new/thing");
        assert_eq!(r.permission, Permission::Read);
    }

    #[test]
    fn viewer_reads_but_never_writes() {
        let viewer = session("viewer");
        assert!(allowed(&viewer, &Method::GET, "/api/v1/devices"));
        assert!(allowed(&viewer, &Method::GET, "/api/v1/dns/query"));
        assert!(allowed(
            &viewer,
            &Method::POST,
            "/api/v1/auth/change-password"
        ));
        for (method, path) in [
            (Method::POST, "/api/v1/devices/aa:bb:cc:dd:ee:ff/wol"),
            (Method::POST, "/api/v1/dns/adblock/rules"),
            (Method::POST, "/api/v1/firewall/config"),
            (Method::POST, "/api/v1/users"),
            (Method::PUT, "/api/v1/users/admin/password"),
            (Method::POST, "/api/v1/auth/tokens"),
            (Method::GET, "/api/v1/auth/tokens"),
            (Method::GET, "/api/v1/users"),
            (Method::GET, "/api/v1/pppoe/config"),
            (Method::GET, "/api/v1/system/config/toml"),
            (Method::POST, "/api/v1/system/shutdown"),
        ] {
            assert!(!allowed(&viewer, &method, path), "{method} {path}");
        }
    }

    #[test]
    fn operator_runs_devices_and_dns_but_not_config_or_accounts() {
        let op = session("operator");
        for (method, path) in [
            (Method::POST, "/api/v1/devices/aa:bb:cc:dd:ee:ff/wol"),
            (Method::DELETE, "/api/v1/devices/aa:bb:cc:dd:ee:ff"),
            (
                Method::POST,
                "/api/v1/dhcp/leases/aa:bb:cc:dd:ee:ff/release",
            ),
            (Method::PATCH, "/api/v1/hosts/aa:bb:cc:dd:ee:ff"),
            (Method::DELETE, "/api/v1/dns/adblock/rules"),
            (Method::DELETE, "/api/v1/dns/cache"),
            (Method::POST, "/api/v1/dns/rewrites"),
        ] {
            assert!(allowed(&op, &method, path), "{method} {path}");
        }
        for (method, path) in [
            (Method::POST, "/api/v1/firewall/commit"),
            (Method::POST, "/api/v1/pppoe/reconnect"),
            (Method::POST, "/api/v1/dns/adblock/config"),
            (Method::POST, "/api/v1/dns/upstreams"),
            (Method::POST, "/api/v1/dhcp/pools/config"),
            (Method::GET, "/api/v1/pppoe/config"),
            (Method::POST, "/api/v1/users"),
            (Method::DELETE, "/api/v1/db"),
            (Method::POST, "/api/v1/system/service/dns/control"),
        ] {
            assert!(!allowed(&op, &method, path), "{method} {path}");
        }
    }

    #[test]
    fn unknown_role_grants_nothing() {
        let ghost = session("root");
        assert!(!allowed(&ghost, &Method::GET, "/api/v1/devices"));
    }

    #[test]
    fn token_scopes_are_enforced() {
        let monitoring = token(&[ApiScope::Monitoring]);
        assert!(allowed(&monitoring, &Method::GET, "/api/v1/devices"));
        assert!(!allowed(&monitoring, &Method::GET, "/api/v1/pppoe/config"));
        assert!(!allowed(&monitoring, &Method::GET, "/api/v1/dns/query"));
        assert!(!allowed(
            &monitoring,
            &Method::POST,
            "/api/v1/devices/x/wol"
        ));
        assert!(!allowed(&monitoring, &Method::POST, "/api/v1/auth/tokens"));

        let dns = token(&[ApiScope::DnsQuery]);
        assert!(allowed(&dns, &Method::GET, "/api/v1/dns/query"));
        assert!(!allowed(&dns, &Method::GET, "/api/v1/devices"));

        let upstream = token(&[ApiScope::UpstreamWrite]);
        assert!(allowed(&upstream, &Method::POST, "/api/v1/dns/upstreams"));
        assert!(!allowed(
            &upstream,
            &Method::POST,
            "/api/v1/dns/adblock/rules"
        ));

        let config = token(&[ApiScope::ConfigWrite]);
        assert!(allowed(&config, &Method::POST, "/api/v1/firewall/config"));
        assert!(allowed(&config, &Method::POST, "/api/v1/dns/upstreams"));
        assert!(allowed(&config, &Method::POST, "/api/v1/dns/adblock/rules"));
        assert!(!allowed(&config, &Method::POST, "/api/v1/devices/x/wol"));
        assert!(!allowed(&config, &Method::POST, "/api/v1/system/shutdown"));

        let devices = token(&[ApiScope::DeviceWrite]);
        assert!(allowed(&devices, &Method::POST, "/api/v1/devices/x/wol"));
        assert!(!allowed(&devices, &Method::GET, "/api/v1/devices"));

        // A token holds no role: `role` is never consulted for tokens.
        let mut named = token(&[]);
        named.role = "admin".into();
        assert!(!allowed(&named, &Method::GET, "/api/v1/devices"));
    }

    #[test]
    fn account_takeover_and_lasting_access_need_elevation() {
        for (method, path) in [
            (Method::POST, "/api/v1/users"),
            (Method::DELETE, "/api/v1/users/bob"),
            (Method::PUT, "/api/v1/users/admin/password"),
            (Method::POST, "/api/v1/auth/tokens"),
            (Method::POST, "/api/v1/auth/tokens/3/renew"),
            (Method::DELETE, "/api/v1/db"),
        ] {
            assert_eq!(
                requirement(&method, path),
                Requirement::sensitive(),
                "{method} {path}"
            );
        }
        for (method, path) in [
            (Method::DELETE, "/api/v1/auth/tokens/3"),
            (Method::GET, "/api/v1/users"),
            (Method::POST, "/api/v1/firewall/commit"),
        ] {
            assert!(!requirement(&method, path).sensitive, "{method} {path}");
        }
    }
}
