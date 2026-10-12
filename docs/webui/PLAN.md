# Lanforge WebUI — Architecture & Page Plan (Draft / Pre-Dev)

Status: planning skeleton, not implementation-ready. Intended as living doc — fill in as decisions get made, same spirit as `API.md`/`PPPOE.md`.

Stack (decided): SvelteKit (`adapter-static`) + shadcn-svelte + Tailwind (Catppuccin Mocha tokens). Static output served by `axum` from `lanforged`. Data via `HTTP_API.md`. Real-time via SSE.

---

## 1. Route Tree

Mapped directly to backend service boundaries (mirrors §2–6 of `API.md`), not a generic settings tree.

```
/                          Dashboard — topology graph + ServiceBanner overlay
/network                   Devices list (list_devices)
/network/[target]          Device detail (whois) + host promotion actions
/network/hosts             Static host management (host_list/add/set/remove/import/export)
/dns                       Redirect -> /dns/resolver
/dns/resolver              dns_stats, dns_analytics, dns_query (diagnostic tool)
/dns/log                   dns_query_log — table view (follow=false) + live tail toggle (follow=true, SSE)
/dns/cache                 dns_cache_dump, dns_cache_stats_ext, flush action
/dns/adblock               dns_adblock_status, toggle, timer control
/dns/adblock/sources       dns_adblock_urls, add/remove
/dns/adblock/allowlist     dns_adblock_allowlist, dns_allow/unallow
/dns/rewrites              dns_rewrite_list/add/remove/clear/import/export
/dhcp/leases               leases, lease_renew/release
/dhcp/pools                dhcp_pools
/pppoe                     ⚠️ BLOCKED — no API surface defined yet (see §5)
/system                    status, service_banners, ServerCapabilities, resources
/system/database           db_vacuum/prune/log_clean/reset (X-Confirm: wipe gate)
/system/auth               ak_list (read-only in webui; generate/delete/renew stay UDS-only, CLI/TUI territory)
```

Notes:
- `/dns` as a section is big enough to earn its own subnav (mirrors your instinct to treat it like Pi-hole *within* Lanforge, not as the whole app).
- `/system/auth` should probably just show tokens with a "manage via `lanforge-cli` locally" hint, since `ak_generate`/`delete`/`renew` are UDS-only by design — don't fight that constraint in the UI, surface it honestly.

---

## 2. Layout Structure

```
+layout.svelte (root)
├── Topbar — connection/auth status, daemon uptime
├── Sidenav — top-level sections from route tree above
├── <slot> — page content
└── EventFeed — collapsible panel, global, independent of route
```

- **EventFeed** consumes `GET /api/v1/events` (SSE), own Svelte store, filterable by `EventKind`. Lives in root layout so it persists across navigation — this is the differentiator vs Pi-hole/UniFi you flagged earlier, so it shouldn't be buried in a per-page component.
- Section-local subnav (e.g. DNS's five subpages) gets its own `+layout.svelte` inside `/dns`, not duplicated per page.

---

## 3. Data Layer

Since `adapter-static` means no SSR at runtime, all data fetching is client-side post-hydration — SvelteKit `load` functions won't have a server to run on in production.

- `lib/api/client.ts` — thin typed fetch wrapper, one function per RPC method (`listDevices()`, `dnsStats()`, etc.), mirroring the method names in `API.md` 1:1 so the doc and the code stay easy to cross-reference.
- `lib/api/types.ts` — TS interfaces mirroring `API_TYPES.md` structures. Worth asking later whether to hand-write these or codegen from a shared schema — not a pre-dev decision, flag for when `lf-api` stabilizes.
- Auth token stored client-side (this is a real deployed app, not a sandboxed artifact, so `localStorage` is fine here) after `POST /auth/validate` succeeds.

## 4. Real-time / SSE Integration Points

| Where | Endpoint | Mode |
|---|---|---|
| Global event feed | `/api/v1/events` | always-on, filterable |
| DNS query log live tail | `/api/v1/dns/log?follow=true` | opt-in per page, separate connection from the global feed |

Each SSE consumer should independently handle `Last-Event-ID` reconnection per `HTTP_API.md` — don't centralize reconnection logic in one store shared by both, since they have different `EventKind`/entry shapes.

## 5. Open Items

- **PPPoE API surface undefined.** `PPPOE.md` covers the module's internal state machine (Discovery → LCP → Auth → IPCP → IPv6CP → KernelHandoff → Established → Reconnecting) but none of `API.md`/`API_TYPES.md`/`HTTP_API.md` expose it. Before `/pppoe` can be scoped, need at minimum: current state + substate, session uptime, LCP echo stats, reconnect count/history, and a force-redial action. Worth doing as a small addendum to `API.md` once you've nailed down what you're expanding in the module.
- **Mobile/responsive scope** — is this a desktop-oriented admin tool (like most router UIs) or does it need to work reasonably on a phone? Affects whether the sidenav/EventFeed layout needs a collapsed mobile variant from day one or can be retrofitted.
- **PPPoE nav placement** — top-level item, or nested under `/network` alongside devices/hosts? Depends partly on how much surface area the expanded module ends up needing.
