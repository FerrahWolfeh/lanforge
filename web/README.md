# Lanforge WebUI

Modern, responsive management dashboard for Lanforge built with **SvelteKit**, **shadcn-svelte**, and **Tailwind CSS**.

The WebUI compiles to a production static SPA bundle (`adapter-static`), which is embedded directly into the `lanforged` binary via `lanforge-webui` (using `rust-embed`) and served by `lanforge-http` (`axum`).

---

## Tech Stack

- **Framework**: [SvelteKit](https://svelte.dev/) with Svelte 5 runes and `adapter-static`.
- **UI Components**: [shadcn-svelte](https://shadcn-svelte.com/) with Catppuccin Mocha aesthetic tokens.
- **Styling**: [Tailwind CSS v4](https://tailwindcss.com/).
- **Icons**: [Lucide Svelte](https://lucide.dev/).
- **Live Data**: Server-Sent Events (SSE) via `/api/v1/events` and typed client-side fetch calls against the JSON-RPC HTTP API.

---

## Development Workflow

```bash
# 1. Install dependencies
pnpm install

# 2. Run local development server with hot-reload (runs on http://localhost:5173)
pnpm dev

# 3. Type-check & lint
pnpm check

# 4. Build static bundle (outputs to build/)
pnpm build
```

When developing locally with `pnpm dev`, API requests proxy to your running Lanforge daemon instance (default port `:8088`).

---

## Architecture & Guidelines

- **Strict English Only**: All user-facing text (labels, placeholders, toasts, tooltips, dialogs) and code comments must be in English.
- **Client-Side Hydration**: Because Lanforge embeds a static SPA bundle, data fetching is strictly client-side post-hydration.
- **EventFeed Integration**: The global real-time event feed listens to SSE events persistently without breaking across page transitions.
