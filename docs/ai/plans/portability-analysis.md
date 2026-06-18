# SonicJS Portability Analysis — Running Outside Cloudflare

> High-level feasibility + effort analysis for decoupling SonicJS from
> Cloudflare-specific services, and the deployment targets it would unlock.
>
> **Status:** analysis only — no implementation committed.
> **Date:** 2026-06-17

## TL;DR

- The hardest Cloudflare primitive (**Durable Objects**) is **not used** — there is no impossible port.
- The D1 → SQLite adapter **already exists** as a test shim (`packages/core/src/__tests__/utils/d1-sqlite.ts`, ~644 lines). Promoting it to a runtime driver is ~80% of the self-host DB layer.
- R2 surface is **4 methods** (`put`/`get`/`delete`/`head`); only **1 queue producer**; KV used in a few plugins.
- **Recommendation:** ship a tiered self-host story. Tier 1 (Docker + SQLite-on-disk + filesystem storage) captures most of the "won't use Cloudflare" audience for ~1–3 weeks of work and requires **no SQL rewrite**. Defer Postgres (Tier 2) — it's the only months-long, dialect-rewriting tier — until demand is proven.

## Cloudflare lock-in inventory (measured)

| Primitive | Actual usage in `packages/core/src` | Port difficulty |
|---|---|---|
| **Durable Objects** | **ZERO** | none — absent |
| **`env.DB` (D1)** | 309 `c.env.DB` refs, 58 files, `.prepare` in 112 files | uniform API (rule R1) → shim once |
| **`.batch()` atomicity** | ~12 sites (`services/documents.ts` = 5) | better-sqlite3 transactions cover it |
| **R2 bucket** | only `put` / `get` / `delete` / `head` | tiny surface → S3 / filesystem trivial |
| **KV (`CACHE_KV`)** | cache plugin, brute-force detector, multi-tenant | medium — needs KV shim (Redis / in-mem / SQLite) |
| **Queue (`EMAIL_QUEUE`)** | **1 producer** (email plugin `.send`) | minimal — sync fallback |
| **Runtime (Workers)** | Hono.js (Web-standard) | portable — Node/Bun/Deno/Lambda adapters exist |
| **Auth (Better Auth)** | runtime-agnostic | free |
| **Misc env vars** | JWT_SECRET, SENDGRID/RESEND, IMAGES_*, etc. | plain config |

### The SQLite-specific SQL wall (Postgres only)

Dialect-coupled SQL counted in `packages/core`:

```
28  json_extract        ← document projection, everywhere
11  VIRTUAL  (generated columns)
 5  json_set
 3  COALESCE(MAX...)     ← version_number derivation
```

- **Stay on SQLite (any host): zero translation.**
- **Go to Postgres:** real rewrite — `json_extract`, `VIRTUAL` generated columns, and partial/expression UNIQUE indexes do not port cleanly. This is the expensive tier.

## Effort estimate

| Target | Effort | Why |
|---|---|---|
| **Node/Bun + SQLite-on-disk + filesystem storage** | small–medium, **~1–3 weeks** | No Durable Objects. DB shim exists. R2 = 4 calls. 1 queue. Hono already portable. |
| **+ Postgres + S3 (scale tier)** | large, **months** | 28 `json_extract` + virtual columns + partial indexes = dialect rewrite + re-test matrix |

Tier 1 blockers are all small and mechanical:

1. Promote `d1-sqlite.ts` test shim → runtime DB driver (SQLite-on-disk).
2. Storage driver abstraction: R2 → S3 / filesystem (4 methods).
3. KV shim: `CACHE_KV` → Redis / in-memory / SQLite table.
4. Queue fallback: `EMAIL_QUEUE.send` → synchronous send.
5. Replace Cloudflare `env` binding injection with config-driven DI at bootstrap.

No architectural surgery required for Tier 1.

## Deployment targets unlocked

### Tier 0 — today (Cloudflare-native, no work)
- **Cloudflare Workers** + D1 + R2 + KV (flagship)

### Tier 1 — Node/Bun + SQLite-on-disk + filesystem (~1–3 wk)
Anywhere a Node/Bun process + persistent local disk runs.

**Self-host / VPS / bare metal**
- **Docker** (`docker run sonicjs`) — the primary unlock
- Any Linux **VPS** — DigitalOcean, Linode, Hetzner, Vultr, OVH
- **Raspberry Pi / homelab / NAS** (Synology, Unraid)
- On-prem / air-gapped (sovereignty, privacy buyers)

**PaaS (container / Node-native)**
- **Railway**, **Render**, **Fly.io**, **Koyeb**
- **Heroku**, DigitalOcean App Platform
- **Coolify** / Dokku (self-host PaaS)

> Caveat: SQLite-on-disk needs a **persistent volume**. Ephemeral-filesystem hosts need Tier 1.5.

### Tier 1.5 — serverless Node (SQLite → libSQL/Turso, storage → S3)
Same SQLite dialect → **no SQL rewrite**. Swap DB endpoint + storage driver.
- **Vercel** functions
- **Netlify** functions
- **AWS Lambda** / Lambda@Edge
- **Deno Deploy** (Hono runs on Deno)

### Tier 2 — Postgres + S3 (months work, dialect rewrite)
Managed-Postgres + object-store at scale.
- **AWS** (ECS/Fargate/EC2 + RDS + S3)
- **GCP** (Cloud Run + Cloud SQL + GCS)
- **Azure** (Container Apps + Postgres + Blob)
- **Kubernetes** anywhere (EKS/GKE/AKS/self-managed)
- Supabase-backed deploys

### Summary map

| Target class | Tier | DB | Storage |
|---|---|---|---|
| CF Workers | 0 | D1 | R2 |
| Docker / VPS / homelab | 1 | SQLite-on-disk | filesystem |
| Railway / Render / Fly | 1 | SQLite-on-disk (volume) | fs / S3 |
| Vercel / Netlify / Lambda / Deno | 1.5 | Turso / libSQL | S3 |
| AWS / GCP / Azure / K8s scale | 2 | Postgres | S3 / GCS / Blob |

## Audience trade-off

**For broadening:**
- "Cloudflare-only" filters out a large share of developers (no CF account, existing AWS/Vercel/self-host stacks).
- Docker / self-host story unlocks enterprise + privacy/sovereignty buyers.
- SQLite-anywhere = trivial local dev and demos.

**Against:**
- Cloudflare-native edge perf is the current differentiator; going generic competes head-on with Strapi / Payload / Directus where the edge angle is lost.
- The document model leans on SQLite-specific features — Postgres is a real rewrite, not a config flag.
- Maintenance drag: every feature tested across more runtimes/DBs.

## Recommendation

1. **Ship Tier 1 first** (Docker + SQLite-on-disk + filesystem). Cheap, reuses the existing shim, no SQL rewrite, captures most non-Cloudflare demand.
2. **Add Tier 1.5** (Turso swap) next — nearly free since the dialect stays SQLite; unlocks Vercel / Netlify / Lambda / Deno.
3. **Defer Tier 2** (Postgres) until demand is proven — it is the only architecture-bending, months-long tier.

Keep Cloudflare-native as the flagship/recommended path. Market portability as **"runs anywhere SQLite runs"** — honest, cheap, and broadens reach without diluting the edge story.
