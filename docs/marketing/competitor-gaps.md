# SonicJS Competitor Gaps — Developer Interest Analysis

Source: `/compare` feature matrix (`www/src/components/ComparisonMatrix.tsx`), SonicJS
vs Payload, Strapi, Directus, Sanity, Contentful. Data verified July 2026.

This documents the biggest gaps in the SonicJS column that would prevent a developer
from choosing (or even trialing) SonicJS, ranked by severity, plus a proposed SDK plan.

---

## Tier 1 — hard filters (developer bounces before trying)

- **No official SDK** (`no`). All 5 competitors ship one. Developers expect a typed
  client with autocomplete out of the box. Biggest DX credibility hit.
- **GraphQL roadmap-only** (`soon`). Payload / Strapi (plugin) / Directus / Sanity /
  Contentful all have it. Teams that filter their CMS shortlist on "GraphQL: yes"
  never see SonicJS in results.
- **i18n / localization roadmap-only** — content localization, locale fallbacks, and
  field-level localization all `soon`; admin UI translations + RTL are `no`. Any
  multi-language project is eliminated instantly. Four red rows in one category.
- **Type generation from schema = `partial`**. The killer: the site markets
  "TypeScript-first," but competitors auto-generate types from schema and SonicJS is
  only partial. The headline DX claim is undercut by its own matrix.

## Tier 2 — serious, surfaces during evaluation

- **Relationship modeling is weak**: one-to-one `partial`, many-to-many `partial`,
  polymorphic `partial`, deep population `partial`. Content modeling is a core CMS
  job; SonicJS trails all 5 peers here.
- **No conditional fields, no computed/virtual fields, no UI fields** (`no`). Modeling
  depth gap — Payload / Strapi / Directus / Sanity are all `yes`.
- **Single DB dialect (SQLite only)**. Postgres is roadmap. Teams with existing
  Postgres/Mongo infra can't adopt. Directus / Strapi / Payload flex here.
- **No real-time / WebSockets** (`soon`), **no background jobs / queues** (`no`),
  **cron `partial`**. Automation / reactive workloads are blocked.
- **No SSO/SAML** (`soon`), custom access-control functions `no`, row-level access
  `partial`. Enterprise evaluation fails.

## Tier 3 — trust / maturity signal

- **~1.6k GitHub stars** vs Strapi ~72k, Payload ~43k, Directus ~36k — roughly
  20–45x behind. Developers read stars as a risk proxy ("will this still exist in two
  years / is anyone using it").
- **No marketplace** (~25 bundled plugins vs competitors' marketplaces). Small
  ecosystem = you build integrations yourself.
- **No visual page builder, no soft-delete/trash, no editorial comments/collaboration.**
  Feels less "finished" than incumbents in a side-by-side.

## Sharpest problem

The matrix contradicts SonicJS's own pitch. The site sells **edge speed +
TypeScript-first + free/no-paywall**. Edge speed is real (0–5 ms cold start; the only
option with global edge *and* self-host). But "TypeScript-first" is undermined by
**no SDK + partial type-gen** — the two rows a TS developer checks first. Fixing
SDK + full schema→type generation closes the credibility gap more cheaply than chasing
GraphQL/i18n, and defends the differentiation already claimed.

---

## Proposed SDK plan

The SDK is layered, not one deliverable. Build bottom-up.

### 1. Core: TypeScript/JavaScript client (the actual "SDK") — build first

Framework-agnostic. Wraps the REST + OpenAPI spec SonicJS already emits. Runs
anywhere — Node, Bun, browser, Workers, React Native.

```ts
const sonic = createClient({ url, apiKey })
const posts = await sonic.collection('posts').find({ where, limit })
```

This is what the matrix row means. Competitor equivalents: Sanity `@sanity/client`,
Contentful `contentful.js`, Strapi `@strapi/sdk-js`, Directus `@directus/sdk` — all
JS/TS-first and framework-neutral. This is ~90% of the value and flips the matrix
`no` → `yes`.

### 2. Type layer — ties to the type-gen gap

Types generated from the collection schema feed the client, so `find('posts')`
returns `Post`, not `any`. This is why the SDK and schema→type-generation are **one
project, not two**. Directus's SDK does exactly this.

### 3. Framework adapters — thin, optional, later

- **React hooks** — `useDocument`, `useCollection` (TanStack Query wrapper). Highest
  demand; build second.
- **Next.js** helpers — server components / cache tags (Payload's whole pitch).
- Vue / Svelte — later, low priority.

### Recommendation

Ship the **typed JS/TS core client first** — a single framework-agnostic package.
React adapter second (biggest audience). Do **not** start with React: it locks out
everyone else and can't flip the matrix row on its own.

**Edge angle to exploit:** SonicJS runs *on* Workers, so an SDK that works identically
server-side (in the same Worker, zero network hop) and client-side is a differentiator
Sanity/Contentful can't match — their "local / server-side API" rows are `no`.
