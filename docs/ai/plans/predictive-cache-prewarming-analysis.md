# Predictive Cache Pre-Warming — Feasibility Analysis & Recommendation

## Context

The idea: record every API URL SonicJS serves into the DB so we can *predict* the incoming request surface. Then, when content changes and the cache is invalidated, instead of purging and waiting for the next visitor to repopulate lazily, **proactively regenerate the responses for those known URLs and push them into KV worldwide** — so the cache is warm *before* the request arrives. Open questions the user raised: does anyone else do this and how; how does logged-in/personalized context complicate it; is it actually achievable; what are the limits and drawbacks.

This document is a feasibility study + market comparison + a recommended, scoped path — not a commitment to build the maximal version.

## The concept, decomposed

It is really two independent mechanisms that are being conflated:

- **(A) URL catalog / request prediction** — persist the set of URLs actually requested (+ frequency) so we know what to warm and in what priority order.
- **(B) Proactive pre-warm on invalidation** — on a content change, regenerate affected responses out-of-band and write them to the edge/KV ahead of demand.

(A) is a prerequisite for a *smart* (B), but (B) can also run off a static curated list. They can ship independently.

## How SonicJS caches today (baseline — verified)

- **3 tiers** (`packages/core/src/plugins/cache/services/cache.ts`): Tier-1 in-memory LRU (per-isolate `Map`, 50 MB cap); Tier-2 Cloudflare KV (global, **min 60 s TTL**, silently clamped); Tier-3 = DB (source of truth, the caller's fallback on miss).
- **Cache key** = `{namespace}:{type}:{identifier}:{version}` (`cache-config.ts:129`). For the API the identifier folds in **collection name + full filter object + normalized SQL** (`api.ts:790, 954, 1108`). It deliberately **excludes user identity** — the cache is only consulted when `!needsAcl` (see below), so every entry is the *public/privileged* projection shared by all such callers.
- **API namespace TTL = 300 s** (`cache-config.ts`).
- **Invalidation is event-driven but a sledgehammer** (`cache-invalidation.ts`): any `content.create/update/publish/delete` purges the entire `api:*` **and** `content:*` prefixes. There is **no mapping from a changed document → the specific cache keys it affects.** KV prefix purge = `list` + regex scan (`cache.ts:370`), which is the expensive path.
- **No per-request URL logging exists.** Metrics middleware counts requests only; analytics is an opt-in event API; security-audit logs auth events. Nothing records the request-URL surface to D1/KV today.
- **Response generation is only *partially* context-coupled.** Data path (`QueryFilterBuilder.parseFromQuery` → `db.prepare().bind().all()` → `mapDocRowToContent`) is essentially pure and re-runnable off-request. Only the envelope's `addTimingMeta()` reads `c.get('startTime')` and the caller's role for filter serialization. `cache.set()` already takes a **plain object**, not a `Context` — so writing a regenerated response into cache out-of-band is architecturally fine.
- **Background primitives**: `c.executionCtx.waitUntil()` is available and already used (audit, ai-search). **No cron triggers and no Queues are configured** in any `wrangler.toml` (an `EMAIL_QUEUE` binding is *referenced* but not wired). Plugin `onBoot` hooks exist and run once per isolate.

The `needsAcl` gate is the linchpin: `needsAcl = !anon && !canReadNonPublicContent(role)`. Anonymous callers and privileged roles (admin/editor) share one cache entry; only *non-privileged authenticated* users bypass cache entirely because their row-level ACL result set differs.

## What the market actually does

| Platform | Invalidation model | Pre-warm? | Mechanism |
|---|---|---|---|
| **Vercel ISR / Next.js** | `revalidateTag` / `revalidatePath`, marks stale in every region (~300 ms) | **No — lazy** | Stale-while-revalidate; regen happens on the *first request after* invalidation, on the instance that got it. On-demand + tag-based purge is the recommended granular model. |
| **Fastly** | Surrogate keys (= cache tags), instant purge (~150 ms), **batch** key purge | **No — lazy** | *Soft purge* marks stale + serves stale while revalidating; **origin shield** means one regen serves all edges (kills the thundering herd). |
| **Cloudflare** | Cache tags (Enterprise), Cache Reserve, Tiered Cache | **No — lazy/pull** | Read-through: edges *pull* from an upper tier / central store on miss. KV is a single global store with edge read caching, **eventually consistent** (1–5 s nearby, 5–15 s same-continent, **up to 60 s global**), write limit **1/s per key**. |
| **Headless CMS (Contentful/Strapi/Sanity + Uniform/Stellate)** | Webhook → map changed doc to affected routes/tags → call CDN purge API | **No — lazy** | Event-driven *targeted* purge, then SWR. Tag responses with the IDs they depend on; purge by tag. |
| **Cache warming (CacheFly/Varnish/Laravel/general)** | n/a | **Yes — but curated** | Warm a **curated top-URL list** after deploy / purge / before a known spike. ML-predictive warming exists but targets *demand prediction*, not "regenerate everything on every edit." |
| **Predictive prefetch (Quicklink/Guess.js)** | n/a | Client-side | Prefetch *likely-next* routes in the browser — different layer, but the same "predict then pre-fetch" instinct. |

**The load-bearing insight:** essentially nobody eagerly regenerates their whole URL space and pushes it to every edge on every content edit. The mature pattern that has won is **precise tag-based purge + stale-while-revalidate + an origin shield/upper tier** so exactly one lazy regeneration repopulates all edges. Eager pre-warm is reserved for *predictable* events against a *bounded* hot list. The user's instinct (predict + pre-warm) is real and used — but the industry applies it narrowly on purpose, because of the economics below.

## Feasibility on Cloudflare / SonicJS

### (A) URL catalog — feasible, with discipline
- Add `/api/*` middleware that, via `waitUntil()` (never blocking the response), increments a frequency counter for the **cache-eligible** request (only when `!needsAcl` and no field projection — mirror the exact cache-gate predicate so we never catalog an uncacheable shape).
- Store as counters, not raw rows: a `url_stat` document type or KV counter keyed by the *same* cache key the cache layer computes, so catalog ⇔ cache entries line up 1:1. Cloudflare **Analytics Engine** is the ideal sink (cheap, high-write, sampled) if we accept approximate counts.
- **Do not** synchronously `INSERT` into D1 per request — that adds latency and burns D1 write quota on the hot path. Sample + aggregate.

### (B) Proactive pre-warm — partially feasible, and it fights the platform
- **Out-of-band regeneration: yes.** Extract the pure data path into a service that takes `(collection, filter, params)` → response object, synthesizing timing meta (`startTime = now`). `cache.set()` already accepts a plain object. This is a real but contained refactor.
- **"Push to KV across the world": mostly a misconception of the platform.** You write a KV key *once*; Cloudflare propagates it. You cannot address per-region pushes. And KV is **read-through at the edge** — a pre-written key is only *materialized* at a given colo on its **first read there** (cold read pulls from the upper tier). So pre-writing KV shifts the cost but does **not** make every edge instantly warm, and the write itself is subject to up-to-60 s global propagation and the 1-write/s-per-key ceiling.
- **The memory tier cannot be pre-warmed at all.** It's a per-isolate `Map` across thousands of isolates worldwide; there is no remote write path. It only warms on the first local request — inherently lazy.
- **Compute limits force fan-out.** Subrequests and CPU per invocation are capped, so one request/handler can't regenerate an unbounded URL set. Real pre-warm needs **Queues** (no CPU limit on consumers) or **Cron** (1-min min, 15-min wall) — **neither is configured today**, so this is net-new infra + `wrangler.toml` + billing surface.
- **Precise warming requires precise invalidation first.** You can't warm "the URLs a change affects" while invalidation only knows how to purge `api:*` wholesale. A **dependency/tag map** (changed `rootId` → dependent cache keys), i.e. the Fastly-surrogate-key / Vercel-`revalidateTag` model, is a hard prerequisite — and is independently the single most valuable improvement here.

### The invalidation fan-out problem
One document can appear in page 1, page 2, any `sort`, any `where[...]` filter, any `fields` projection, any `limit`. The set of cache keys a single edit invalidates is combinatorially large. Purging them is fine (prefix nuke). **Re-warming all of them is not** — you'd regenerate a long tail of near-zero-traffic permutations on every save. This is why warming must be **top-N by the (A) catalog**, never "all known URLs."

## The logged-in / personalized-context problem

This is the sharpest constraint, and the user flagged it correctly.

- Personalized responses can't share a global cache entry. As request granularity grows (user, role, per-row ACL), **cache-key cardinality explodes** until every key is unique — at which point caching (and warming) buys nothing. `Vary: Cookie` is the classic anti-pattern that triggers exactly this.
- **SonicJS already sidesteps it** by only caching the `!needsAcl` projection. Consequence: pre-warming can *only ever* target the **anonymous/public projection**. That is genuinely useful (it's the bulk of headless-CMS read traffic) but it means the feature does **nothing** for non-privileged logged-in users — they bypass cache by design, and trying to warm per-user is the cardinality bomb above.
- Industry escape hatches, for reference: keep logged-out traffic cookie-free so it stays cacheable; exclude session cookies from the cache key except on account/cart pages; **content fragmentation / ESI** — cache the public skeleton, fetch the personalized slice per request. Only the first two fit SonicJS's current model; ESI would be a much larger architecture change.

## Limitations & drawbacks (summary)

- **Public-projection only.** Zero benefit for personalized/ACL-filtered responses — the hardest and often most valuable case.
- **KV realities.** Up-to-60 s global propagation, 1 write/s per key, read-through (pre-write ≠ per-edge warm), min 60 s TTL. Warming a hot key that changes faster than propagation is pointless.
- **Memory tier unwarmable.** The fastest tier is always cold-started per isolate.
- **Fan-out / long tail.** Naive "warm all catalogued URLs" regenerates mostly cold permutations → wasted CPU, subrequests, KV writes, and dollars.
- **New infra + cost.** Queues/Cron not present today; per-request cataloging adds write volume; pre-warm adds compute + KV write billing that scales with edit rate × catalog size.
- **Correctness risk.** Pre-warm races invalidation: a second edit mid-warm can write a stale response *over* a fresh purge. Needs versioning/generation stamps on warm jobs.
- **Complexity vs. payoff.** SWR (below) captures most of the latency win at a fraction of this cost.

## Verdict

- **"Track *all* URLs and push *all* responses to *every* edge on *every* invalidation" — not feasible / not advisable.** It fights Cloudflare's pull-based edge model, ignores the fan-out long tail, and duplicates what SWR does better. This is precisely why no major platform does it.
- **A scoped version — catalog the hot public URLs, invalidate precisely by tag, serve stale while revalidating, and optionally pre-warm a bounded top-N — is feasible and worthwhile**, and it's the same shape Vercel/Fastly/CMS vendors converged on.

## Recommended phased approach

1. **Dependency/tag-based invalidation (surrogate keys).** Record `document_references`-style edges from each cached key → the `rootId`s it depends on; on a doc change, purge only dependent keys instead of `api:*`. Highest value even if we ship nothing else. Files: `plugins/cache/services/cache-invalidation.ts`, cache-key emission in `routes/api.ts`, `services/documents.ts` write hooks.
2. **URL catalog (async, sampled, ranked).** `/api/*` `waitUntil()` counter keyed by the real cache key, gated by the exact cache-eligibility predicate; sink = Analytics Engine or a `url_stat` counter. No synchronous D1 writes.
3. **Stale-while-revalidate.** On invalidation, mark stale + serve the stale entry while a single `waitUntil()` regen refreshes it. Biggest latency win, lowest cost, no new infra. This likely satisfies the real goal ("fast even right after an edit") without eager global warming.
4. **Optional targeted pre-warm.** A Queue/Cron consumer that, after a tag purge, regenerates the **top-N** hottest keys for the affected tags (from step 2) and `cache.set()`s them. Bounded N, generation-stamped to lose races safely. Requires `wrangler.toml` Queue/Cron wiring.
5. **Document the ceiling.** Public-projection only; KV propagation lag; memory tier stays lazy. Set expectations in docs.

Ship 1→3 first; treat 4 as opt-in for high-read/low-edit deployments.

## Verification approach

- **Tag invalidation (1)**: real-DB test — cache two collections, edit one doc, assert only its dependent keys are gone and the unrelated collection's entry survives (today it would be purged too). Harness: `__tests__/**/*.integration.test.ts` + `documents.sqlite.test.ts`.
- **Catalog (2)**: hit several `/api/:collection?...` shapes, assert counters exist for cache-eligible ones and are **absent** for `needsAcl`/projection requests (never catalog uncacheable shapes). Confirm zero added latency (write is in `waitUntil`).
- **SWR (3)**: warm an entry, invalidate, immediately re-request → assert stale served instantly (`source: kv`, stale flag) and a subsequent request shows the refreshed value.
- **Pre-warm (4)**: publish a doc, then (without any client request) read the top-N keys → assert `source: kv` hit cold. Verify a mid-warm second edit does not clobber the newer generation.
- **E2E**: Playwright spec numbered 68+ (R11), tagged `@api @content`, asserting the `meta.cache.source`/`X-Cache-Source` transitions. Write it; CI runs it — do not run E2E locally.
