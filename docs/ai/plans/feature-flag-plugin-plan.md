# Feature-Flag Plugin — Design & Phased Build Plan

Status: **Proposal / design doc** (not yet implemented). Author: research + design pass, 2026-07.

Goal: a first-class SonicJS **plugin** that turns the CMS into a feature-flag / progressive-delivery platform
in the spirit of LaunchDarkly, Unleash, Flagsmith, GrowthBook, and Statsig — delivered as an escalating set of
phases from a shippable MVP through a "highly complex" LaunchDarkly-parity system.

---

## Context

Two constraints shape everything:

- **Document model is the data model** (`CLAUDE.md`, non-negotiable): no new feature tables. Flags, segments,
  projects, environments, SDK keys, audit entries, experiments all live as **system document types** in
  `documents`, with queryable `q_*` generated columns + `document_facets` for multi-valued fields.
- **Cloudflare-edge native**: the hot path (flag evaluation) must be sub-ms via the 3-tier `CacheService`
  (memory → `CACHE_KV` → D1), never a raw D1 read per eval.

### Why the document model is a natural fit

A flag definition is just a versioned JSON document. SonicJS already provides exactly the primitives a flag
platform needs:

- **versioning** → flag change history / rollback (free)
- **`is_published` vs `is_current_draft`** (separate axes) → staged flag edits that don't go live until
  published — mirrors LaunchDarkly's draft/approval model
- **`document_permissions`** → RBAC governance per flag
- **`document_facets`** → segment / tag membership (multi-valued)
- **hooks** → outbound webhooks + cache invalidation
- **cron** → scheduled changes / progressive-rollout ticks
- **`CACHE_KV`** → edge delivery

We are not building a database — we compose existing SonicJS services.

### Decisions locked (scoping)

- **Dual consumer:** flags serve BOTH (a) SonicJS internally — core/plugins/admin gate their own features via
  a server-side `FlagService.isEnabled(key, ctx)` + a `flags:evaluate` hook — AND (b) external apps, via SDK
  keys, the `/flags` public API, and an OpenFeature provider.
- **Terminal complexity = Phase 6** (full: scheduling/approvals + A/B experimentation engine).
- **Edge delivery = simple:** D1 as source of truth behind the 3-tier `CacheService` (memory → `CACHE_KV` →
  D1) + **polling** config download (`/flags/config?since=<ver>`). SSE streaming is a documented **optional
  stretch**, not on the critical path.
- **Tenancy = full multi-project + multi-environment:** `project` and `environment` are first-class
  dimensions. Same flag key exists across all environments of a project with independent per-env targeting +
  credentials. (POC `tenant_id` stays `'default'`; project/env are intra-tenant dimensions on the flag docs.)

---

## Feature-flag landscape (research summary)

Distilled from LaunchDarkly, Unleash, Flagsmith, Split/Harness FME, GrowthBook, ConfigCat, Statsig,
Optimizely, and the OpenFeature spec. Sources listed in the appendix.

**Universal entity spine:** `Project → Environment → Flag(key) → Variations[] → TargetingConfig`, plus reusable
`Segment`s. Same flag key exists in every environment; each environment holds independent on/off + targeting +
its own SDK credentials.

**Flag value types:** boolean (kill switch) · string · number · JSON/object (remote config). Anything beyond
boolean is "multivariate" and is the substrate for A/B tests. Metadata: `temporary|permanent` +
`purpose(release|experiment|ops|permission)` drives stale-flag / tech-debt tooling.

**Deterministic evaluation order (adopt verbatim):**

1. flag off → serve **off variation** (`reason: OFF`)
2. **prerequisites** — each must be on & serving required variation (`PREREQUISITE_FAILED`)
3. **individual targets** — exact key match (`TARGET_MATCH`)
4. **rules** — first-match wins, top-to-bottom; serves fixed variation or a **% rollout** (`RULE_MATCH`)
5. **fallthrough** — default rule/rollout (`FALLTHROUGH`)

Return `{ value, variant, reason }`. Map reasons/errors onto OpenFeature's vocabulary
(`STATIC/DEFAULT/TARGETING_MATCH/SPLIT/CACHED/DISABLED/ERROR`; `FLAG_NOT_FOUND/TYPE_MISMATCH/…`).

**Operator library (build the union):** `in/notIn` · string `contains/startsWith/endsWith/regex` · numeric
`< <= > >=` · date `before/after` (epoch-ms) · `semVer{Eq,Lt,Gt}` · `segmentMatch`.

**Percentage rollout / bucketing (the load-bearing algorithm):** deterministic
`hash(flagKey + salt + contextAttributeValue) → number in range → compare to cumulative variation weights`.
Gives stickiness (same input → same variation) + monotonicity (a 10%→20% ramp never re-buckets someone out)
with zero server state. Hash choice varies by vendor: LaunchDarkly = SHA-1 (first 15 hex ÷ 0xFFF…),
Unleash/Optimizely = MurmurHash3-32, GrowthBook = FNV-1a-32, ConfigCat = hash mod 100. **We pick
MurmurHash3-32** (most common cross-language, cheap on Workers). Expose `bucketBy`/`hashAttribute` + per-flag
`salt` (changing the salt reshuffles). Add optional **sticky-bucketing persistence** later for experiments.

**Segments:** rule-based (reusable clause group) + list-based (enumerated keys). Very large lists become
"big/unbounded segments" backed by an out-of-band store (KV) instead of the config payload.

**Contexts:** modern model is **multi-context** (LaunchDarkly "context kinds": user + org + device evaluated
together; each rollout/experiment picks a randomization unit). Start single `user` context; add multi-context
in Phase 4.

**Delivery / SDK:** server SDKs pull the whole ruleset + evaluate locally; client SDKs must NOT see other
users' targeting → get pre-evaluated values or restricted config. Config delivery = versioned **polling**
(chosen) with **SSE streaming** as an optional stretch for instant kill-switch propagation; CDN edge; client
**bootstrap**. **OpenFeature** is the vendor-neutral standard — ship a provider so consumers adopt us behind
the standard API + before/after/error/finally hooks.

**Experimentation:** A/B = multivariate flag + metrics layer. Atomic unit = **exposure/impression event**
(assigned variant at time T), joined to metric events for lift. Guardrail metrics, holdouts, mutual-exclusion
layers, SRM checks. Stats accelerators: CUPED (variance reduction), sequential/anytime-valid testing.

**Governance:** RBAC/custom roles · approval / change-request workflows · scheduled changes + progressive
rollout workflows · immutable audit log · inbound triggers + outbound webhooks · code-reference scanning for
stale-flag cleanup. Credentials: secret server **SDK key**, rotatable **mobile key**, public **client-side
ID**, separate **API tokens** for admin REST.

---

## SonicJS integration recipe (verified against codebase)

- **Author with `definePlugin({...})`** — `packages/core/src/plugins/sdk/define-plugin.ts`. Sync `register(app)`
  mounts routes only; async `onBoot(ctx)` does DB/KV/seeding/dynamic hooks. Never read `c.env` in `register`.
- **Public eval endpoint must be TOP-LEVEL** (`/flags/*`), NOT `/api/flags/*` — the core `/:collection`
  catch-all shadows user-plugin `/api/*` routes (documented in the starter example plugin,
  `packages/create-app/templates/starter/src/plugins/example/index.ts:114-128`).
- **Store flags as a system document type** (`internal: true`), registered in `onBoot` via
  `DocumentTypeRegistry.register(...)` (`packages/core/src/services/document-type-registry.ts:44`, idempotent,
  auto-DDLs `q_*` columns). Model on `document-types-seed.ts` (`plugin`, `analytics_event`, `security_event`).
  Not a collection — flags are control-plane records, not editor content.
- **Writes** → `DocumentsService.create/saveDraft/publish` (`packages/core/src/services/documents.ts`,
  raw prepare/bind/batch per R1). Timestamps in **seconds** (`documentSecondsToMs`).
- **Reads** → `DocumentRepository.listPublished({ typeId:'feature_flag', scalarFilters:[…] })`
  (`packages/core/src/services/document-repository.ts:182`) — tenant-scoped chokepoint (R3/R4).
- **`q_*` generated columns** auto-created from `queryableFields`; self-healed by
  `ensureDocumentGeneratedColumns` (`services/migrations.ts:108`). Facets for tags/segment membership.
- **ACL** → `DocumentPermissionsService.isAllowed` (deny → override → baseGrants). Public eval uses
  `[{type:'public',id:'*'}]`; admin uses `[{type:'user'},{type:'role'}]`.
- **Edge cache** → `CacheService` (`packages/core/src/plugins/cache/services/cache.ts:162`) over `CACHE_KV`
  binding; `getCacheService(config, kv)`. Invalidate on publish via hooks.
- **Admin UI** → `renderAdminLayoutCatalyst`; nav via `menu:[{label,path,icon,order,permissions}]`; global
  defaults via `configSchema`. Model on `plugins/core-plugins/analytics/routes/admin.ts`.
- **Hooks** → `content:after:publish` + custom events for webhook fan-out + cache bust
  (`plugins/hooks/catalog.ts`).
- **Cron** → `crons:[{schedule,hookFamily}]` + `onCronTick` for scheduled changes / progressive ramps
  (also add schedule to app `wrangler.toml [triggers]`).
- **Tests** → real-D1 harness `createTestD1()` (`__tests__/utils/d1-sqlite.ts`) + `applyScalarSchema(...)`;
  E2E Playwright numbered **68+** (R11), tagged `@smoke`/feature tag.

Folder layout (mirror `analytics/`):

```
src/plugins/feature-flags/
  index.ts                    definePlugin
  services/flag-service.ts    write/read wrappers over Documents{Service,Repository}
  services/evaluator.ts       pure deterministic eval engine (unit-testable, no I/O)
  services/bucketing.ts       MurmurHash3-32 rollout bucketing
  routes/admin.ts             /admin/feature-flags UI + mutations
  routes/api.ts               /flags/* public eval + SDK endpoints
  types.ts                    Flag/Segment/Rule/Context Zod schemas
  __tests__/*.sqlite.test.ts  real-D1 + evaluator unit tests
```

---

## Phased roadmap (MVP → highly complex)

Each phase is independently shippable and additive. Complexity/effort rises L→XL.

### Phase 0 — Foundations & data model (S)

- Register `feature_flag` + `flag_segment` system document types (`internal:true`).
  `queryableFields`: `q_ff_key` (text), `q_ff_project` (text), `q_ff_env` (text), `q_ff_type`,
  `q_ff_enabled` (int), `q_ff_archived` (int); facets: `tags`, `segment_refs`.
  Project + env are first-class from day one (uniqueness is per `project+env+key`). Also seed a
  `flag_project` type (name, key, list of environments).
- Zod schemas (`types.ts`): Flag `{ key, type, variations[], on, offVariation, fallthrough, rules[],
  individualTargets[], prerequisites[], salt, temporary, purpose, tags }`; Segment `{ key, kind:'rule'|'list',
  clauses[]|keys[] }`; Rule/Clause `{ attribute, op, values[], negate }`.
- `FlagService` CRUD over `DocumentsService`/`DocumentRepository`. Single tenant `'default'`.
- Tests: `flag-service.sqlite.test.ts` (create → q_* populated → read back).
- **Ships:** flags exist in DB, boolean on/off, no UI yet.

### Phase 1 — Evaluation engine + public eval API (M) ← MVP boundary

- Pure `evaluator.ts`: the 5-step order (off→prereq→individual→rules→fallthrough) → `{value,variant,reason}`.
- Full operator library in evaluator. `bucketing.ts` MurmurHash3-32 percentage rollout w/ salt + `bucketBy`.
- `GET /flags/evaluate/:key?ctx=…` and `POST /flags/evaluate` (batch, context in body) — **top-level path**,
  public principalSet, wrapped in `CacheService` (key `flags:<tenant>:<project>:<env>`), cache-bust on publish
  hook.
- OpenFeature-shaped response (`value/variant/reason`); typed error codes.
- **Internal gating API** (the "both consumers" requirement): export
  `FlagService.isEnabled(key, ctx)` / `variation(key, ctx, default)` for SonicJS core, plugins, and admin to
  gate their own features server-side (reads through the same cache). Publish a `flags:evaluate` hook so other
  plugins can subscribe. This is the in-process twin of the public `/flags` API — same evaluator, no HTTP hop.
- Tests: evaluator unit matrix (every operator, rollout distribution ±, prereq chains, reason codes) —
  pure functions, no D1 needed → cheap + exhaustive. Integration test for the cached endpoint.
- **Ships:** a working flag service, callable both over HTTP (`/flags/evaluate`) and in-process
  (`FlagService.isEnabled`), returning sticky, targeted results.

### Phase 2 — Admin UI + governance basics (M)

- `/admin/feature-flags`: list (filter by project/env/tag/status), create/edit flag (variations, rules
  builder, individual targets, rollout sliders), instant on/off toggle (kill switch), archive.
- Segment admin (rule-based + list-based).
- Uses draft/publish: edits save as draft, "Publish" flips live (LD-style staged change) via
  `DocumentsService.publish`. Change history = document versions (free rollback).
- RBAC gates via `document_permissions` / `requireRbac`. `menu[]` entry, `configSchema` for global defaults
  (default TTL, default-off).
- E2E spec `68-feature-flags-admin.spec.ts` (`@smoke @content`): toggle persists, eval endpoint reflects it.
- **Ships:** self-service flag management in the admin.

### Phase 3 — Projects, environments & credentials (L)

- Promote **project** + **environment** to full first-class management (list/create/switch in admin, env
  copy/clone, per-env config download). Flag docs already carry `q_ff_project`/`q_ff_env` from Phase 0; this
  phase adds the management surface + per-env credentials. Same flag key across all envs of a project with
  independent per-env targeting. (`tenant_id` stays `'default'`; project/env are intra-tenant.)
- **SDK credentials** as a `flag_sdk_key` document type: server key (secret, full ruleset), client-side ID
  (public, client-safe flags only), per-flag `clientAvailable` toggle. Reuse `api-keys-plugin` patterns.
- `GET /flags/config?env=…` server-SDK bulk config download (auth by SDK key); client-safe filtered variant.
- Outbound **webhooks** on flag change (hook subscriber → fetch); inbound **triggers** (signed URL flips a
  flag) for APM/alerting kill switches.
- Immutable **audit log** as `flag_audit` document type (who/what/when/before/after) via hook.
- **Ships:** multi-environment, SDK-key-gated delivery, webhooks, audit trail.

### Phase 4 — Polling delivery + OpenFeature SDK (L)

- **Polling config delivery** (chosen "simple edge" path): `GET /flags/config?env=…&since=<ver>` returns the
  server-SDK ruleset (or a `304`/empty diff if unchanged). A monotonic **config version** per project+env is
  bumped on publish (stored in KV + document), so SDKs cheaply poll for changes. Served through the 3-tier
  `CacheService` — memory-hot, KV-global, D1 source of truth.
- **OpenFeature provider** package (`@sonicjs-cms/openfeature-provider`): pulls `/flags/config`, evaluates
  **locally** with the shared evaluator (user attributes never leave the app), before/after/error/finally
  hooks, evaluation-details. Server + edge (Workers) flavors. This is the primary external-consumer surface.
- Client **bootstrap** helper: inject evaluated flags into SSR HTML (SonicJS renders server-side already) so
  browsers get flags with no extra round-trip and no client exposure of other users' targeting.
- Multi-context ("context kinds": user+org+device) in evaluator + `bucketBy` per kind.
- **Optional stretch (not critical path):** SSE streaming endpoint `GET /flags/stream` (Workers
  `ReadableStream`, fan-out on publish hook) for instant kill-switch propagation — layer on later if polling
  latency is too high.
- **Ships:** standards-based OpenFeature SDK, cheap versioned polling, edge/offline local evaluation.

### Phase 5 — Scheduling, approvals & progressive rollouts (L)

- **Scheduled changes**: a flag change document with `execute_at`; cron `onCronTick` applies due changes
  (`q_ff_execute_at` time-window query). Chained steps = **workflow** (ramp 5%→25%→50% over days).
- **Progressive/automatic rollouts**: cron advances rollout % on a cadence; halt/rollback if a guardrail
  metric breaches (ties into Phase 6).
- **Approval / change-request workflow**: draft edit requires N approvals before publish; reuse
  draft-vs-published axis + `document_permissions` + a `flag_change_request` type. Comments in audit log.
- **Stale-flag / tech-debt tooling**: "ready to archive" scoring (age, last-change, is-prerequisite);
  code-reference scanner CLI (`ld-find-code-refs` analogue) that greps consumer repos and reports usage.
- **Ships:** enterprise release-management: schedule, approve, auto-ramp, clean up.

### Phase 6 — Experimentation & analytics (XL, "highly complex")

- **Exposure events**: eval endpoint + SDK emit batched impression events → `flag_exposure` documents
  (or analytics plugin pipeline). Custom **metric events** endpoint.
- **A/B experiments** as a `flag_experiment` type: multivariate flag + randomization unit + primary/guardrail
  metrics. Assignment via existing bucketing (sticky). Exposure→metric join.
- **Stats engine**: frequentist (p-value/CI) + Bayesian (chance-to-win); variance reduction (**CUPED**),
  **sequential/anytime-valid** early stopping, **SRM** + sample-quality guards.
- **Holdouts** (global withheld slice) + **mutual-exclusion layers** (shared traffic allocation to prevent
  interaction effects). Results dashboard in admin.
- **Big/unbounded segments**: KV-backed membership for lists too large for the config payload; synced
  segments from an external CDP.
- **Ships:** LaunchDarkly/Statsig-parity experimentation platform.

### Cross-cutting (every phase)

- Escape all admin HTML with `escapeHtml` (R8). ACL-gate every mutation. Tenant-scope every query (R3).
- Count binds by hand on any raw INSERT (R5). Chunk to D1's 100-param / 100-column limits.
- Each phase adds ≥1 `*.sqlite.test.ts` (R10) + ≥1 Playwright spec (68+, tagged).

---

## Recommended MVP cut

**Phases 0 → 2** = a genuinely useful, shippable feature-flag system: document-model-native flags (project+env
aware), deterministic sticky targeting + % rollouts, a fast edge-cached public eval API **plus the in-process
`FlagService.isEnabled` gating API**, and a self-service admin with kill switches and change history. Phases
3→6 escalate to the "highly complex" terminal target: full project/env + SDK keys (3), OpenFeature SDK +
versioned polling (4), scheduling/approvals/progressive rollouts (5), and the A/B experimentation engine (6).

---

## Verification (per phase, when implemented)

- **Unit (cheap, exhaustive):** `evaluator.ts` + `bucketing.ts` are pure — full operator matrix, reason-code
  assertions, and a rollout-distribution test (10k synthetic contexts → variation split within tolerance;
  monotonicity: ramp % never de-buckets). `cd packages/core && npm test -- evaluator`.
- **Real-D1:** `flag-service.sqlite.test.ts` via `createTestD1()` + `applyScalarSchema('feature_flag', …)` —
  create/publish/read, `q_*` columns populated, facet segment rows, ACL public-read.
- **Type-check:** `cd packages/core && npm run type-check`.
- **E2E (write, don't run locally — CI validates):** `tests/e2e/68-feature-flags-admin.spec.ts` — login,
  create flag, toggle on, assert `/flags/evaluate/:key` returns the variation; edit+publish, assert change.
  Tag `@smoke @content`.
- **Manual smoke:** `cd my-sonicjs-app && npm run setup:db && npm run dev`, then
  `curl /flags/evaluate/<key>` with a context and confirm sticky/targeted result.

---

## Research appendix — sources

- **LaunchDarkly** — [flag types](https://launchdarkly.com/docs/home/flags/types) ·
  [context kinds](https://launchdarkly.com/docs/home/flags/context-kinds) ·
  [targeting rules](https://launchdarkly.com/docs/home/flags/target-rules) ·
  [flag-evaluation-rules (algorithm + reasons)](https://github.com/launchdarkly/LaunchDarkly-Docs/blob/main/src/content/topics/sdk/concepts/flag-evaluation-rules.mdx) ·
  [percentage rollouts](https://launchdarkly.com/docs/home/releases/percentage-rollouts) ·
  [flag salt](https://support.launchdarkly.com/hc/en-us/articles/36961986486811-How-to-update-the-flag-salt) ·
  [big segments](https://launchdarkly.com/docs/sdk/features/big-segments) ·
  [prerequisites](https://launchdarkly.com/docs/home/flags/prereqs) ·
  [scheduled changes](https://launchdarkly.com/docs/home/releases/scheduled-changes) ·
  [workflows](https://launchdarkly.com/docs/home/releases/workflows) ·
  [triggers](https://docs.launchdarkly.com/home/releases/triggers) ·
  [client vs server SDK](https://launchdarkly.com/docs/sdk/concepts/client-side-server-side) ·
  [relay proxy](https://launchdarkly.com/docs/sdk/relay-proxy/guidelines) ·
  [polling→streaming](https://launchdarkly.com/blog/launchdarklys-evolution-from-polling-to-streaming/) ·
  [SDK credentials](https://launchdarkly.com/docs/home/account/environment/keys) ·
  [REST API](https://launchdarkly.com/docs/api) ·
  [technical debt](https://launchdarkly.com/docs/guides/flags/technical-debt) ·
  [code references](https://launchdarkly.com/docs/home/flags/code-references)
- **OpenFeature** — [flag evaluation API](https://openfeature.dev/specification/sections/flag-evaluation/) ·
  [hooks](https://openfeature.dev/specification/sections/hooks/) ·
  [providers](https://openfeature.dev/specification/sections/providers/) ·
  [appendix A (reasons/errors)](https://openfeature.dev/specification/appendix-a/)
- **Unleash** — [activation strategies](https://docs.getunleash.io/concepts/activation-strategies) ·
  [stickiness](https://docs.getunleash.io/concepts/stickiness) ·
  [Hashing it Right (MurmurHash3)](https://www.getunleash.io/blog/hashing-it-right-solving-a-gradual-rollout-puzzle)
- **GrowthBook** — [JS SDK (hashing / sticky bucketing)](https://docs.growthbook.io/lib/js) ·
  [Hash module (fnv32a)](https://growthbook.hexdocs.pm/GrowthBook.Hash.html)
- **Statsig** — [gates vs experiments](https://docs.statsig.com/guides/featureflags-or-experiments) ·
  [conditions](https://docs.statsig.com/feature-flags/conditions) ·
  [layers](https://docs.statsig.com/experiments/layers-overview) ·
  [holdouts](https://docs.statsig.com/experiments/holdouts-introduction)
- **Optimizely** —
  [core concepts (MurmurHash3 + datafile)](https://support.optimizely.com/hc/en-us/articles/38931713970189-Core-concepts-of-Feature-Experimentation)
- **ConfigCat** — [percentage options](https://configcat.com/docs/targeting/percentage-options/) ·
  [evaluation](https://configcat.com/docs/targeting/feature-flag-evaluation/)
- **Split / Harness FME** —
  [treatments & targeting](https://help.split.io/hc/en-us/articles/360020791591-Define-feature-flag-treatments-and-targeting) ·
  [matcher types](https://docs.split.io/reference/matcher-type)
- **Flagsmith** — [architecture](https://github.com/Flagsmith/flagsmith) ·
  [open-source scope](https://www.flagsmith.com/open-source)
