# Demo App Plan — `demo.sonicjs.com`

**Goal:** A new in-repo Worker app that always runs the latest `main`, ships a few
example collections + sample content, prefills demo login credentials, and
**resets/reseeds its data on every promotion to main** so visitor edits never
persist past the next release.

**Branch:** `lane711/demo-app-seed-plan` · **Base:** `origin/main` · **PRs:** `gh pr create --base main`

---

## 1. What already exists (no rebuild needed)

| Capability | Where | Status |
|---|---|---|
| Credential autofill on login | `packages/core/src/templates/pages/auth-login.template.ts:139` (renders prefill JS) + `routes/auth.ts:84` (gate) | **Live** — gated on a `plugins` row `id='demo-login-prefill' AND status='active'` |
| Old hook-based demo plugin | `packages/core/src/plugins/core-plugins/demo-login/` (`demoLoginPlugin`, id `demo-login-plugin`) | **Dead** — relies on `template:render`/`page:before-render` hooks the login route never emits, AND id mismatches the gate (`demo-login-prefill`). Do not revive the hooks. |
| App skeleton to copy | `my-sonicjs-app/` (`src/index.ts`, `wrangler.toml`, `scripts/`, collections) | reference |
| Collection pattern | `my-sonicjs-app/src/collections/blog-posts.collection.ts` (`CollectionConfig`, `registerCollections([...])`) | reference |
| Doc write path | `DocumentsService.create/publish` (R1/R4-compliant) | reuse for seeding |
| Deploy-on-main CI model | `.github/workflows/deploy-www.yml` (push→main, paths filter, wrangler) | template for demo workflow |

**Key insight:** "bring back the demo plugin" = ensure the `plugins` row
`demo-login-prefill` / `active` exists in the demo DB. The template gate does the
rest. We will register a real, minimal plugin whose id matches the gate so it's
discoverable in the admin plugin list (not just a naked seed row).

---

## 2. Architecture decision

**New workspace `demo-app/`** (sibling of `my-sonicjs-app/`), added to root
`package.json` `workspaces`. It depends on the **workspace** core
(`"@sonicjs-cms/core": "file:../packages/core"`), so a deploy built from `main`
HEAD always runs the latest core — that is the "always update on each release"
guarantee (we redeploy on every push to main rather than chasing npm).

Rejected alternatives:
- Reusing `my-sonicjs-app` for demo → couples dev sandbox to a public site; different DB/secrets/reseed policy. No.
- Pinning `@sonicjs-cms/core@latest` from npm → lags publish; demo would trail main. No.

---

## 3. Deliverables

### 3.1 `demo-app/` workspace
```
demo-app/
  package.json            # name "demo-app", deps: file:../packages/core; scripts: deploy, seed:demo, setup:db
  wrangler.toml           # name=sonicjs-demo, custom_domain demo.sonicjs.com, own DB/R2/KV bindings
  tsconfig.json
  migrations/             # byte-identical copies of packages/core/migrations (R9) — 0001, 0002
  src/
    index.ts              # createSonicJSApp + registerCollections([...demo]) + demoSeedPlugin + demo-login plugin + scheduled handler
    collections/
      blog-posts.collection.ts
      pages.collection.ts
      testimonials.collection.ts
      faqs.collection.ts
    plugins/
      demo-seed/
        index.ts          # demoSeedPlugin: POST /__demo/reseed route + cron(0 */2 * * *) + onCronTick → runReseed
        reseed.ts         # runReseed(env): wipe-all → reseed collections → seed media → admin → demo-login row
      demo-login/
        index.ts          # plugin id 'demo-login-prefill' (matches auth.ts gate); activation upserts active row
    seed/
      content.ts          # sample docs per collection (titles/bodies)
      assets/             # bundled sample images as base64 TS modules
  scripts/
    seed-demo.ts          # local seed (getPlatformProxy) — dev parity, calls runReseed
```

### 3.2 Example collections (code-only, `registerCollections`)
A few, telling a CMS story:
- **Blog Posts** (`blog_post`) — reuse existing schema; 3–4 posts (mix published/draft).
- **Pages** (`page`) — Home / About / Contact; 3 published.
- **Testimonials** (`testimonial`) — name, role, quote, avatar?; 3–4 published.
- **FAQs** (`faq`) — question, answer, category; 4–5 published.

All `managed: true`, `access.public: ['read']` (non-PII → safe per R8/checklist §5).
`autoRegisterCollectionDocumentTypes` registers their `document_type` rows at boot.

### 3.3 Demo-login activation
- Add `demo-login` plugin registered in `demo-app/src/index.ts` config with **id `demo-login-prefill`** (matches the gate). Its `onActivate`/seed ensures the `plugins` row is `active`.
- Reseed step also upserts the `plugins` row (`id=demo-login-prefill`, `status=active`) defensively.
- Cleanup (separate small PR, optional): delete the dead `core-plugins/demo-login` hook plugin or fix its id; out of scope for v1.

### 3.4 Reseed-on-promotion + 2-hour cron  ← core requirement
Reseed logic factored into one shared `runReseed(env): Promise<Summary>` used by
**both** an HTTP endpoint (CI calls after deploy) **and** a cron (every 2h),
shipped as `demoSeedPlugin` mounted only in the demo app.

**`runReseed(env)` — FULL WIPE (Q2 resolved → wipe ALL):**
  1. Wipe **all** content for tenant `default`: `DELETE` from `document_facets`,
     `document_references`, `document_permissions`, then `documents`
     (R7 — delete derived rows explicitly, don't trust cascade). Not type-scoped —
     a pure demo, so nuke everything and rebuild.
  2. Purge the R2 media bucket prefix used by the demo (list + delete), so reseed
     media doesn't accumulate across runs.
  3. Reseed each demo collection via `DocumentsService.create` + `.publish`
     (correct versioning/facets/q_* — R1/R4/R6; never hand-write doc SQL — R4).
  4. **Seed media (images now):** upload bundled sample images to `MEDIA_BUCKET`,
     create `media_asset` documents via `MediaDocumentService.createFromUpload`
     (`MediaUploadMeta`: filename/mimeType/size/width/height/folder/r2Key/alt).
     Blog posts + testimonials reference these images (avatar / hero).
  5. Ensure admin user (`admin@sonicjs.com` / `sonicjs!`) — idempotent.
  6. Upsert `plugins` row `demo-login-prefill` = active.
  7. Return `{ wiped, created, media, ms }`.

**HTTP trigger:** `POST /__demo/reseed`, requires `Authorization: Bearer
${DEMO_SEED_TOKEN}`. **Hard-gated:** refuses unless `env.ENVIRONMENT === 'demo'`
(prevents accidental wipe if the plugin ever lands in a real install).

**Cron trigger (every 2 hours):** plugin declares
`crons: [{ schedule: '0 */2 * * *', hookFamily: 'demo-reseed' }]`; `onCronTick`
branches on `hookFamily` and calls `runReseed(ctx.env)`. Also env-gated to demo.
Requires `[triggers] crons = ["0 */2 * * *"]` in `wrangler.toml` (cron declared
in code is inert without the wrangler trigger — see email-reconciliation plugin).
This guarantees visitor edits reset at most 2h later even between deploys.

**Sample images:** bundle a handful of small images committed under
`demo-app/src/seed/assets/` as base64 modules (Workers can't read FS at runtime),
decode to `Uint8Array`, `MEDIA_BUCKET.put(r2Key, bytes)`. Keep them small (a few
KB each) to stay well under Worker memory + bundle limits.

Why an endpoint/cron through `DocumentsService` (not a SQL file or
`wrangler d1 execute`): document-model writes (versions, facets, refs, generated
`q_*` cols, derived `version_number`) are too error-prone to hand-author in SQL
(R5/R6). Running in the real Worker runtime also exercises D1's real
100-param/100-col limits and the R2 binding.

### 3.5 CI: `.github/workflows/deploy-demo.yml`
```
on:
  push: { branches: [main], paths: ['demo-app/**','packages/core/**','.github/workflows/deploy-demo.yml'] }
  workflow_dispatch:
steps:
  - checkout, setup-node 20, npm ci
  - npm run build:core
  - wrangler deploy (cwd demo-app)               # CLOUDFLARE_API_TOKEN/ACCOUNT_ID secrets
  - wrangler d1 migrations apply <demo-db> --remote
  - wait-for-health: poll https://demo.sonicjs.com/health until 200
  - curl -XPOST https://demo.sonicjs.com/__demo/reseed -H "Authorization: Bearer $DEMO_SEED_TOKEN"
```
`paths` includes `packages/core/**` so any core change on main redeploys+reseeds
the demo → "always latest".

### 3.6 Infra (one-time, manual or noted for operator)
- D1 `sonicjs-demo`, R2 `sonicjs-demo-media`, KV cache namespace — create + paste ids into `wrangler.toml`.
- Custom domain `demo.sonicjs.com` — **confirmed same CF account** (`f9d6328…`), so `routes = [{ pattern = "demo.sonicjs.com", custom_domain = true }]` works once zone DNS points in.
- `[triggers] crons = ["0 */2 * * *"]` — activates the 2-hour reseed cron.
- Secrets: `BETTER_AUTH_SECRET`, `DEMO_SEED_TOKEN` via `wrangler secret put` (and `DEMO_SEED_TOKEN` as a GH Actions secret).
- `[vars] ENVIRONMENT = "demo"`.

### 3.7 Tests
- **Integration (real SQLite, R10):** `demo-app` or core `*.integration.test.ts` for the reseed plugin — asserts wipe→reseed leaves exactly the expected published doc counts, demo-login row active, second run is idempotent.
- **E2E (R11, ≥68):** `tests/e2e/68-demo-login-prefill.spec.ts` — login page shows "Demo Mode" notice + prefilled email/password when the plugin row is active. (Write spec; CI runs it — do not run locally.)

---

## 4. Phased execution (after approval)

1. **Scaffold workspace** — `demo-app/` dir, `package.json`, `wrangler.toml` (with `[triggers] crons` + custom_domain + `ENVIRONMENT=demo`), `tsconfig`, migrations copy, root workspaces + scripts. Type-check. ← **starting now**
2. **Collections + index** — 4 collection configs, `registerCollections`, demo-login plugin (id `demo-login-prefill`) wired, scheduled handler exported.
3. **Reseed plugin** — `demoSeedPlugin`: `runReseed` (wipe-all + reseed + media + admin + demo-login row), HTTP route, 2h cron `onCronTick`, env gate. Sample-content + image-asset modules.
4. **Local seed script** — `scripts/seed-demo.ts` (getPlatformProxy → runReseed) for dev parity + `setup:db`.
5. **Tests** — reseed integration test (wipe→reseed counts, media docs, demo-login active, idempotent) + E2E 68 spec.
6. **CI workflow** — `deploy-demo.yml` (deploy → migrate → health-poll → curl reseed).
7. **Infra doc** — `demo-app/README.md` with the one-time CF setup checklist (§3.6).
8. **Review section** appended here.

Commit implementation + tests together (CLAUDE.md E2E workflow).

---

## 5. Risks / open questions

**Resolved:** Q1 collections = Blog/Pages/Testimonials/FAQs ✓ · Q2 reset = **wipe ALL** tenant `default` ✓ · R1 zone = **same CF account** ✓ · Media = **seed real images now** ✓ · Cron = **reseed every 2h** ✓

- **R-2 Reseed timing:** new deployment must be live before the post-deploy curl. Mitigated by health poll + retry; flag if `wrangler deploy` returns before propagation.
- **R-3 Demo-login id mismatch / dead plugin:** v1 uses id `demo-login-prefill` (matches `auth.ts` gate) + seeds the active row. The old `core-plugins/demo-login` hook plugin stays dead; deleting it is a later cleanup PR.
- **R-5 Plugins-table availability — CORRECTED:** the legacy `plugins` table does **not** exist on greenfield (only `0001`+`0002`; no `CREATE TABLE plugins` anywhere). The `auth.ts` demo-login gate was querying a non-existent table → always caught → prefill permanently dead. Fixed by repointing the gate at the **document-model** plugin status (`documents` `type_id='plugin'`, `data.status='active'`), which is what `PluginService.ensurePlugin`/`activatePlugin` actually write. Demo-login activation is now a public-API call — no vestigial table, doc-model aligned.
- **R-6 Cron + HTTP both wipe:** both go through one env-gated `runReseed`; double-fire (deploy curl + cron overlap) is harmless (idempotent rebuild) but log a run id to spot overlap.
- **R-7 Image assets in bundle:** base64 modules inflate the Worker bundle; keep total seed images tiny (target < ~100 KB combined) or move to R2-seeded-once + skip purge for a fixed set. Decide during phase 3.

---

## 6. Review

All 7 phases implemented. Core + demo-app type-check clean.

### Shipped
- **Phase 1 — workspace scaffold:** `demo-app/` workspace (`package.json`, `wrangler.toml` with custom_domain + `[triggers] crons` + `ENVIRONMENT=demo`, `tsconfig`, `.gitignore`, `.dev.vars.example`), migrations `0001`/`0002` copied byte-identical, root `workspaces` + `dev:demo`/`deploy:demo` scripts. `index.ts` boots core + exports `fetch`/`scheduled`.
- **Phase 2 — collections + demo-login:** 4 collections (`blog_post`, `page`, `testimonial`, `faq`) with `media` fields; `demo-login` plugin (id `demo-login-prefill`, env-gated self-activation via `PluginService`); **core gate fix** in `routes/auth.ts` (doc-model query — see R-5).
- **Phase 3 — reseed plugin:** `runReseed(env)` (wipe-all → R2 purge → ensure types → seed media to R2 + `media_asset` docs → seed 4 collections → re-activate demo-login). `demo-seed` plugin: token+env-gated `POST /__demo/reseed` + `0 */2 * * *` cron `onCronTick`. Both share `runReseed`.
- **Phase 4 — local seed:** `scripts/seed-demo.ts` (getPlatformProxy → `runReseed`), `seed:demo` script.
- **Phase 5 — tests:** `tests/e2e/82-demo-seed.spec.ts` (prefill, seeded API, reseed auth; skipped unless `DEMO_BASE_URL`).
- **Phase 6 — CI:** `.github/workflows/deploy-demo.yml` (push-to-main → build core → type-check → migrate → deploy → seed-admin → reseed, with health poll).
- **Phase 7 — docs:** `demo-app/README.md` (operator setup + how-it-works).

### Key design decisions
- **Images = SVG strings** (not binary base64) — tiny, diff-able, no decode; encoded to bytes → R2 → `media_asset` docs; referenced via `/files/demo-seed/<file>`. Resolves R-7 (combined assets ≈ few KB).
- **Wipe = all tenant-`default` documents** (incl. plugin docs), then re-assert demo-login. `document_types` + auth users survive.
- **Media path** reuses `MediaDocumentService.createFromUpload` — newly re-exported from core (`MediaDocumentService` + `MediaUploadMeta`) so the demo (a real consumer) doesn't duplicate media type/queryable logic.
- **`runReseed` self-ensures document types** (INSERT OR IGNORE) so it works on the cron path and in the local script without relying on bootstrap order.

### Core changes (outside demo-app)
- `packages/core/src/routes/auth.ts` — demo-login gate → document-model query (fixes a latent dead gate; affects all installs but only flips true where a `demo-login-prefill` plugin doc is active).
- `packages/core/src/index.ts` — re-export `MediaDocumentService` + `MediaUploadMeta`.

### Follow-ups / not done
- **Real-DB integration test for `runReseed`** (R10) — wants the `better-sqlite3` D1 shim + an R2 stub; the E2E (82) covers the live path. Recommended next.
- **Public demo front-end** — this ships the CMS + seeded data + admin; a themed public site rendering the collections is separate scope.
- Deleting the dead `core-plugins/demo-login` hook plugin (R-3) — later cleanup.
- Operator must fill `REPLACE_WITH_*` ids in `wrangler.toml` + set secrets before first deploy.
