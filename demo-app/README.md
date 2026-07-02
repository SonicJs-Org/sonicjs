# SonicJS Demo App — demo.sonicjs.com

The public demo. It **always runs the latest `main`** and **resets its data on
every deploy and every 2 hours**, so visitors can freely edit content, upload
media, and explore the admin without permanently changing anything.

## What it includes

- **4 example collections** (code-defined, no DB tables): `blog_post`, `page`,
  `testimonial`, `faq`.
- **Sample content + images** — seeded blog posts, pages, testimonials, FAQs,
  and SVG media assets uploaded to R2.
- **Demo-login prefill** — the login page is pre-filled with
  `admin@sonicjs.com` / `sonicjs!` (the `demo-login` plugin, gated to this app).
- **Reset machinery** — the `demo-seed` plugin exposes `POST /__demo/reseed`
  and a `0 */2 * * *` cron; both run the same `runReseed` (full wipe + rebuild).

## How the reset works

`runReseed(env)` (`src/plugins/demo-seed/reseed.ts`):

1. Counts, then deletes **every** document for tenant `default` plus its derived
   facet / reference / permission rows.
2. Purges the `demo-seed/` prefix in R2.
3. Upserts the seed document types (defensive FK guard).
4. Uploads the bundled SVG images to R2 and registers `media_asset` documents.
5. Recreates the 4 collections' sample content (published-on-create).
6. Re-activates the demo-login prefill.

`document_types` and Better-Auth users are **not** documents, so they survive a
reset — the admin user is seeded once at deploy time via `/auth/seed-admin`.

Both triggers are **hard-gated to `ENVIRONMENT === 'demo'`**; the HTTP route also
requires `Authorization: Bearer $DEMO_SEED_TOKEN`. This app can never wipe a
non-demo install.

## One-time Cloudflare setup (operator)

Provision the dedicated resources and paste their ids into `wrangler.toml`
(placeholders marked `REPLACE_WITH_...`):

```bash
cd demo-app

# D1
npx wrangler d1 create sonicjs-demo
# → paste database_id into [[d1_databases]]

# R2
npx wrangler r2 bucket create sonicjs-demo-media

# KV
npx wrangler kv namespace create sonicjs-demo-cache
# → paste id into [[kv_namespaces]]

# Secrets
openssl rand -hex 32 | npx wrangler secret put BETTER_AUTH_SECRET
npx wrangler secret put DEMO_SEED_TOKEN     # random token; also add as a GH Actions secret
```

DNS: point `demo.sonicjs.com` at this worker (the `sonicjs.com` zone is on the
same Cloudflare account, so the `custom_domain` route in `wrangler.toml` binds
directly).

GitHub Actions secrets required by `.github/workflows/deploy-demo.yml`:
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `DEMO_SEED_TOKEN`.

## Local development

```bash
# from repo root — build core first (the demo imports @sonicjs-cms/core)
npm run build:core

cd demo-app
cp .dev.vars.example .dev.vars      # set BETTER_AUTH_SECRET + DEMO_SEED_TOKEN
npm run db:migrate:local            # apply 0001 + 0002 to local D1
npm run seed:demo                   # full wipe + reseed local data (same runReseed)
npm run dev                         # wrangler dev
```

## Deploy

Automatic on every push to `main` (see `.github/workflows/deploy-demo.yml`):
build core → type-check → migrate → deploy → seed admin → reseed.

Manual:

```bash
npm run deploy:demo                 # from repo root (builds core, deploys demo-app)
# then, against the live site:
curl -X POST https://demo.sonicjs.com/__demo/reseed \
  -H "Authorization: Bearer $DEMO_SEED_TOKEN"
```

## E2E

`tests/e2e/82-demo-seed.spec.ts` — runs only when `DEMO_BASE_URL` is set
(skipped in the normal suite). Validates credential prefill, seeded public
content, and reseed-endpoint auth.
