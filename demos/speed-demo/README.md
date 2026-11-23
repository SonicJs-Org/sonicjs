# SonicJS Speed Demo

A live employee directory demo showcasing SonicJS edge-caching performance. Compares raw origin latency against SonicJS's KV-cached responses in real time.

**Live:** [employee-directory.sonicjs.com](https://employee-directory.sonicjs.com)

## What it shows

| Stat | Description |
|---|---|
| **Origin** | Baseline DB fetch time (1,429 ms avg) |
| **SonicJS** | Live response time from the edge cache |
| **Boost** | Speed multiplier (`Origin / SonicJS`) |

The stats bar updates on every fetch. Toggle **Edge Cache off** in the UI to force a live DB hit and see the difference.

## Stack

- **Frontend:** React + Vite + Tailwind CSS, deployed to Cloudflare Pages via [`sonicjs-client-directory`](https://edgecache-demo.pages.dev)
- **Backend:** SonicJS CMS worker (`sonicjs-client-backend`) at [`employee-directory-backend.sonicjs.com`](https://employee-directory-backend.sonicjs.com), sharing the `sonicjs-demo` D1 database with its own isolated KV cache namespace for independent tuning
- **SDK:** [`@sonicjs-cms/sdk`](../../packages/sdk) — the same SDK your app would use

## Local development

```bash
# From the repo root — build the SDK first
npm run build:core

# Then start the dev server (proxies /api through to the live backend)
cd demos/speed-demo
VITE_DEV_BACKEND=https://employee-directory-backend.sonicjs.com \
VITE_CMS_URL=http://localhost:5173 \
npm run dev
```

The Vite proxy forwards `/api/*` and `/v1/*` requests to the live backend, so there are no CORS issues and no local worker needed.

To run a fully local backend instead:

```bash
# In one terminal — start the SonicJS worker
cd my-sonicjs-app
npx wrangler dev --config wrangler.client-backend.toml --port 8787

# Apply local D1 migrations (first time only)
npx wrangler d1 migrations apply DB --local --config wrangler.client-backend.toml

# Seed local data (first time only)
npx tsx scripts/seed-employees-demo.ts

# In another terminal — start the frontend
cd demos/speed-demo
VITE_CMS_URL=http://localhost:8787 npm run dev
```

## Deployment

Automatically deployed on every push to `main` that touches `demos/speed-demo/**` or `packages/sdk/src/**` via `.github/workflows/deploy-demo.yml`.

The backend (`sonicjs-client-backend`) is deployed separately via `.github/workflows/deploy-client-backend-cms.yml` on changes to `packages/core/**` or `my-sonicjs-app/**`.

## Tuning the cache

Edit `my-sonicjs-app/wrangler.client-backend.toml` to adjust KV TTLs and caching behaviour. The KV namespace (`fa15ce6927af43af9149e926631d7ad5`) is isolated from `demo.sonicjs.com`, so changes here don't affect the main demo.
