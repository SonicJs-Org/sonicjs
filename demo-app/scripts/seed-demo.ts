/**
 * Local demo seed — dev parity with POST /__demo/reseed.
 *
 * Uses wrangler's platform proxy to get the local D1 + R2 bindings, then runs
 * the exact same `runReseed` the deploy workflow and cron use. Idempotent
 * (full wipe + rebuild).
 *
 * Run from demo-app/:
 *   npm run seed:demo
 *   # or: npx tsx scripts/seed-demo.ts
 *
 * Requires the local DB to be migrated first (npm run db:migrate:local).
 */

import { getPlatformProxy } from 'wrangler'
import { runReseed, type DemoEnv } from '../src/plugins/demo-seed/reseed'

async function main() {
  const { env, dispose } = await getPlatformProxy()
  const demoEnv = env as unknown as DemoEnv

  if (!demoEnv.DB) {
    console.error('DB binding not found. Run `npm run db:migrate:local` and check wrangler.toml.')
    await dispose()
    process.exit(1)
  }
  if (!demoEnv.MEDIA_BUCKET) {
    console.error('MEDIA_BUCKET binding not found. Check wrangler.toml.')
    await dispose()
    process.exit(1)
  }

  try {
    console.log('Reseeding demo data (full wipe + rebuild)...')
    const summary = await runReseed(demoEnv)
    console.log('Done:', summary)
  } catch (error) {
    console.error('Seed failed:', error)
    await dispose()
    process.exit(1)
  }

  await dispose()
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Seed failed:', error)
    process.exit(1)
  })
