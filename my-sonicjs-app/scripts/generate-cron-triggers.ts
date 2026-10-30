#!/usr/bin/env npx tsx
/**
 * Generate [triggers] crons in wrangler.toml from plugin cron declarations.
 *
 * Run this script whenever you add or remove plugin crons, then commit the
 * updated wrangler.toml. A CI test in packages/core will fail if the committed
 * triggers don't match the declared plugin crons.
 *
 * Usage:
 *   npx tsx scripts/generate-cron-triggers.ts
 *   npx tsx scripts/generate-cron-triggers.ts --check  # CI mode: fail if outdated
 */

import { readFileSync, writeFileSync } from 'fs'
import { resolve } from 'path'
import { parseCronTriggers, updateWranglerTriggers } from '../../packages/core/src/plugins/generate-triggers'

// ── Plugin list ───────────────────────────────────────────────────────────────
// Import your app's plugins here and list any that declare `crons[]`.
// (The reference app has no plugin crons yet — add them here as you create them.)
const allPlugins: Array<{ name?: string; crons?: Array<{ schedule: string }> }> = [
  // e.g. emailReconciliationPlugin,
]

// ─────────────────────────────────────────────────────────────────────────────

const schedules = [...new Set(allPlugins.flatMap((p) => p.crons ?? []).map((c) => c.schedule))].sort()

// Support wrangler.toml, wrangler.jsonc, or wrangler.json
import { existsSync } from 'fs'
const candidates = ['wrangler.toml', 'wrangler.jsonc', 'wrangler.json']
const wranglerPath = candidates.map(f => resolve(__dirname, '..', f)).find(p => existsSync(p))
if (!wranglerPath) {
  console.error('[cron-triggers] No wrangler config found (wrangler.toml / wrangler.jsonc / wrangler.json)')
  process.exit(1)
}
if (!wranglerPath.endsWith('.toml')) {
  console.error('[cron-triggers] wrangler.jsonc/json detected — cron trigger codegen only supports wrangler.toml. Skipping.')
  process.exit(0)
}
const current = readFileSync(wranglerPath, 'utf8')

const isCheck = process.argv.includes('--check')

if (isCheck) {
  const committed = parseCronTriggers(current)
  const matches =
    JSON.stringify(committed) === JSON.stringify(schedules)
  if (!matches) {
    console.error(
      '[cron-triggers] wrangler.toml triggers are out of sync.\n' +
        `  Committed: ${JSON.stringify(committed)}\n` +
        `  Expected:  ${JSON.stringify(schedules)}\n` +
        `  Run: npx tsx scripts/generate-cron-triggers.ts`
    )
    process.exit(1)
  }
  console.log('[cron-triggers] wrangler.toml triggers are up to date.')
  process.exit(0)
}

const updated = updateWranglerTriggers(current, schedules)
writeFileSync(wranglerPath, updated, 'utf8')
console.log(
  schedules.length > 0
    ? `[cron-triggers] Updated wrangler.toml with ${schedules.length} cron(s): ${schedules.join(', ')}`
    : '[cron-triggers] No plugin crons declared — [triggers] section cleared.'
)
