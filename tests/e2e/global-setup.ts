import { request } from '@playwright/test'
import type { FullConfig } from '@playwright/test'

/** Fail once before tests cascade. Never reset a database or retry a seed mutation. */
export async function prepareEnvironment(baseURL: string): Promise<void> {
  if (process.env.E2E_DISPOSABLE_TARGET !== '1' && !process.env.CI) {
    throw new Error('E2E setup refused: set E2E_DISPOSABLE_TARGET=1 only for an owned disposable environment')
  }
  const client = await request.newContext({ baseURL, timeout: 15_000, extraHTTPHeaders: { Origin: new URL(baseURL).origin } })
  const started = Date.now()
  try {
    for (const endpoint of ['/auth/seed-admin', '/test-seed-defaults']) {
      const res = await client.post(endpoint)
      if (!res.ok()) throw new Error(`E2E setup ${endpoint}: HTTP ${res.status()}`)
      const body = await res.json()
      if (body.success === false || body.error) throw new Error(`E2E setup ${endpoint}: application rejected seed`)
    }
    const signedIn = await client.post('/auth/sign-in/email', {
      data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
    })
    if (!signedIn.ok()) throw new Error(`E2E setup sign-in: HTTP ${signedIn.status()}`)
    const session = await client.get('/auth/get-session')
    if (!session.ok() || (await session.json()).user?.email !== 'admin@sonicjs.com') {
      throw new Error('E2E setup: admin session not established (check credentials, 2FA and seed state)')
    }
    const migrations = await client.get('/admin/api/migrations/status')
    if (!migrations.ok()) throw new Error(`E2E setup migrations: HTTP ${migrations.status()}`)
    const status = await migrations.json()
    if (status.success !== true || status.data?.pendingMigrations !== 0) {
      throw new Error('E2E setup: migrations are unavailable or pending; apply checkout migrations first')
    }
    const admin = await client.get('/admin/content', { maxRedirects: 0 })
    if (admin.status() !== 200 || !(await admin.text()).includes('content')) {
      throw new Error(`E2E setup authenticated content page: HTTP ${admin.status()}`)
    }
    process.env.E2E_ADMIN_SEEDED = '1'
    console.log(`E2E authenticated seed/schema readiness: ${Date.now() - started}ms`)
  } finally {
    await client.dispose()
  }
}

/**
 * Playwright global setup: seeds the admin DB and verifies readiness before any test runs.
 * In sharded CI the setup job calls `prepareEnvironment` once; shard jobs set
 * `E2E_ADMIN_SEEDED=1` so this function skips the seed while still enforcing the
 * disposable-target safety guard.
 */
export default async function globalSetup(config: FullConfig): Promise<void> {
  // In sharded CI runs, the setup job already ran e2e-readiness.ts which calls
  // prepareEnvironment once before all shards start. Skip the seed mutations here to
  // avoid concurrent seed calls on the same DB. Set E2E_ADMIN_SEEDED=1 in shard job env.
  // The disposable-target guard still runs on the skip path so a stale local E2E_ADMIN_SEEDED
  // cannot bypass the safety check against a non-disposable environment.
  if (process.env.E2E_ADMIN_SEEDED === '1') {
    if (process.env.E2E_DISPOSABLE_TARGET !== '1' && !process.env.CI) {
      throw new Error('E2E setup refused: set E2E_DISPOSABLE_TARGET=1 only for an owned disposable environment')
    }
    console.log('E2E global setup: skipping seed (E2E_ADMIN_SEEDED=1 — already seeded by CI setup job)')
    return
  }
  const baseURL = config.projects[0]?.use.baseURL
  if (!baseURL) throw new Error('E2E setup requires baseURL')
  await prepareEnvironment(baseURL)
}
