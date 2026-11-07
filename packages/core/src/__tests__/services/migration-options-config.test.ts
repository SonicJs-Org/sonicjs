import { describe, expect, it, vi } from 'vitest'
import type { Bindings, SonicJSConfig } from '../../app'

// Bootstrap owns schema/seed work, independent of application config propagation.
// Stop only that work; exercise the real factory and its request middleware.
vi.mock('../../middleware/bootstrap', async importOriginal => ({
  ...await importOriginal<typeof import('../../middleware/bootstrap')>(),
  bootstrapMiddleware: () => async (_c: unknown, next: () => Promise<void>) => next(),
}))

import { createSonicJSApp } from '../../app'

/** Create an app exposing its captured migration options before authentication. */
function configuredApp(migrations?: SonicJSConfig['migrations']) {
  return createSonicJSApp({
    migrations,
    plugins: { disableAll: true },
    middleware: {
      beforeAuth: [async c => { c.res = c.json({ options: c.get('migrationOptions') ?? null }) }],
    },
  })
}

describe('Application migration configuration', () => {
  it('rejects invalid identifiers at app creation, before a request or SQL execution', () => {
    expect(() => configuredApp({ tableName: 'ledger; DROP TABLE documents' })).toThrow(/migration.*table/i)
  })

  it('copies each app configuration and exposes it on the request context', async () => {
    const options = { tableName: 'custom_migration_history' }
    const custom = configuredApp(options)
    const standard = configuredApp()
    options.tableName = 'changed_after_app_creation'
    const env = {} as Bindings
    expect(await (await custom.request('/migration-options', {}, env)).json()).toEqual({ options: { tableName: 'custom_migration_history' } })
    expect(await (await standard.request('/migration-options', {}, env)).json()).toEqual({ options: { tableName: 'd1_migrations' } })
    expect(await (await custom.request('/migration-options', {}, env)).json()).toEqual({ options: { tableName: 'custom_migration_history' } })
  })
})
