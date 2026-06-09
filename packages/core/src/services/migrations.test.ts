/**
 * Migration Service Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { MigrationService } from './migrations'

// Mock D1Database with configurable responses
function createMockDb(options: {
  appliedMigrations?: Array<{ name: string; applied_at: string }>;
  existingTables?: string[];
  existingColumns?: Array<{ table: string; column: string }>;
} = {}) {
  const {
    appliedMigrations = [],
    existingTables = [],
    existingColumns = []
  } = options

  const mockRun = vi.fn().mockResolvedValue({ success: true })
  const mockFirst = vi.fn()
  const mockAll = vi.fn()
  const mockBind = vi.fn()

  // Track queries to respond appropriately
  let lastQuery = ''

  const chainable = {
    bind: (...args: any[]) => {
      mockBind(...args)
      // For table existence checks
      if (lastQuery.includes('sqlite_master')) {
        const tableName = args[0]
        return {
          first: vi.fn().mockResolvedValue(
            existingTables.includes(tableName) ? { name: tableName } : null
          ),
          all: mockAll,
          run: mockRun,
          bind: chainable.bind
        }
      }
      // For column existence checks
      if (lastQuery.includes('pragma_table_info')) {
        const [table, column] = args
        const exists = existingColumns.some(c => c.table === table && c.column === column)
        return {
          first: vi.fn().mockResolvedValue(exists ? { name: column } : null),
          all: mockAll,
          run: mockRun,
          bind: chainable.bind
        }
      }
      // For D1 migration table queries
      if (lastQuery.includes('SELECT name, applied_at FROM d1_migrations')) {
        return {
          first: mockFirst,
          all: vi.fn().mockResolvedValue({ results: appliedMigrations }),
          run: mockRun,
          bind: chainable.bind
        }
      }
      return {
        first: mockFirst,
        all: mockAll,
        run: mockRun,
        bind: chainable.bind
      }
    },
    first: mockFirst,
    all: vi.fn().mockResolvedValue({ results: appliedMigrations }),
    run: mockRun
  }

  const mockPrepare = vi.fn((query: string) => {
    lastQuery = query
    // For SELECT from D1 migrations (applied migrations list)
    if (query.includes('SELECT name, applied_at FROM d1_migrations')) {
      return {
        all: vi.fn().mockResolvedValue({ results: appliedMigrations }),
        bind: chainable.bind,
        first: mockFirst,
        run: mockRun
      }
    }
    return chainable
  })

  return {
    prepare: mockPrepare,
    _mocks: { prepare: mockPrepare, bind: mockBind, first: mockFirst, all: mockAll, run: mockRun }
  }
}

describe('MigrationService', () => {
  describe('consolidated greenfield migrations', () => {
    it('exposes only the greenfield core migrations', async () => {
      const db = createMockDb({
        appliedMigrations: []
      })

      const service = new MigrationService(db as any)
      const migrations = await service.getAvailableMigrations()

      expect(migrations.map(m => m.id)).toEqual(['0001', '0002'])
      expect(migrations.find(m => m.id === '029')).toBeUndefined()
      expect(db._mocks.prepare).not.toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS migrations'))
    })
  })

  describe('runPendingMigrations', () => {
    it('should direct callers to Wrangler instead of running migrations in-app', async () => {
      const db = createMockDb({
        appliedMigrations: [],
        existingTables: ['users', 'documents', 'document_types'],
        existingColumns: []
      })

      const service = new MigrationService(db as any)
      const result = await service.runPendingMigrations()

      expect(result).toHaveProperty('errors')
      expect(Array.isArray(result.errors)).toBe(true)
      expect(result.success).toBe(false)
      expect(result.message).toContain('wrangler d1 migrations apply')
      expect(db._mocks.prepare).not.toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS migrations'))
    })

    it('should read applied migrations from d1_migrations', async () => {
      const db = createMockDb({
        appliedMigrations: [
          { name: '0001_core.sql', applied_at: '2026-01-01T00:00:00.000Z' },
          { name: '0002_documents.sql', applied_at: '2026-01-01T00:00:01.000Z' }
        ],
        existingTables: ['users', 'documents', 'document_types'],
        existingColumns: []
      })

      const service = new MigrationService(db as any)
      const status = await service.getMigrationStatus()

      expect(status.appliedMigrations).toBe(2)
      expect(status.pendingMigrations).toBe(0)
      expect(status.lastApplied).toBe('2026-01-01T00:00:01.000Z')
    })
  })
})
