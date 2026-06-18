/**
 * Cache Warming Tests
 *
 * Tests for cache preloading and warming utilities
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import {
  warmCommonCaches,
  warmNamespace,
  preloadCache,
  schedulePeriodicWarming
} from '../services/cache-warming.js'
import { clearAllCaches } from '../services/cache.js'

// Mock D1Database
const createMockDb = (
  collectionsData: any[] = [],
  contentData: any[] = [],
  mediaData: any[] = []
) => {
  const rowsFor = (sql: string) => {
    if (sql.includes('collections')) return collectionsData
    // Media SQL: `type_id = 'media_asset'`. Content SQL: `type_id != 'media_asset'`.
    if (sql.includes(`type_id = 'media_asset'`) || sql.includes(' media ')) return mediaData
    if (sql.includes('documents') || sql.includes('content')) return contentData
    return []
  }
  return {
    prepare: vi.fn().mockImplementation((sql: string) => {
      const all = vi.fn().mockResolvedValue({ results: rowsFor(sql) })
      const stmt: any = { all, bind: vi.fn() }
      stmt.bind.mockReturnValue(stmt)
      return stmt
    })
  } as unknown as D1Database
}

describe('Cache Warming', () => {
  beforeEach(async () => {
    await clearAllCaches()
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('warmCommonCaches', () => {
    it('should warm collections, content, and media caches', async () => {
      const mockCollections = [
        { id: 'col-1', name: 'posts', is_active: 1 },
        { id: 'col-2', name: 'pages', is_active: 1 }
      ]
      const mockContent = [
        { id: 'content-1', title: 'Post 1', created_at: '2024-01-01' },
        { id: 'content-2', title: 'Post 2', created_at: '2024-01-02' }
      ]
      const mockMedia = [
        { id: 'media-1', filename: 'image1.jpg', uploaded_at: '2024-01-01' }
      ]

      const db = createMockDb(mockCollections, mockContent, mockMedia)

      const result = await warmCommonCaches(db)

      expect(result.warmed).toBeGreaterThan(0)
      expect(result.errors).toBe(0)
      expect(result.details).toHaveLength(3)

      // Check namespace counts
      const collectionDetail = result.details.find(d => d.namespace === 'collection')
      const contentDetail = result.details.find(d => d.namespace === 'content')
      const mediaDetail = result.details.find(d => d.namespace === 'media')

      expect(collectionDetail).toBeDefined()
      expect(contentDetail).toBeDefined()
      expect(mediaDetail).toBeDefined()

      // Collections come from the in-memory registry (not DB) — count depends on registry state.
      expect(collectionDetail?.count).toBeGreaterThanOrEqual(1) // at least the list entry
      // Each content item + list = 3 entries
      expect(contentDetail?.count).toBe(3) // 2 items + 1 list
      // Each media item + list = 2 entries
      expect(mediaDetail?.count).toBe(2) // 1 item + 1 list
    })

    it('should handle empty database results', async () => {
      const db = createMockDb([], [], [])

      const result = await warmCommonCaches(db)

      // Even with empty results, the list cache entry is created for each namespace
      // Collections: 0 items + 1 list = 1
      // Content: 0 items + 1 list = 1
      // Media: 0 items + 1 list = 1
      expect(result.warmed).toBe(3)
      expect(result.errors).toBe(0)
      expect(result.details).toHaveLength(3)

      // Each namespace should have 1 entry (the list)
      for (const detail of result.details) {
        expect(detail.count).toBe(1)
      }
    })

    it('should handle database errors gracefully', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const db = {
        prepare: vi.fn().mockImplementation(() => {
          const stmt: any = {
            all: vi.fn().mockRejectedValue(new Error('Database error')),
            bind: vi.fn()
          }
          stmt.bind.mockReturnValue(stmt)
          return stmt
        })
      } as unknown as D1Database

      const result = await warmCommonCaches(db)

      // Errors are caught per-namespace, so no top-level error is recorded
      // Each warming function catches its own errors
      expect(result.errors).toBe(0)
      // Content + media warming touch the DB; collections warming uses the in-memory registry.
      expect(consoleSpy).toHaveBeenCalledWith('Error warming content cache:', expect.any(Error))
      expect(consoleSpy).toHaveBeenCalledWith('Error warming media cache:', expect.any(Error))

      consoleSpy.mockRestore()
    })

    it('should handle individual cache warming errors', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      // First call succeeds (collections), second fails (content), third succeeds (media)
      let callCount = 0
      const db = {
        prepare: vi.fn().mockImplementation((sql: string) => {
          callCount++
          const stmt: any = { bind: vi.fn() }
          if (sql.includes(`type_id = 'media_asset'`) || sql.includes(' media ')) {
            stmt.all = vi.fn().mockResolvedValue({ results: [] })
          } else if (sql.includes('documents') || sql.includes('content')) {
            stmt.all = vi.fn().mockRejectedValue(new Error('Content error'))
          } else {
            stmt.all = vi.fn().mockResolvedValue({
              results: sql.includes('collections') ? [{ id: 'col-1', name: 'posts' }] : []
            })
          }
          stmt.bind.mockReturnValue(stmt)
          return stmt
        })
      } as unknown as D1Database

      const result = await warmCommonCaches(db)

      // Should still have warmed collections
      expect(result.details.find(d => d.namespace === 'collection')?.count).toBeGreaterThan(0)
      // Content should be 0 due to error
      expect(result.details.find(d => d.namespace === 'content')?.count).toBe(0)

      consoleSpy.mockRestore()
    })
  })

  describe('warmNamespace', () => {
    it('should warm a specific namespace with custom data', async () => {
      const entries = [
        { key: 'key1', value: 'value1' },
        { key: 'key2', value: 'value2' },
        { key: 'key3', value: { nested: true } }
      ]

      const count = await warmNamespace('content', entries)

      expect(count).toBe(3)
    })

    it('should throw error for unknown namespace', async () => {
      const entries = [{ key: 'key1', value: 'value1' }]

      await expect(warmNamespace('unknown-namespace', entries)).rejects.toThrow('Unknown namespace: unknown-namespace')
    })

    it('should handle empty entries array', async () => {
      const count = await warmNamespace('content', [])

      expect(count).toBe(0)
    })

    it('should warm config namespace', async () => {
      const entries = [
        { key: 'setting1', value: { enabled: true } },
        { key: 'setting2', value: { theme: 'dark' } }
      ]

      const count = await warmNamespace('config', entries)

      expect(count).toBe(2)
    })

    it('should warm user namespace', async () => {
      const entries = [
        { key: 'user-1', value: { id: '1', name: 'John' } }
      ]

      const count = await warmNamespace('user', entries)

      expect(count).toBe(1)
    })

    it('should warm media namespace', async () => {
      const entries = [
        { key: 'media-1', value: { id: '1', filename: 'test.jpg' } }
      ]

      const count = await warmNamespace('media', entries)

      expect(count).toBe(1)
    })
  })

  describe('preloadCache', () => {
    it('should preload cache and log results', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      const mockCollections = [{ id: 'col-1', name: 'posts' }]
      const db = createMockDb(mockCollections, [], [])

      await preloadCache(db)

      expect(consoleSpy).toHaveBeenCalledWith('🔥 Preloading cache...')
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('✅ Cache preloaded:')
      )

      consoleSpy.mockRestore()
    })

    it('should log errors during preloading', async () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const db = {
        prepare: vi.fn().mockImplementation(() => {
          const stmt: any = {
            all: vi.fn().mockRejectedValue(new Error('Database error')),
            bind: vi.fn()
          }
          stmt.bind.mockReturnValue(stmt)
          return stmt
        })
      } as unknown as D1Database

      await preloadCache(db)

      expect(logSpy).toHaveBeenCalledWith('🔥 Preloading cache...')
      // Content + media warming touch the DB; collections warming uses the in-memory registry.
      expect(errorSpy).toHaveBeenCalledWith('Error warming content cache:', expect.any(Error))

      logSpy.mockRestore()
      errorSpy.mockRestore()
    })

    it('should log individual namespace details', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      const mockCollections = [
        { id: 'col-1', name: 'posts' },
        { id: 'col-2', name: 'pages' }
      ]
      const db = createMockDb(mockCollections, [], [])

      await preloadCache(db)

      // Should log each namespace detail
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringMatching(/- collection: \d+ entries/)
      )
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringMatching(/- content: \d+ entries/)
      )
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringMatching(/- media: \d+ entries/)
      )

      consoleSpy.mockRestore()
    })
  })

  describe('schedulePeriodicWarming', () => {
    it('should schedule periodic cache warming', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      vi.useFakeTimers()

      const db = createMockDb([], [], [])
      const intervalMs = 60000 // 1 minute

      const timer = schedulePeriodicWarming(db, intervalMs)

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Scheduling periodic cache warming')
      )
      expect(timer).toBeDefined()

      // Clean up
      clearInterval(timer)
      vi.useRealTimers()
      consoleSpy.mockRestore()
    })

    it('should use default interval of 5 minutes', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      vi.useFakeTimers()

      const db = createMockDb([], [], [])

      const timer = schedulePeriodicWarming(db)

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('300s') // 300000ms / 1000 = 300s
      )

      // Clean up
      clearInterval(timer)
      vi.useRealTimers()
      consoleSpy.mockRestore()
    })

    it('should execute warming on interval', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      vi.useFakeTimers()

      const db = createMockDb([{ id: 'col-1', name: 'posts' }], [], [])
      const intervalMs = 1000 // 1 second for testing

      const timer = schedulePeriodicWarming(db, intervalMs)

      // Fast-forward past one interval
      await vi.advanceTimersByTimeAsync(1100)

      expect(consoleSpy).toHaveBeenCalledWith('🔄 Running periodic cache warming...')

      // Clean up
      clearInterval(timer)
      vi.useRealTimers()
      consoleSpy.mockRestore()
    })

    it('should handle errors during periodic warming', async () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      vi.useFakeTimers()

      const db = {
        prepare: vi.fn().mockImplementation(() => {
          const stmt: any = {
            all: vi.fn().mockRejectedValue(new Error('Periodic error')),
            bind: vi.fn()
          }
          stmt.bind.mockReturnValue(stmt)
          return stmt
        })
      } as unknown as D1Database

      const timer = schedulePeriodicWarming(db, 1000)

      // Fast-forward past one interval
      await vi.advanceTimersByTimeAsync(1100)

      // Errors are caught per-namespace within warmCommonCaches
      expect(errorSpy).toHaveBeenCalledWith(
        'Error warming content cache:',
        expect.any(Error)
      )

      // Clean up
      clearInterval(timer)
      vi.useRealTimers()
      logSpy.mockRestore()
      errorSpy.mockRestore()
    })

    it('should run multiple warming cycles', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      vi.useFakeTimers()

      const db = createMockDb([], [], [])
      const intervalMs = 1000

      const timer = schedulePeriodicWarming(db, intervalMs)

      // Fast-forward past three intervals
      await vi.advanceTimersByTimeAsync(3100)

      // Count how many times the warming message was logged
      const warmingCalls = consoleSpy.mock.calls.filter(
        call => call[0] === '🔄 Running periodic cache warming...'
      )
      expect(warmingCalls.length).toBe(3)

      // Clean up
      clearInterval(timer)
      vi.useRealTimers()
      consoleSpy.mockRestore()
    })
  })
})
