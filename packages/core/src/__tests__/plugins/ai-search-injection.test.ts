import { describe, it, expect } from 'vitest'
import { AISearchService } from '../../plugins/core-plugins/ai-search-plugin/services/ai-search'
import type { SearchQuery } from '../../plugins/core-plugins/ai-search-plugin/types'

// Guards the keyword-search SQL builder against injection via `dateRange.field`
// (a column identifier that cannot be a bound `?`) and against unbounded page
// sizes. We capture every prepared SQL string + bind params and assert on them.

type Rec = { sql: string; params: unknown[] }

function makeCapturingDb(records: Rec[]) {
  return {
    prepare(sql: string) {
      const rec: Rec = { sql, params: [] }
      records.push(rec)
      const stmt: any = {
        bind: (...p: unknown[]) => { rec.params = p; return stmt },
        first: async () => (/count\(\*\)/i.test(sql) ? { count: 0 } : null),
        all: async () => ({ results: [] }),
        run: async () => ({}),
      }
      return stmt
    },
  } as any
}

const resultsQueryOf = (records: Rec[]) =>
  records.find((r) => /ORDER BY c\.updated_at DESC/.test(r.sql))

describe('ai-search keyword SQL builder @api-keys', () => {
  it('never interpolates an un-allowlisted dateRange.field into SQL', async () => {
    const records: Rec[] = []
    const service = new AISearchService(makeCapturingDb(records))
    const payload = "id) OR (SELECT 1 FROM auth_user) -- "
    const query: SearchQuery = {
      query: 'x',
      mode: 'keyword',
      filters: { dateRange: { field: payload, start: new Date('2020-01-01') } },
    } as any

    await service.search(query)

    const results = resultsQueryOf(records)
    expect(results).toBeDefined()
    // The injection payload must not appear anywhere in the generated SQL...
    for (const r of records) {
      expect(r.sql).not.toContain(payload)
      expect(r.sql).not.toContain('OR (SELECT')
    }
    // ...and the sink must fall back to the safe default column.
    expect(results!.sql).toContain('c.created_at >=')
  })

  it('preserves an allowlisted dateRange.field (updated_at)', async () => {
    const records: Rec[] = []
    const service = new AISearchService(makeCapturingDb(records))
    await service.search({
      query: 'x',
      mode: 'keyword',
      filters: { dateRange: { field: 'updated_at', end: new Date('2025-01-01') } },
    } as any)

    const results = resultsQueryOf(records)
    expect(results!.sql).toContain('c.updated_at <=')
  })

  it('clamps an oversized limit to the ceiling', async () => {
    const records: Rec[] = []
    const service = new AISearchService(makeCapturingDb(records))
    await service.search({ query: 'x', mode: 'keyword', limit: 999999, offset: -5 } as any)

    const results = resultsQueryOf(records)
    // results query binds [...searchParams, limit, offset] — the last two.
    const params = results!.params
    const [limit, offset] = params.slice(-2)
    expect(limit).toBe(100)
    expect(offset).toBe(0) // negative offset floored to 0
  })
})
