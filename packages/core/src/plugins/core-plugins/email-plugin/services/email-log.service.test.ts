import { describe, it, expect, vi } from 'vitest'
import { EmailLogService } from './email-log.service'

interface CapturedCall {
  sql: string
  binds: unknown[]
}

function makeDb(captured: CapturedCall[], listResults: unknown[] = []): D1Database {
  return {
    prepare: vi.fn((sql: string) => ({
      bind: vi.fn((...binds: unknown[]) => ({
        run: vi.fn(async () => {
          captured.push({ sql, binds })
          return {}
        }),
        all: vi.fn(async () => {
          captured.push({ sql, binds })
          return { results: listResults }
        }),
        first: vi.fn(async () => {
          captured.push({ sql, binds })
          return null
        }),
      })),
      // For queries that call .first() directly without .bind()
      first: vi.fn(async () => {
        captured.push({ sql, binds: [] })
        return null
      }),
      all: vi.fn(async () => {
        captured.push({ sql, binds: [] })
        return { results: listResults }
      }),
    })),
  } as unknown as D1Database
}

// Extended mock for getStats() which calls .first() on two statements via Promise.all
function makeStatsDb(
  captured: CapturedCall[],
  statsRow: { total: number; failed: number; submitted: number; delivered: number } | null,
  lastTestedRow: { last_tested: number | null } | null,
): D1Database {
  let firstCallIndex = 0
  const firstResults = [statsRow, lastTestedRow]
  return {
    prepare: vi.fn((sql: string) => ({
      bind: vi.fn((...binds: unknown[]) => ({
        run: vi.fn(async () => { captured.push({ sql, binds }); return {} }),
        all: vi.fn(async () => ({ results: [] })),
        first: vi.fn(async () => {
          captured.push({ sql, binds })
          return firstResults[firstCallIndex++] ?? null
        }),
      })),
      first: vi.fn(async () => {
        captured.push({ sql, binds: [] })
        return firstResults[firstCallIndex++] ?? null
      }),
      all: vi.fn(async () => ({ results: [] })),
    })),
  } as unknown as D1Database
}

describe('EmailLogService.insertOnSubmit', () => {
  it('writes a submitted row with the right column values', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.insertOnSubmit({
      id: 'log-1',
      cloudflareMessageId: 'cf-1',
      recipient: 'rec@example.com',
      sender: 'from@example.com',
      subject: 's',
      purpose: 'otp',
      templateName: 'auth.otp',
      templateVariablesJson: '{"code":"123"}',
      userId: 'u-1',
      sentAt: 1700000000000,
    })
    expect(captured).toHaveLength(1)
    expect(captured[0]?.sql).toMatch(/INSERT INTO email_log/i)
    expect(captured[0]?.sql).toMatch(/'submitted'/)
    expect(captured[0]?.binds).toEqual([
      'log-1', 'cf-1', 'rec@example.com', 'from@example.com', 's',
      'otp', 'auth.otp', '{"code":"123"}',
      'u-1', null, null, null,
      1700000000000,
    ])
  })

  it('coerces omitted optional fields to NULL bindings', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.insertOnSubmit({
      id: 'log-1', cloudflareMessageId: 'cf-1',
      recipient: 'r@e.c', sender: 's@e.c', subject: 's', purpose: 'p',
      sentAt: 0,
    })
    expect(captured[0]?.binds).toContain(null)
    // template_name, template_variables_json, user_id, context_type, context_id, tenant_id all NULL
    const nulls = captured[0]?.binds.filter(b => b === null) ?? []
    expect(nulls.length).toBe(6)
  })
})

describe('EmailLogService.insertOnFailedAtSend', () => {
  it('writes failed_at_send with NULL cloudflare_message_id', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.insertOnFailedAtSend({
      id: 'log-2',
      recipient: 'r@e.c', sender: 's@e.c', subject: 's', purpose: 'p',
      sentAt: 0,
      errorCode: 'E1', errorMessage: 'transport down',
    })
    expect(captured[0]?.sql).toMatch(/NULL/)
    expect(captured[0]?.sql).toMatch(/'failed_at_send'/)
    expect(captured[0]?.binds).toContain('E1')
    expect(captured[0]?.binds).toContain('transport down')
  })
})

describe('EmailLogService.updateDeliveryState', () => {
  it('updates only rows where delivery_synced_at IS NULL (idempotency filter)', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.updateDeliveryState({
      cloudflareMessageId: 'cf-1',
      deliveryState: 'delivered',
      syncedAt: 1700000000000,
    })
    expect(captured[0]?.sql).toMatch(/UPDATE email_log/i)
    expect(captured[0]?.sql).toMatch(/delivery_synced_at IS NULL/)
    expect(captured[0]?.binds).toEqual(['delivered', 1700000000000, null, 'cf-1'])
  })
})

describe('EmailLogService.list', () => {
  it('returns rows from the result.results array', async () => {
    const rows = [{ id: 'log-1', recipient: 'r@e.c' }]
    const svc = new EmailLogService(makeDb([], rows))
    const out = await svc.list({ limit: 50 })
    expect(out).toEqual(rows)
  })
})

describe('EmailLogService.listFiltered', () => {
  it('status=delivered maps to delivery_state = delivered, NOT status = delivered', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.listFiltered({ limit: 50, offset: 0, status: 'delivered' })
    const sqls = captured.map(c => c.sql)
    expect(sqls.some(s => s.includes("delivery_state = 'delivered'"))).toBe(true)
    expect(sqls.some(s => /WHERE status = ['"]delivered['"]/.test(s))).toBe(false)
  })

  it('status=bounced maps to delivery_state = bounced', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.listFiltered({ limit: 50, offset: 0, status: 'bounced' })
    const sqls = captured.map(c => c.sql)
    expect(sqls.some(s => s.includes("delivery_state = 'bounced'"))).toBe(true)
  })

  it('status=submitted maps to status = submitted AND delivery_state IS NULL', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.listFiltered({ limit: 50, offset: 0, status: 'submitted' })
    const sqls = captured.map(c => c.sql)
    expect(sqls.some(s => s.includes("status = 'submitted' AND delivery_state IS NULL"))).toBe(true)
  })

  it('status=failed_at_send maps to status = failed_at_send', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.listFiltered({ limit: 50, offset: 0, status: 'failed_at_send' })
    const sqls = captured.map(c => c.sql)
    expect(sqls.some(s => s.includes("status = 'failed_at_send'"))).toBe(true)
  })

  it('purpose filter adds WHERE purpose = ? clause and binds the value', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.listFiltered({ limit: 50, offset: 0, purpose: 'test' })
    const sqls = captured.map(c => c.sql)
    expect(sqls.some(s => s.includes('purpose = ?'))).toBe(true)
    expect(captured.some(c => c.binds.includes('test'))).toBe(true)
  })

  it('search uses LIKE on both recipient and subject via OR', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    await svc.listFiltered({ limit: 50, offset: 0, search: 'marco' })
    const sqls = captured.map(c => c.sql)
    expect(sqls.some(s => s.includes('recipient LIKE') && s.includes('subject LIKE'))).toBe(true)
    // search term bound twice (once for recipient, once for subject)
    expect(captured.some(c => c.binds.filter(b => b === 'marco').length === 2)).toBe(true)
  })

  it('timeRangeMs is computed as Date.now() - windowMs inside the service (caller does not supply a timestamp)', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(makeDb(captured))
    const before = Date.now()
    await svc.listFiltered({ limit: 50, offset: 0, timeRangeMs: 86_400_000 })
    const after = Date.now()
    const sqls = captured.map(c => c.sql)
    expect(sqls.some(s => s.includes('sent_at >= ?'))).toBe(true)
    // Bound threshold should be within [before - 86_400_000, after - 86_400_000]
    const thresholdBind = captured
      .flatMap(c => c.binds)
      .find(b => typeof b === 'number' && b > before - 86_400_000 - 1000 && b <= after - 86_400_000 + 1000)
    expect(thresholdBind).toBeDefined()
  })

  it('returns both rows and total from separate COUNT query', async () => {
    const rows = [{ id: 'log-1' }]
    const svc = new EmailLogService(makeDb([], rows))
    const result = await svc.listFiltered({ limit: 50, offset: 0 })
    expect(result).toHaveProperty('rows')
    expect(result).toHaveProperty('total')
    expect(Array.isArray(result.rows)).toBe(true)
    expect(typeof result.total).toBe('number')
  })
})

describe('EmailLogService.getStats', () => {
  it('returns correct shape with service-computed threshold; caller only passes windowMs', async () => {
    const captured: CapturedCall[] = []
    const svc = new EmailLogService(
      makeStatsDb(
        captured,
        { total: 10, failed: 2, submitted: 5, delivered: 3 },
        { last_tested: 1700000000000 },
      ),
    )
    const stats = await svc.getStats(86_400_000)
    expect(stats.last24hTotal).toBe(10)
    expect(stats.last24hFailed).toBe(2)
    expect(stats.last24hSubmitted).toBe(5)
    expect(stats.last24hDelivered).toBe(3)
    expect(stats.lastTestedAt).toBe(1700000000000)
    // The threshold must be bound; caller never touches Date.now()
    const thresholdBind = captured.flatMap(c => c.binds).find(b => typeof b === 'number')
    expect(thresholdBind).toBeDefined()
    expect(Number(thresholdBind)).toBeGreaterThan(Date.now() - 86_400_000 - 5000)
  })
})

describe('EmailLogService.getDistinctPurposes', () => {
  it('returns [] on empty table', async () => {
    const svc = new EmailLogService(makeDb([], []))
    const purposes = await svc.getDistinctPurposes()
    expect(purposes).toEqual([])
  })

  it('returns sorted string array when rows exist', async () => {
    const rows = [{ purpose: 'otp' }, { purpose: 'pw_reset' }]
    const svc = new EmailLogService(makeDb([], rows))
    const purposes = await svc.getDistinctPurposes()
    expect(purposes).toEqual(['otp', 'pw_reset'])
  })
})
