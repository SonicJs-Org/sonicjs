import { describe, it, expect, vi } from 'vitest'
import {
  ReconciliationService,
  mapGraphQLStatusToDeliveryState,
} from './reconciliation'
import type { CfGraphqlClient } from './cf-graphql-client'
import type { EmailLogService } from './email-log.service'
import type { GraphQLActivityLogRow } from '../types'

function makeGraphql(rows: GraphQLActivityLogRow[] | Error): CfGraphqlClient {
  return {
    queryEmailSends: vi.fn(async () => {
      if (rows instanceof Error) throw rows
      return rows
    }),
  } as unknown as CfGraphqlClient
}

function makeLog(): EmailLogService & { calls: unknown[] } {
  const calls: unknown[] = []
  const svc = {
    calls,
    updateDeliveryState: vi.fn(async (input: unknown) => {
      calls.push(input)
    }),
  }
  return svc as unknown as EmailLogService & { calls: unknown[] }
}

describe('mapGraphQLStatusToDeliveryState', () => {
  it('maps each GraphQL status to its delivery_state', () => {
    expect(mapGraphQLStatusToDeliveryState('delivered')).toBe('delivered')
    expect(mapGraphQLStatusToDeliveryState('deliveryFailed')).toBe('delivery_failed')
    expect(mapGraphQLStatusToDeliveryState('bounced')).toBe('bounced')
    expect(mapGraphQLStatusToDeliveryState('rejected')).toBe('rejected')
  })
})

describe('ReconciliationService.run', () => {
  it('returns no_rows when GraphQL returns empty', async () => {
    const out = await new ReconciliationService(makeGraphql([]), makeLog()).run()
    expect(out.status).toBe('no_rows')
    expect(out.updatedRowCount).toBe(0)
  })

  it('updates one row per GraphQL row and returns ok', async () => {
    const rows: GraphQLActivityLogRow[] = [
      { messageId: 'cf-1', status: 'delivered' },
      { messageId: 'cf-2', status: 'bounced', errorCause: 'mailbox full' },
    ]
    const log = makeLog()
    const out = await new ReconciliationService(makeGraphql(rows), log).run({
      windowHours: 24,
      now: 1700000000000,
    })
    expect(out.status).toBe('ok')
    expect(out.graphqlRowCount).toBe(2)
    expect(out.updatedRowCount).toBe(2)
    expect(log.calls[0]).toMatchObject({
      cloudflareMessageId: 'cf-1',
      deliveryState: 'delivered',
      syncedAt: 1700000000000,
    })
    expect(log.calls[1]).toMatchObject({
      cloudflareMessageId: 'cf-2',
      deliveryState: 'bounced',
      errorMessage: 'mailbox full',
    })
  })

  it('returns graphql_error and zero updates when query throws', async () => {
    const out = await new ReconciliationService(
      makeGraphql(new Error('graphql down')),
      makeLog(),
    ).run()
    expect(out.status).toBe('graphql_error')
    expect(out.error).toBe('graphql down')
    expect(out.updatedRowCount).toBe(0)
  })

  it('continues past a single failed row update (per-row failure not fatal)', async () => {
    const rows: GraphQLActivityLogRow[] = [
      { messageId: 'cf-bad', status: 'delivered' },
      { messageId: 'cf-good', status: 'delivered' },
    ]
    const log = makeLog()
    let call = 0
    log.updateDeliveryState = vi.fn(async () => {
      call++
      if (call === 1) throw new Error('row 1 fail')
    })

    const out = await new ReconciliationService(makeGraphql(rows), log).run()
    expect(out.status).toBe('ok')
    expect(out.graphqlRowCount).toBe(2)
    expect(out.updatedRowCount).toBe(1) // only the second one succeeded
  })

  it('computes startSeconds = now - windowHours and endSeconds = now', async () => {
    const queryEmailSends = vi.fn(async () => [] as GraphQLActivityLogRow[])
    const graphql = { queryEmailSends } as unknown as CfGraphqlClient
    await new ReconciliationService(graphql, makeLog()).run({ windowHours: 1, now: 1_700_000_000_000 })
    expect(queryEmailSends).toHaveBeenCalledWith({
      startSeconds: 1_700_000_000_000 / 1000 - 60 * 60,
      endSeconds: 1_700_000_000_000 / 1000,
    })
  })
})
