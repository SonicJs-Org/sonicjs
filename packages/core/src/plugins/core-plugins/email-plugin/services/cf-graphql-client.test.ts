import { describe, it, expect, vi } from 'vitest'
import { CfGraphqlClient } from './cf-graphql-client'
import { EmailValidationError } from '../errors'

function makeFetch(body: unknown, opts: { ok?: boolean; status?: number } = {}) {
  return vi.fn(async () => ({
    ok: opts.ok ?? true,
    status: opts.status ?? 200,
    statusText: 'OK',
    json: async () => body,
  })) as unknown as typeof fetch
}

// CF GraphQL response shape for emailSendingAdaptive — used by every test
// in this file as the well-known success envelope. The dataset is zone-scoped
// (not account-scoped — that was the schema mistake that broke reconciliation
// for two weeks; see PR #701 final resolution).
function envelope(rows: unknown[] = []) {
  return { data: { viewer: { zones: [{ emailSendingAdaptive: rows }] } } }
}

describe('CfGraphqlClient constructor', () => {
  it('throws EmailValidationError when zoneId is empty', () => {
    expect(() => new CfGraphqlClient('', 'token')).toThrow(EmailValidationError)
  })

  it('throws EmailValidationError when apiToken is empty', () => {
    expect(() => new CfGraphqlClient('zone-123', '')).toThrow(EmailValidationError)
  })
})

describe('CfGraphqlClient.queryEmailSends', () => {
  it('returns typed rows on a successful response', async () => {
    const rows = [
      { messageId: 'cf-1', status: 'delivered' as const },
      { messageId: 'cf-2', status: 'bounced' as const, errorCause: 'mailbox full' },
    ]
    const fetchImpl = makeFetch(envelope(rows))
    const client = new CfGraphqlClient('zone', 'tok', fetchImpl)

    const out = await client.queryEmailSends({ startSeconds: 1000, endSeconds: 2000 })

    expect(out).toEqual(rows)
  })

  it('returns empty array when GraphQL returns no rows', async () => {
    const fetchImpl = makeFetch(envelope())
    const client = new CfGraphqlClient('zone', 'tok', fetchImpl)
    expect(await client.queryEmailSends({ startSeconds: 0, endSeconds: 1 })).toEqual([])
  })

  it('throws on HTTP non-2xx', async () => {
    const fetchImpl = makeFetch({}, { ok: false, status: 401 })
    const client = new CfGraphqlClient('zone', 'tok', fetchImpl)
    await expect(client.queryEmailSends({ startSeconds: 0, endSeconds: 1 })).rejects.toThrow(/HTTP 401/)
  })

  it('throws on GraphQL-level errors', async () => {
    const fetchImpl = makeFetch({ errors: [{ message: 'unauthorized' }] })
    const client = new CfGraphqlClient('zone', 'tok', fetchImpl)
    await expect(client.queryEmailSends({ startSeconds: 0, endSeconds: 1 })).rejects.toThrow(/unauthorized/)
  })

  it('sends bearer token and zone tag in the request', async () => {
    const fetchImpl = makeFetch(envelope())
    const client = new CfGraphqlClient('the-zone', 'the-token', fetchImpl)
    await client.queryEmailSends({ startSeconds: 1, endSeconds: 2 })

    const [, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer the-token')
    const body = JSON.parse(init.body as string) as { variables: { zoneTag: string } }
    expect(body.variables.zoneTag).toBe('the-zone')
  })

  it('targets zones.emailSendingAdaptive (not accounts.emailSendingAdaptive) — regression guard for issue #701', async () => {
    // The hub spec originally specified `accounts.emailSendingAdaptive`, which
    // does not exist in CF's GraphQL schema (verified by live introspection
    // 2026-05-22). The correct dataset is the zone-scoped variant at the same
    // field name: `zones.emailSendingAdaptive`. This test pins the query path
    // and the variable name so a future "looks like it should be account-
    // scoped" misread can't regress us — only the parent (zones vs accounts)
    // matters; the dataset field name itself is `emailSendingAdaptive` under
    // either parent (CF uses the field name with a different parent-type
    // namespace, not a different field name).
    const fetchImpl = makeFetch(envelope())
    const client = new CfGraphqlClient('z', 't', fetchImpl)
    await client.queryEmailSends({ startSeconds: 1, endSeconds: 2 })

    const [, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit]
    const body = JSON.parse(init.body as string) as { query: string; variables: Record<string, unknown> }

    expect(body.query).toMatch(/zones\(filter:\s*\{\s*zoneTag:\s*\$zoneTag\s*\}\)/)
    expect(body.query).toMatch(/emailSendingAdaptive\b/)
    expect(body.query).not.toMatch(/accounts\(filter:/)
    expect(body.variables).toHaveProperty('zoneTag')
    expect(body.variables).not.toHaveProperty('accountTag')
  })

  it('uses spec-compliant GraphQL scalar names (capitalized String/Int) — regression guard for issue #701', async () => {
    const fetchImpl = makeFetch(envelope())
    const client = new CfGraphqlClient('zone', 'tok', fetchImpl)
    await client.queryEmailSends({ startSeconds: 1, endSeconds: 2 })

    const [, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit]
    const body = JSON.parse(init.body as string) as { query: string }

    // Builtin GraphQL scalars are case-sensitive per spec. Lowercase `string!`/`int!`
    // is invalid and CF's endpoint rejects the entire query — which broke reconciliation
    // silently from PR #584 (2026-05-13) until #701 (2026-05-22). Asserting the literal
    // capitalized forms catches regressions the mocked-response tests above cannot.
    expect(body.query).toMatch(/\$zoneTag:\s*String!/)
    expect(body.query).toMatch(/\$limit:\s*Int!/)
    expect(body.query).not.toMatch(/:\s*string!/)
    expect(body.query).not.toMatch(/:\s*int!/)
  })

  it('default fetchImpl invokes the global fetch via closure (issue #701 — no Illegal invocation)', async () => {
    // Regression guard: bare `fetchImpl: typeof fetch = fetch` stored on `this`
    // makes Workers' V8 throw `Illegal invocation` because globalThis.fetch's
    // receiver check fails when called as `this.fetchImpl(...)`. The fix wraps
    // fetch in an arrow function so the closure preserves the global binding.
    // This test simulates the failure by installing a global fetch that throws
    // when invoked with the wrong receiver (mirrors V8 behavior).
    const origFetch = globalThis.fetch
    const globalFetchMock = vi.fn(async function (this: unknown, _input: unknown, _init?: unknown) {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError('Illegal invocation: function called with incorrect `this` reference.')
      }
      return new Response(JSON.stringify(envelope()), { status: 200 })
    }) as unknown as typeof fetch
    globalThis.fetch = globalFetchMock

    // No fetchImpl injected — exercises the default arrow wrapper.
    const client = new CfGraphqlClient('zone', 'tok')
    await expect(client.queryEmailSends({ startSeconds: 0, endSeconds: 1 })).resolves.toEqual([])
    expect(globalFetchMock).toHaveBeenCalledTimes(1)

    globalThis.fetch = origFetch
  })
})
