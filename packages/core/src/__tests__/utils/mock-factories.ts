/**
 * Shared author mock harness (T4.5)
 *
 * A single importable module of typed mock primitives for plugin authors writing
 * unit / integration tests. Previously 5+ inline fakes existed across the test
 * suite with varying shapes. This module normalises them into one place.
 *
 * Usage in a plugin test:
 *
 *   import { makeMockD1Database, makeMockHookSystem } from '@sonicjs-cms/core/test-utils'
 *   // (or relative path: '../../__tests__/utils/mock-factories')
 */

import { HookSystemImpl } from '../../plugins/hook-system'
import type { EmailService } from '../../services/email/email-service'
import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../../services/email/types'

// ── D1 database mock ──────────────────────────────────────────────────────────

export interface MockD1Row {
  [column: string]: unknown
}

export interface MockD1Options {
  /**
   * Data to return from `.first()` and `.all()` calls. `prepare(sql)` looks up
   * `sql` as a key; if no entry matches, returns null / empty results.
   */
  rows?: MockD1Row | MockD1Row[] | null
  /**
   * If provided, use this function to look up rows given the SQL (gives tests
   * more control than a static map).
   */
  resolver?: (sql: string, args: unknown[]) => MockD1Row | MockD1Row[] | null
}

/**
 * A minimal D1-shaped mock. Covers `prepare().bind().first()`,
 * `prepare().bind().all()`, `prepare().bind().run()`, and `batch()`.
 *
 * All operations succeed silently unless you pass a `resolver` or `rows`.
 */
export function makeMockD1Database(options: MockD1Options = {}) {
  const resolve = (sql: string, args: unknown[]) => {
    if (options.resolver) return options.resolver(sql, args)
    return options.rows ?? null
  }

  const makeStatement = (sql: string) => ({
    bind: (...args: unknown[]) => ({
      first: async <T = MockD1Row>() => {
        const data = resolve(sql, args)
        if (Array.isArray(data)) return (data[0] ?? null) as T | null
        return (data ?? null) as T | null
      },
      all: async <T = MockD1Row>() => {
        const data = resolve(sql, args)
        const results = Array.isArray(data) ? data : data ? [data] : []
        return { results: results as T[], success: true }
      },
      run: async () => ({ success: true, meta: {} }),
    }),
    first: async <T = MockD1Row>() => {
      const data = resolve(sql, [])
      if (Array.isArray(data)) return (data[0] ?? null) as T | null
      return (data ?? null) as T | null
    },
    all: async <T = MockD1Row>() => {
      const data = resolve(sql, [])
      const results = Array.isArray(data) ? data : data ? [data] : []
      return { results: results as T[], success: true }
    },
    run: async () => ({ success: true, meta: {} }),
  })

  return {
    prepare: (sql: string) => makeStatement(sql),
    batch: async (stmts: unknown[]) => stmts.map(() => ({ success: true, results: [] })),
    exec: async (_sql: string) => ({ count: 0, duration: 0 }),
  }
}

// ── KV namespace mock ─────────────────────────────────────────────────────────

/**
 * A minimal KVNamespace-shaped mock that stores data in memory.
 * Supports `get`, `put`, `delete`, and `list`.
 */
export function makeMockKVNamespace() {
  const store = new Map<string, { value: string; expiration?: number }>()

  return {
    async get(key: string): Promise<string | null> {
      const entry = store.get(key)
      if (!entry) return null
      if (entry.expiration && entry.expiration < Date.now() / 1000) {
        store.delete(key)
        return null
      }
      return entry.value
    },
    async getWithMetadata(key: string): Promise<{ value: string | null; metadata: unknown }> {
      return { value: await this.get(key), metadata: null }
    },
    async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
      store.set(key, {
        value,
        expiration: options?.expirationTtl ? Date.now() / 1000 + options.expirationTtl : undefined,
      })
    },
    async delete(key: string): Promise<void> {
      store.delete(key)
    },
    async list(options?: { prefix?: string }): Promise<{ keys: Array<{ name: string }> }> {
      const keys = [...store.keys()]
        .filter((k) => !options?.prefix || k.startsWith(options.prefix))
        .map((name) => ({ name }))
      return { keys }
    },
  }
}

// ── Hono context mock ─────────────────────────────────────────────────────────

export interface MockHonoContextOptions {
  env?: Record<string, unknown>
  /** Variables set on the context (c.get / c.set). */
  vars?: Record<string, unknown>
  /** URL for the fake request. Defaults to 'http://localhost/'. */
  url?: string
  method?: string
}

/**
 * A minimal Hono-context-shaped mock for route handler unit tests.
 * Covers `c.env`, `c.get()`, `c.set()`, `c.json()`, `c.html()`, `c.redirect()`,
 * and `c.req.{query,header,param,json,formData}`.
 */
export function makeMockHonoContext(options: MockHonoContextOptions = {}) {
  const vars: Record<string, unknown> = { ...(options.vars ?? {}) }
  let responseStatus = 200
  let responseBody: unknown = null

  const ctx = {
    env: options.env ?? {},
    executionCtx: { waitUntil: (_p: Promise<unknown>) => {} },
    req: {
      url: options.url ?? 'http://localhost/',
      method: options.method ?? 'GET',
      query: (key?: string) => (key ? '' : {}),
      header: (_key: string) => undefined as string | undefined,
      param: (_key: string) => '' as string,
      json: async () => ({} as Record<string, unknown>),
      formData: async () => new FormData(),
    },
    get: (key: string) => vars[key],
    set: (key: string, value: unknown) => { vars[key] = value },
    json: (body: unknown, status = 200) => {
      responseStatus = status
      responseBody = body
      return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
    },
    html: (body: string, status = 200) => {
      responseStatus = status
      responseBody = body
      return new Response(body, { status, headers: { 'Content-Type': 'text/html' } })
    },
    text: (body: string, status = 200) => {
      responseStatus = status
      responseBody = body
      return new Response(body, { status })
    },
    redirect: (url: string, status = 302) => {
      responseStatus = status
      responseBody = url
      return new Response(null, { status, headers: { Location: url } })
    },
    /** Inspect what the handler responded with. */
    _response: { get status() { return responseStatus }, get body() { return responseBody } },
  }

  return ctx
}

// ── Email service mock ────────────────────────────────────────────────────────

export interface SentEmail {
  to: string[]
  subject: string
  flow?: string
  html?: string
  text?: string
}

/**
 * A recording EmailProvider that captures every send in `.sent`.
 * Pass it to `createSonicJSApp({ email: { provider: recordingEmailProvider() } })`.
 */
export function makeMockEmailProvider(): EmailProvider & { sent: SentEmail[] } {
  return {
    name: 'mock',
    sent: [] as SentEmail[],
    isConfigured: () => true,
    async send(message: NormalizedEmailMessage): Promise<SendResult> {
      ;(this as any).sent.push({
        to: message.to,
        subject: message.subject,
        flow: message.flow,
        html: message.html,
        text: message.text,
      })
      return { ok: true, provider: 'mock', providerId: `mock-${(this as any).sent.length}` }
    },
  }
}

// ── Hook system mock ──────────────────────────────────────────────────────────

/**
 * A real (not mocked) `HookSystemImpl` instance, ready to use in tests.
 * Prefer this over `vi.fn()` stubs so hook ordering and dispatch semantics
 * are real — the thing being tested is the plugin behavior, not the mock.
 */
export function makeMockHookSystem() {
  return new HookSystemImpl()
}
