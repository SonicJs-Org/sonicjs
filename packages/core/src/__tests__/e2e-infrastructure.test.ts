import { mkdtempSync, readFileSync, writeFileSync, rmSync, utimesSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { acquireTestLock, uniqueTestId } from '../../../../tests/e2e/utils/test-runtime'
import { prepareEnvironment } from '../../../../tests/e2e/global-setup'
import { describe, expect, it, vi } from 'vitest'
import { submitAndWaitForDocument, submitAndWaitForXhr } from '../../../../tests/e2e/utils/test-helpers'
import type { Page } from '@playwright/test'

function response(status: number, url = 'http://localhost:8787/admin/content/one') {
  return { ok: () => status >= 200 && status < 300, status: () => status,
    url: () => url, finished: vi.fn(async () => null),
    request: () => ({ method: () => 'PUT', resourceType: () => 'xhr' }) }
}

describe('E2E synchronization contracts', () => {
  it('matches the exact endpoint rather than a substring and completes the response', async () => {
    const res = response(200)
    const waitForResponse = vi.fn(async (predicate: (r: unknown) => boolean) => {
      expect(predicate(response(200, 'http://localhost:8787/admin/content/one-other'))).toBe(false)
      expect(predicate(res)).toBe(true)
      return res
    })
    const page = { url: () => 'http://localhost:8787/admin', waitForResponse } as unknown as Page
    const click = vi.fn(async () => { expect(waitForResponse).toHaveBeenCalledTimes(1) })
    await submitAndWaitForXhr(page, 'PUT', '/admin/content/one', click)
    expect(click).toHaveBeenCalledTimes(1)
    expect(res.finished).toHaveBeenCalledTimes(1)
  })

  it('propagates a failed response without replaying the mutation', async () => {
    const res = response(500)
    const click = vi.fn(async () => {})
    const page = { url: () => 'http://localhost:8787/admin', waitForResponse: async () => res } as unknown as Page
    await expect(submitAndWaitForXhr(page, 'PUT', '/admin/content/one', click)).rejects.toThrow('500')
    expect(click).toHaveBeenCalledTimes(1)
  })

  it('rejects a failed redirect document instead of treating it as readiness', async () => {
    const res = response(500)
    const page = { url: () => 'http://localhost:8787/admin', waitForResponse: async () => res, waitForLoadState: vi.fn(async () => {}) } as unknown as Page
    await expect(submitAndWaitForDocument(page, '/admin/content', async () => {})).rejects.toThrow('500')
  })

  it('refuses setup without disposable-target consent before contacting the server', async () => {
    vi.stubEnv('E2E_DISPOSABLE_TARGET', '')
    vi.stubEnv('CI', '')
    try { await expect(prepareEnvironment('http://127.0.0.1:1')).rejects.toThrow('refused') }
    finally { vi.unstubAllEnvs() }
  })

  it('allocates unique identities even with a frozen clock', () => {
    vi.spyOn(Date, 'now').mockReturnValue(1)
    try {
      const ids = Array.from({ length: 10_000 }, () => uniqueTestId())
      expect(new Set(ids).size).toBe(ids.length)
      expect(ids[0]).toMatch(/^e2e-[a-f0-9-]{36}$/)
    } finally { vi.restoreAllMocks() }
  })

  it('does not steal an old but live lock, and allows reuse after release', async () => {
    const root = mkdtempSync(join(tmpdir(), 'sonicjs-lock-test-'))
    try {
      const release = await acquireTestLock(root, 'settings')
      utimesSync(join(root, 'settings'), new Date(0), new Date(0))
      await expect(acquireTestLock(root, 'settings', { timeoutMs: 10, pollMs: 1 })).rejects.toThrow('Timed out')
      release()
      release() // Idempotent release must not delete a future owner's lock.
      const next = await acquireTestLock(root, 'settings')
      next()
    } finally { rmSync(root, { recursive: true, force: true }) }
  })

  it('never releases a replacement owner lock', async () => {
    const root = mkdtempSync(join(tmpdir(), 'sonicjs-lock-test-'))
    try {
      const release = await acquireTestLock(root, 'settings')
      const path = join(root, 'settings', 'owner.json')
      writeFileSync(path, JSON.stringify({ token: 'replacement', pid: process.pid }))
      expect(release).toThrow('Ownership lost')
      expect(JSON.parse(readFileSync(path, 'utf8')).token).toBe('replacement')
    } finally { rmSync(root, { recursive: true, force: true }) }
  })
})
