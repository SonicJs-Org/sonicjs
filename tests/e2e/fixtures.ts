import { test as base } from '@playwright/test'
import type { APIRequestContext, Browser, BrowserContext, Page } from '@playwright/test'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { acquireTestLock, uniqueTestId } from './utils/test-runtime'
import { prepareLocalRequest } from './utils/local-client'
import { cacheVendorAssets } from './utils/vendor-cache'

export * from '@playwright/test'
export { uniqueTestId } from './utils/test-runtime'

const HARDENED = Symbol('sonicjs.e2e.page')
const HARDENED_CONTEXT = Symbol('sonicjs.e2e.context')

/** Default to parsed document; readiness belongs to locator assertions.
 * Explicit waitUntil/timeout contracts are never downgraded, swallowed, or retried.
 * Reload may resubmit a POST, so must not be replayed automatically. */
function preparePage(page: Page, headers?: Record<string, string>): Page {
  prepareLocalRequest(page.request, process.env.BASE_URL || 'http://localhost:8787', base.info().file, headers)
  const marked = page as unknown as Record<symbol, boolean>
  if (marked[HARDENED]) return page
  marked[HARDENED] = true
  const goto = page.goto.bind(page)
  const reload = page.reload.bind(page)
  page.goto = (url, options) => goto(url, { waitUntil: 'domcontentloaded', ...options })
  page.reload = options => reload({ waitUntil: 'domcontentloaded', ...options })
  return page
}

async function prepareContext(context: BrowserContext, headers?: Record<string, string>, vendorClient?: APIRequestContext): Promise<BrowserContext> {
  prepareLocalRequest(context.request, process.env.BASE_URL || 'http://localhost:8787', base.info().file, headers)
  await cacheVendorAssets(context, process.env.BASE_URL || 'http://localhost:8787', vendorClient)
  const marked = context as unknown as Record<symbol, boolean>
  if (marked[HARDENED_CONTEXT]) return context
  marked[HARDENED_CONTEXT] = true
  const newPage = context.newPage.bind(context)
  context.newPage = async () => preparePage(await newPage(), headers)
  return context
}

// Same-host processes targeting the same deployment share the namespace.
// NOT cross-runner coordination: each CI job must own its environment.
const LOCK_ROOT = join(tmpdir(), `sonicjs-e2e-${createHash('sha256')
  .update(process.env.BASE_URL || 'http://localhost:8787').digest('hex').slice(0, 16)}`)

export const test = base.extend<
  { page: Page; context: BrowserContext; exclusiveLocks: void; resourceId: string },
  { browser: Browser }
>({
  request: async ({ request, baseURL, extraHTTPHeaders }, use, testInfo) => {
    await use(prepareLocalRequest(request, baseURL || 'http://localhost:8787', testInfo.file, extraHTTPHeaders))
  },
  resourceId: async ({}, use) => { await use(uniqueTestId()) },
  exclusiveLocks: [async ({}, use, testInfo) => {
    const names = [...new Set(testInfo.tags.filter(tag => tag.startsWith('@lock-'))
      .map(tag => tag.slice('@lock-'.length)))].sort()
    const releases: Array<() => void> = []
    const waits: Array<{ name: string; waitMs: number }> = []
    const budget = testInfo.timeout
    let queued = 0
    try {
      for (const name of names) {
        const start = Date.now()
        releases.push(await acquireTestLock(LOCK_ROOT, name, {
          onWaiting: ms => { testInfo.setTimeout(budget + queued + ms + 1_000) },
        }))
        const waitMs = Date.now() - start
        queued += waitMs
        waits.push({ name, waitMs })
      }
      testInfo.setTimeout(budget + queued)
      await use()
    } finally {
      const errors: unknown[] = []
      for (const release of releases.reverse()) {
        try { release() } catch (error) { errors.push(error) }
      }
      if (waits.length) await testInfo.attach('lock-waits', {
        body: JSON.stringify(waits), contentType: 'application/json',
      })
      if (errors.length) throw new AggregateError(errors, 'E2E lock release failed')
    }
  }, { auto: true }],
  browser: [async ({ browser, playwright }, use) => {
    const vendorClient = await playwright.request.newContext()
    const newPage = browser.newPage.bind(browser)
    const newContext = browser.newContext.bind(browser)
    browser.newPage = async options => {
      const page = await newPage(options)
      await cacheVendorAssets(page.context(), process.env.BASE_URL || 'http://localhost:8787', vendorClient)
      return preparePage(page, options?.extraHTTPHeaders)
    }
    browser.newContext = async options => prepareContext(await newContext(options), options?.extraHTTPHeaders, vendorClient)
    try { await use(browser) } finally {
      browser.newPage = newPage
      browser.newContext = newContext
      await vendorClient.dispose()
    }
  }, { scope: 'worker' }],
  context: async ({ context, extraHTTPHeaders }, use) => { await use(await prepareContext(context, extraHTTPHeaders)) },
  page: async ({ page }, use) => { await use(preparePage(page)) },
})
