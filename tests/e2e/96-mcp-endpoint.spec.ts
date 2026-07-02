import { test, expect } from '@playwright/test'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'

/**
 * Live JSON-RPC endpoint coverage for the MCP plugin (POST /mcp).
 *
 * The admin dashboard is covered by 93-mcp-admin. This exercises the wire path an
 * AI agent actually uses: mint an API key, then drive the endpoint with Bearer auth.
 * It specifically pins the review fix that `get_*` by slug resolves a never-published
 * draft (previously only published rows were reachable by slug).
 */

const RPC_URL = `${TEST_ORIGIN}/mcp`

// Unique slug per run so parallel/repeat runs don't collide.
const SLUG = `mcp-e2e-${Date.now()}`

test.describe('MCP JSON-RPC endpoint', () => {
  let apiKey = ''
  let keyId = ''

  test.beforeAll(async ({ browser }) => {
    // Log in and mint a one-time API key via the api-keys admin route (cookie-authed,
    // so a CSRF token header is required for the POST).
    const page = await browser.newPage()
    await loginAsAdmin(page)
    const csrf = await getCsrfTokenFromPage(page)
    const res = await page.request.post(`${TEST_ORIGIN}/admin/plugins/api-keys/api/keys`, {
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      data: { name: `mcp-e2e-${Date.now()}` },
    })
    expect(res.status(), await res.text()).toBe(201)
    const body = await res.json()
    apiKey = body.apiKey.key
    keyId = body.apiKey.id
    expect(apiKey).toMatch(/^sk_/)
    await page.close()
  })

  test.afterAll(async ({ browser }) => {
    // Revoke the minted key so it doesn't accumulate against the per-user cap.
    if (!keyId) return
    const page = await browser.newPage()
    await loginAsAdmin(page)
    const csrf = await getCsrfTokenFromPage(page)
    await page.request.delete(`${TEST_ORIGIN}/admin/plugins/api-keys/api/keys/${keyId}`, {
      headers: { 'X-CSRF-Token': csrf },
    })
    await page.close()
  })

  // Bearer-authed JSON-RPC helper (CSRF-exempt because of the Authorization header).
  async function rpc(request: any, method: string, params?: unknown) {
    const res = await request.post(RPC_URL, {
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      data: { jsonrpc: '2.0', id: Date.now(), method, params },
    })
    return { status: res.status(), body: await res.json() }
  }
  const toolResult = (envelope: any) => JSON.parse(envelope.result.content[0].text)

  test('rejects a request with no API key (-32001)', async ({ request }) => {
    const res = await request.post(RPC_URL, {
      headers: { 'Content-Type': 'application/json' },
      data: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
    })
    const body = await res.json()
    expect(body.error.code).toBe(-32001)
  })

  test('initialize returns the handshake', async ({ request }) => {
    const { body } = await rpc(request, 'initialize')
    expect(body.result.serverInfo.name).toBe('sonicjs-mcp')
    expect(body.result.capabilities).toHaveProperty('tools')
  })

  test('tools/list advertises blog_post read + write tools', async ({ request }) => {
    const { body } = await rpc(request, 'tools/list')
    const names = body.result.tools.map((t: any) => t.name)
    expect(names).toEqual(
      expect.arrayContaining(['list_collections', 'list_blog_post', 'get_blog_post', 'create_blog_post', 'delete_blog_post']),
    )
  })

  test('create draft → get by slug resolves the unpublished draft', async ({ request }) => {
    // Create as a draft (no publish).
    const created = toolResult(
      await rpc(request, 'tools/call', {
        name: 'create_blog_post',
        arguments: { title: 'MCP E2E Draft', slug: SLUG, data: { content: 'hello from mcp' } },
      }).then((r) => r.body),
    )
    expect(created.isPublished).toBe(false)
    const rootId = created.rootId
    expect(rootId).toBeTruthy()

    // The review fix: get_* by slug now finds a never-published draft.
    const got = toolResult(
      await rpc(request, 'tools/call', { name: 'get_blog_post', arguments: { slug: SLUG } }).then((r) => r.body),
    )
    expect(got.rootId).toBe(rootId)
    expect(got.slug).toBe(SLUG)
    expect(got.isPublished).toBe(false)

    // Clean up the doc.
    const del = toolResult(
      await rpc(request, 'tools/call', { name: 'delete_blog_post', arguments: { id: rootId } }).then((r) => r.body),
    )
    expect(del.deleted).toBe(true)
  })
})
