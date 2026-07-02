/**
 * E2E spec for the MCP Server admin dashboard (/admin/mcp).
 * Verifies the page renders, shows the endpoint URL, exposes collections,
 * and displays the integration guide snippets.
 *
 * NOTE: Do NOT run this locally — requires a running wrangler dev server.
 * CI validates it on PR per CLAUDE.md.
 */
import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('MCP admin dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('renders the /admin/mcp page with correct heading', async ({ page }) => {
    await page.goto('/admin/mcp')
    await expect(page.getByRole('heading', { name: 'MCP Server' })).toBeVisible()
  })

  test('shows the /mcp endpoint URL', async ({ page }) => {
    await page.goto('/admin/mcp')
    const endpointEl = page.locator('#endpoint-url')
    await expect(endpointEl).toBeVisible()
    const url = await endpointEl.textContent()
    expect(url?.trim()).toMatch(/\/mcp$/)
  })

  test('endpoint URL copy button is present', async ({ page }) => {
    await page.goto('/admin/mcp')
    const copyBtn = page.getByRole('button', { name: 'Copy' }).first()
    await expect(copyBtn).toBeVisible()
  })

  test('shows exposed collections table', async ({ page }) => {
    await page.goto('/admin/mcp')
    await expect(page.getByRole('columnheader', { name: 'ID' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Display name' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Read' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Write' })).toBeVisible()
  })

  test('shows Claude Code integration snippet', async ({ page }) => {
    await page.goto('/admin/mcp')
    const pre = page.locator('#claude-config')
    await expect(pre).toBeVisible()
    const text = await pre.textContent()
    expect(text).toContain('mcpServers')
    expect(text).toContain('sonicjs')
    expect(text).toContain('/mcp')
    expect(text).toContain('sk_YOUR_API_KEY')
  })

  test('shows Cursor integration snippet', async ({ page }) => {
    await page.goto('/admin/mcp')
    const pre = page.locator('#cursor-config')
    await expect(pre).toBeVisible()
    const text = await pre.textContent()
    expect(text).toContain('mcpServers')
    expect(text).toContain('/mcp')
  })

  test('links to /admin/plugins/api-keys for key management', async ({ page }) => {
    await page.goto('/admin/mcp')
    const mintLink = page.getByRole('link', { name: /mint api key/i })
    await expect(mintLink).toBeVisible()
    await expect(mintLink).toHaveAttribute('href', '/admin/plugins/api-keys')
  })

  test('unauthenticated access redirects to login', async ({ page }) => {
    // Navigate without logging in (new page context)
    await page.context().clearCookies()
    await page.goto('/admin/mcp')
    // Should redirect to login or return 401/403
    await expect(page).not.toHaveURL('/admin/mcp')
  })
})
