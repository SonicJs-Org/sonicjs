import { test, expect } from './fixtures'
import { loginAsAdmin, TEST_ORIGIN } from './utils/test-helpers'

/**
 * Admin UI i18n (#363) — UI language detection and switching.
 *
 * Every language switch here lives in the browser context only (`?lang=` → `sonicjs_ui_lang`
 * cookie, or the context's Accept-Language). Nothing writes the shared admin's saved profile
 * language: CI runs two workers, and a parallel spec signing in while the admin's
 * `auth_user.language` is `ja` would render in Japanese. The profile-save path is covered
 * against real SQLite in packages/core/src/__tests__/i18n/profile-language.integration.test.ts.
 */

test.describe('Admin UI i18n — login page @smoke', () => {
  test('renders in Japanese with ?lang=ja and back in English with ?lang=en', async ({ page }) => {
    await page.context().clearCookies()

    await page.goto('/auth/login?lang=ja')
    await expect(page.locator('html')).toHaveAttribute('lang', 'ja')
    await expect(page.getByRole('heading', { name: 'おかえりなさい' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'ログイン' })).toBeVisible()

    // The choice sticks without the query string.
    await page.goto('/auth/login')
    await expect(page.locator('html')).toHaveAttribute('lang', 'ja')

    await page.goto('/auth/login?lang=en')
    await expect(page.locator('html')).toHaveAttribute('lang', 'en')
    await expect(page.getByRole('heading', { name: 'Welcome Back' })).toBeVisible()
  })

  test('ignores an unsupported ?lang= value', async ({ page }) => {
    await page.context().clearCookies()
    await page.goto('/auth/login?lang=xx')
    await expect(page.locator('html')).toHaveAttribute('lang', 'en')
    await expect(page.getByRole('heading', { name: 'Welcome Back' })).toBeVisible()
  })
})

test.describe('Admin UI i18n — Accept-Language @smoke', () => {
  test.use({ locale: 'ja-JP' })

  test('a Japanese browser gets the Japanese login page', async ({ page }) => {
    await page.context().clearCookies()
    await page.goto('/auth/login')
    await expect(page.locator('html')).toHaveAttribute('lang', 'ja')
    await expect(page.getByRole('heading', { name: 'おかえりなさい' })).toBeVisible()
  })
})

test.describe('Admin UI i18n — admin shell @smoke', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('switches the sidebar and profile page language and keeps it across navigation', async ({ page }) => {
    const contentLink = page.locator('a[href="/admin/content"]').first()

    await page.goto('/admin/profile?lang=ja', { waitUntil: 'domcontentloaded' })
    await expect(page.locator('html')).toHaveAttribute('lang', 'ja')
    await expect(page.getByRole('heading', { name: 'ユーザープロフィール' })).toBeVisible()
    await expect(contentLink).toContainText('コンテンツ')

    // Navigating without ?lang= keeps Japanese (cookie).
    await page.goto('/admin/content', { waitUntil: 'domcontentloaded' })
    await expect(page.locator('html')).toHaveAttribute('lang', 'ja')
    await expect(contentLink).toContainText('コンテンツ')

    // And switching back restores English.
    await page.goto('/admin/profile?lang=en', { waitUntil: 'domcontentloaded' })
    await expect(page.locator('html')).toHaveAttribute('lang', 'en')
    await expect(page.getByRole('heading', { name: 'User Profile' })).toBeVisible()
    await expect(contentLink).toContainText('Content')
  })

  test('signing out clears the UI language choice', async ({ page }) => {
    await page.goto('/admin/profile?lang=ja', { waitUntil: 'domcontentloaded' })
    await expect(page.locator('html')).toHaveAttribute('lang', 'ja')

    await page.goto('/auth/logout')
    await expect(page).toHaveURL(/\/auth\/login/)
    const cookies = await page.context().cookies()
    expect(cookies.find((c) => c.name === 'sonicjs_ui_lang')).toBeUndefined()
  })

  test("Better Auth's POST /auth/sign-out also clears the UI language choice", async ({ page }) => {
    await page.goto('/admin/profile?lang=ja', { waitUntil: 'domcontentloaded' })
    expect((await page.context().cookies()).find((c) => c.name === 'sonicjs_ui_lang')?.value).toBe('ja')

    const res = await page.request.post('/auth/sign-out', {
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      data: {},
    })
    expect(res.ok(), await res.text()).toBeTruthy()
    expect((await page.context().cookies()).find((c) => c.name === 'sonicjs_ui_lang')).toBeUndefined()
  })
})

test.describe('Admin UI i18n — regional Accept-Language @smoke', () => {
  test('a regional tag alone (ja-JP) selects Japanese', async ({ page }) => {
    await page.context().clearCookies()
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'ja-JP' })
    await page.goto('/auth/login')
    await expect(page.locator('html')).toHaveAttribute('lang', 'ja')
  })
})
