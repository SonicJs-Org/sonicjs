// Route-level integration test: saving the profile language persists it to auth_user, writes the
// UI-language cookie, and asks HTMX to reload the page when the UI language actually changes.
// Real SQLite; only authentication is stubbed.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { contextStorage } from 'hono/context-storage'
import { createTestD1 } from '../utils/d1-sqlite'
import { uiLanguageMiddleware, UI_LANGUAGE_COOKIE } from '../../i18n/middleware'

vi.mock('../../middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../middleware')>()),
  requireAuth: () => async (c: { set: (k: string, v: unknown) => void }, next: () => Promise<void>) => {
    c.set('user', { userId: 'u1', email: 'u1@example.com', role: 'admin' })
    await next()
  },
  requireRole: () => async (_c: unknown, next: () => Promise<void>) => next(),
  logActivity: vi.fn(),
}))

import { userRoutes } from '../../routes/admin-users'

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- test D1 shim
function buildApp(db: any) {
  const app = new Hono()
  app.use('*', contextStorage())
  app.use('*', uiLanguageMiddleware())
  app.use('*', async (c, next) => {
    ;(c as unknown as { env: unknown }).env = { DB: db }
    await next()
  })
  app.route('/admin', userRoutes)
  return app
}

function profileForm(language: string): RequestInit {
  const body = new FormData()
  body.set('first_name', 'Ada')
  body.set('last_name', 'Lovelace')
  body.set('email', 'u1@example.com')
  body.set('timezone', 'UTC')
  body.set('language', language)
  return { method: 'PUT', body }
}

describe('PUT /admin/profile — UI language (real SQLite)', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test D1 shim
  let db: any
  beforeEach(async () => {
    db = createTestD1()
    await db
      .prepare(
        `INSERT INTO auth_user (id, email, first_name, last_name, role, is_active, language, created_at, updated_at)
         VALUES ('u1', 'u1@example.com', 'Ada', 'Lovelace', 'admin', 1, 'en', 0, 0)`
      )
      .run()
  })
  afterEach(() => db.close())

  it('switching en → ja saves it, sets the cookie, reloads, and answers in Japanese', async () => {
    const res = await buildApp(db).request('/admin/profile', profileForm('ja'))
    expect(res.status).toBe(200)

    const row = await db.prepare('SELECT language FROM auth_user WHERE id = ?').bind('u1').first()
    expect(row.language).toBe('ja')
    expect(res.headers.getSetCookie().some((c) => c.startsWith(`${UI_LANGUAGE_COOKIE}=ja`))).toBe(true)
    expect(res.headers.get('HX-Refresh')).toBe('true')
    expect(await res.text()).toContain('プロフィールを更新しました。')
  })

  it('saving without changing the UI language does not force a reload', async () => {
    const res = await buildApp(db).request('/admin/profile', {
      ...profileForm('ja'),
      headers: { Cookie: `${UI_LANGUAGE_COOKIE}=ja` },
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('HX-Refresh')).toBeNull()
  })

  it('an unsupported language is stored as chosen but the UI cookie falls back to en', async () => {
    const res = await buildApp(db).request('/admin/profile', profileForm('fr'))
    const row = await db.prepare('SELECT language FROM auth_user WHERE id = ?').bind('u1').first()
    expect(row.language).toBe('fr')
    expect(res.headers.getSetCookie().some((c) => c.startsWith(`${UI_LANGUAGE_COOKIE}=en`))).toBe(true)
    expect(res.headers.get('HX-Refresh')).toBeNull()
    expect(await res.text()).toContain('Profile updated successfully!')
  })

  it('validation errors are reported in the current UI language', async () => {
    const form = profileForm('ja')
    ;(form.body as FormData).set('first_name', '')
    const res = await buildApp(db).request('/admin/profile?lang=ja', form)
    expect(await res.text()).toContain('名・姓・メールアドレスは必須です。')
  })
})
