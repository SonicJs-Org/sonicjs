// Real-SQLite coverage for UI-language detection: detector precedence, cookie persistence,
// and the signed-in user's saved `auth_user.language` preference.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import { contextStorage } from 'hono/context-storage'
import { createTestD1 } from '../utils/d1-sqlite'
import {
  uiLanguageMiddleware,
  userUiLanguagePreference,
  UI_LANGUAGE_COOKIE,
} from '../../i18n/middleware'
import { t, getUiLanguage } from '../../i18n'
import { renderLoginPage } from '../../templates/pages/auth-login.template'

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- test D1 shim
function buildApp(db: any, userId?: string) {
  const app = new Hono()
  app.use('*', contextStorage())
  app.use('*', uiLanguageMiddleware())
  app.use('*', async (c, next) => {
    ;(c as unknown as { env: unknown }).env = { DB: db }
    if (userId) c.set('user' as never, { userId, email: 'a@b.c', role: 'admin' } as never)
    await next()
  })
  app.use('/admin/*', userUiLanguagePreference())
  app.get('/admin/probe', (c) => c.text(`${getUiLanguage()}|${t('nav.content')}`))
  app.get('/auth/login', (c) => c.html(renderLoginPage({})))
  return app
}

function setCookies(res: Response): string[] {
  return res.headers.getSetCookie?.() ?? []
}

describe('UI language middleware (real SQLite)', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test D1 shim
  let db: any
  beforeEach(() => {
    db = createTestD1()
  })
  afterEach(() => db.close())

  async function insertUser(id: string, language: string | null) {
    await db
      .prepare(
        `INSERT INTO auth_user (id, email, first_name, last_name, role, is_active, language, created_at, updated_at)
         VALUES (?, ?, 'A', 'B', 'admin', 1, ?, 0, 0)`
      )
      .bind(id, `${id}@example.com`, language)
      .run()
  }

  it('defaults to English with no signal', async () => {
    const res = await buildApp(db).request('/admin/probe')
    expect(await res.text()).toBe('en|Content')
  })

  it('detects Accept-Language without persisting it', async () => {
    const res = await buildApp(db).request('/admin/probe', {
      headers: { 'Accept-Language': 'ja-JP,ja;q=0.9,en;q=0.8' },
    })
    expect(await res.text()).toBe('ja|コンテンツ')
    expect(setCookies(res).some((c) => c.startsWith(`${UI_LANGUAGE_COOKIE}=`))).toBe(false)
  })

  it('cookie beats Accept-Language; ?lang= beats both and is persisted', async () => {
    const app = buildApp(db)
    const byCookie = await app.request('/admin/probe', {
      headers: { Cookie: `${UI_LANGUAGE_COOKIE}=en`, 'Accept-Language': 'ja' },
    })
    expect(await byCookie.text()).toBe('en|Content')

    const byQuery = await app.request('/admin/probe?lang=ja', {
      headers: { Cookie: `${UI_LANGUAGE_COOKIE}=en` },
    })
    expect(await byQuery.text()).toBe('ja|コンテンツ')
    expect(setCookies(byQuery).some((c) => c.startsWith(`${UI_LANGUAGE_COOKIE}=ja`))).toBe(true)
  })

  it('ignores an unsupported ?lang= value', async () => {
    const res = await buildApp(db).request('/admin/probe?lang=xx')
    expect(await res.text()).toBe('en|Content')
    expect(setCookies(res).some((c) => c.startsWith(`${UI_LANGUAGE_COOKIE}=`))).toBe(false)
  })

  it("applies the signed-in user's saved language when no cookie is set, and caches it", async () => {
    await insertUser('u-ja', 'ja')
    const res = await buildApp(db, 'u-ja').request('/admin/probe', {
      headers: { 'Accept-Language': 'en' },
    })
    expect(await res.text()).toBe('ja|コンテンツ')
    expect(setCookies(res).some((c) => c.startsWith(`${UI_LANGUAGE_COOKIE}=ja`))).toBe(true)
  })

  it('an existing cookie wins over the saved profile language (no DB override)', async () => {
    await insertUser('u-ja', 'ja')
    const res = await buildApp(db, 'u-ja').request('/admin/probe', {
      headers: { Cookie: `${UI_LANGUAGE_COOKIE}=en` },
    })
    expect(await res.text()).toBe('en|Content')
  })

  it('maps an unsupported saved language to English', async () => {
    await insertUser('u-fr', 'fr')
    const res = await buildApp(db, 'u-fr').request('/admin/probe', {
      headers: { 'Accept-Language': 'ja' },
    })
    expect(await res.text()).toBe('en|Content')
  })

  it('renders the login page in the detected language with a matching <html lang>', async () => {
    const res = await buildApp(db).request('/auth/login?lang=ja')
    const html = await res.text()
    expect(html).toContain('<html lang="ja"')
    expect(html).toContain('おかえりなさい')
    expect(html).not.toContain('Welcome Back')
  })
})
