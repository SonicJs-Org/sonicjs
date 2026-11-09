import { describe, it, expect } from 'vitest'
import { Hono } from 'hono'
import {
  normalizeUiLanguageTag,
  reloadUrlWithoutUiLanguage,
  withUiLanguageCookieCleared,
  UI_LANGUAGE_COOKIE,
} from '../../i18n/middleware'

describe('normalizeUiLanguageTag', () => {
  it.each([
    ['ja', 'ja'],
    ['ja-JP', 'ja'],
    ['JA_jp', 'ja'],
    [' en-GB ', 'en'],
    ['fr-FR', undefined],
    ['', undefined],
    [null, undefined],
  ])('%s → %s', (input, expected) => {
    expect(normalizeUiLanguageTag(input as string | null)).toBe(expected)
  })
})

describe('reloadUrlWithoutUiLanguage', () => {
  async function resolve(headers: Record<string, string>) {
    const app = new Hono()
    app.get('/x', (c) => c.text(reloadUrlWithoutUiLanguage(c, '/fallback')))
    return (await app.request('http://localhost/x', { headers })).text()
  }

  it('strips lang but keeps the rest of the current URL', async () => {
    expect(await resolve({ 'HX-Current-URL': 'http://localhost/admin/content?lang=en&page=2#row' })).toBe(
      '/admin/content?page=2#row'
    )
  })

  it('falls back without a header, on a malformed one, or cross-origin', async () => {
    expect(await resolve({})).toBe('/fallback')
    expect(await resolve({ 'HX-Current-URL': 'http://[bad' })).toBe('/fallback')
    expect(await resolve({ 'HX-Current-URL': 'https://evil.example/admin' })).toBe('/fallback')
  })
})

describe('withUiLanguageCookieCleared', () => {
  it('appends a deletion cookie and keeps the original response intact', async () => {
    const original = new Response('{"success":true}', {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'better-auth.session_token=; Max-Age=0; Path=/' },
    })
    const res = withUiLanguageCookieCleared(original)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('{"success":true}')
    expect(res.headers.getSetCookie()).toEqual([
      'better-auth.session_token=; Max-Age=0; Path=/',
      `${UI_LANGUAGE_COOKIE}=; Max-Age=0; Path=/`,
    ])
  })
})
