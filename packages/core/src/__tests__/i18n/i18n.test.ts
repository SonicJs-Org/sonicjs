import { describe, it, expect, afterEach } from 'vitest'
import { Hono } from 'hono'
import { contextStorage } from 'hono/context-storage'
import {
  t,
  translate,
  getUiLanguage,
  registerMessages,
  isSupportedUiLanguage,
  toUiLanguage,
  resetPluginMessagesForTesting,
} from '../../i18n'
import { en } from '../../i18n/locales/en'
import { ja } from '../../i18n/locales/ja'

type Tree = { [k: string]: string | Tree }
function leafPaths(tree: Tree, prefix = ''): string[] {
  return Object.entries(tree).flatMap(([k, v]) =>
    typeof v === 'string' ? [`${prefix}${k}`] : leafPaths(v, `${prefix}${k}.`)
  )
}

describe('i18n — translate()', () => {
  afterEach(() => resetPluginMessagesForTesting())

  it('returns the message for the requested language', () => {
    expect(translate('en', 'nav.content')).toBe('Content')
    expect(translate('ja', 'nav.content')).toBe('コンテンツ')
  })

  it('falls back to English, then to the key itself', () => {
    registerMessages('demo', 'en', { onlyEn: 'English only' })
    expect(translate('ja', 'demo:onlyEn')).toBe('English only')
    expect(translate('ja', 'nav.doesNotExist' as never)).toBe('nav.doesNotExist')
  })

  it('interpolates {params} and HTML-escapes them', () => {
    registerMessages('demo', 'en', { greet: 'Hello, {name}! {missing}' })
    expect(translate('en', 'demo:greet', { name: '<b>Ada</b>' })).toBe(
      'Hello, &lt;b&gt;Ada&lt;/b&gt;! {missing}'
    )
  })

  it('namespaces plugin messages and rejects invalid namespaces', () => {
    registerMessages('stripe', 'ja', { title: { main: '決済' } })
    expect(translate('ja', 'stripe:title.main')).toBe('決済')
    expect(translate('ja', 'other:title.main')).toBe('other:title.main')
    expect(() => registerMessages('a:b', 'en', {})).toThrow()
    expect(() => registerMessages('', 'en', {})).toThrow()
  })

  it('narrows unsupported languages to English', () => {
    expect(isSupportedUiLanguage('ja')).toBe(true)
    expect(isSupportedUiLanguage('fr')).toBe(false)
    expect(toUiLanguage('fr')).toBe('en')
    expect(toUiLanguage(null)).toBe('en')
  })
})

describe('i18n — request scope', () => {
  it('t() and getUiLanguage() default to English outside a request', () => {
    expect(getUiLanguage()).toBe('en')
    expect(t('nav.settings')).toBe('Settings')
  })

  it('t() follows c.get("uiLanguage") inside a request via contextStorage', async () => {
    const app = new Hono<{ Variables: { uiLanguage: 'en' | 'ja' } }>()
    app.use('*', contextStorage())
    app.use('*', async (c, next) => {
      c.set('uiLanguage', 'ja')
      await next()
    })
    app.get('/', (c) => c.text(`${getUiLanguage()}|${t('nav.settings')}`))
    const res = await app.request('/')
    expect(await res.text()).toBe('ja|設定')
  })
})

describe('i18n — dictionaries', () => {
  it('ja has no keys that en lacks (no orphaned translations)', () => {
    const enKeys = new Set(leafPaths(en as unknown as Tree))
    const orphans = leafPaths(ja as Tree).filter((k) => !enKeys.has(k))
    expect(orphans).toEqual([])
  })

  it('ja currently translates every en key', () => {
    const jaKeys = new Set(leafPaths(ja as Tree))
    const missing = leafPaths(en as unknown as Tree).filter((k) => !jaKeys.has(k))
    expect(missing).toEqual([])
  })
})
