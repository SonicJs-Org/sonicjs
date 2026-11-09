import type { Context, MiddlewareHandler } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { languageDetector } from 'hono/language'
import { DEFAULT_UI_LANGUAGE, SUPPORTED_UI_LANGUAGES, type UiLanguage } from './types'
import { isSupportedUiLanguage, toUiLanguage } from './index'

/**
 * Cookie holding the UI language the user *explicitly* chose (profile setting, `?lang=`).
 * It is never written from `Accept-Language` detection, so its presence means "the user
 * decided" and lets us skip the per-request DB lookup of `auth_user.language`.
 */
export const UI_LANGUAGE_COOKIE = 'sonicjs_ui_lang'
/** Query parameter for a one-off / persisted UI language switch. Not `locale` — that is content. */
export const UI_LANGUAGE_QUERY = 'lang'

const ONE_YEAR_SECONDS = 60 * 60 * 24 * 365

export function setUiLanguageCookie(c: Context, language: UiLanguage): void {
  setCookie(c, UI_LANGUAGE_COOKIE, language, {
    path: '/',
    sameSite: 'Lax',
    httpOnly: true,
    secure: new URL(c.req.url).protocol === 'https:',
    maxAge: ONE_YEAR_SECONDS,
  })
}

export function clearUiLanguageCookie(c: Context): void {
  deleteCookie(c, UI_LANGUAGE_COOKIE, { path: '/' })
}

/**
 * Same as `clearUiLanguageCookie`, for a `Response` built outside Hono's context (e.g. the
 * one Better Auth's handler returns, whose headers `c.header()` would never reach).
 */
export function withUiLanguageCookieCleared(res: Response): Response {
  const cleared = new Response(res.body, res)
  cleared.headers.append('Set-Cookie', `${UI_LANGUAGE_COOKIE}=; Max-Age=0; Path=/`)
  return cleared
}

/**
 * Map a BCP 47 tag to a supported UI language: exact match first, then the primary subtag
 * (`ja-JP` → `ja`). Done here rather than relying on Hono, because `hono/language` only
 * gained prefix matching after 4.11 while our peer range starts at 4.7.
 */
export function normalizeUiLanguageTag(tag: string | null | undefined): UiLanguage | undefined {
  if (!tag) return undefined
  const lower = tag.trim().toLowerCase().replace(/_/g, '-')
  if (isSupportedUiLanguage(lower)) return lower
  const primary = lower.split('-')[0]
  return isSupportedUiLanguage(primary) ? primary : undefined
}

/**
 * Where to send the browser after the UI language changed: the page it was on (HTMX's
 * `HX-Current-URL`), minus a stale `?lang=` that would otherwise override the new choice.
 * Anything that is not same-origin falls back to `fallbackPath`.
 */
export function reloadUrlWithoutUiLanguage(c: Context, fallbackPath: string): string {
  const current = c.req.header('HX-Current-URL')
  if (!current) return fallbackPath
  try {
    const origin = new URL(c.req.url).origin
    const url = new URL(current, origin)
    if (url.origin !== origin) return fallbackPath
    url.searchParams.delete(UI_LANGUAGE_QUERY)
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return fallbackPath
  }
}

/**
 * Detects the UI language for every request and exposes it as `c.get('uiLanguage')`.
 *
 * Order: `?lang=` → `sonicjs_ui_lang` cookie → `Accept-Language` → `en`.
 * A valid `?lang=` is persisted to the cookie so the choice sticks across navigation.
 */
export function uiLanguageMiddleware(): MiddlewareHandler {
  const detect = languageDetector({
    supportedLanguages: [...SUPPORTED_UI_LANGUAGES],
    fallbackLanguage: DEFAULT_UI_LANGUAGE,
    order: ['querystring', 'cookie', 'header'],
    lookupQueryString: UI_LANGUAGE_QUERY,
    lookupCookie: UI_LANGUAGE_COOKIE,
    caches: false,
    // Unsupported tags pass through unchanged so Hono falls back to the next detector.
    convertDetectedLanguage: (tag) => normalizeUiLanguageTag(tag) ?? tag,
  })

  return async (c, next) => {
    return detect(c, async () => {
      c.set('uiLanguage', toUiLanguage(c.get('language')))
      const fromQuery = normalizeUiLanguageTag(c.req.query(UI_LANGUAGE_QUERY))
      if (fromQuery) {
        setUiLanguageCookie(c, fromQuery)
      }
      await next()
    })
  }
}

/**
 * For signed-in admin requests without an explicit choice yet (no cookie, no `?lang=`), apply
 * the language saved on the user's profile and remember it in the cookie. Runs after auth, so
 * it covers every login path (password, OTP, magic link, OAuth) with at most one DB read per
 * browser session. Logout clears the cookie, so the next user on the same browser starts fresh.
 */
export function userUiLanguagePreference(): MiddlewareHandler {
  return async (c, next) => {
    const user = c.get('user') as { userId?: string } | undefined
    if (
      user?.userId &&
      getCookie(c, UI_LANGUAGE_COOKIE) === undefined &&
      !normalizeUiLanguageTag(c.req.query(UI_LANGUAGE_QUERY))
    ) {
      try {
        const row = await (c.env as { DB: D1Database }).DB
          .prepare('SELECT language FROM auth_user WHERE id = ?')
          .bind(user.userId)
          .first<{ language: string | null }>()
        if (row) {
          const language = toUiLanguage(row.language)
          c.set('uiLanguage', language)
          setUiLanguageCookie(c, language)
        }
      } catch {
        // Non-fatal: keep the detected language.
      }
    }
    await next()
  }
}
