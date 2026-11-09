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
  })

  return async (c, next) => {
    return detect(c, async () => {
      c.set('uiLanguage', toUiLanguage(c.get('language')))
      const fromQuery = c.req.query(UI_LANGUAGE_QUERY)
      if (isSupportedUiLanguage(fromQuery)) {
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
      !isSupportedUiLanguage(c.req.query(UI_LANGUAGE_QUERY))
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
