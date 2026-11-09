/**
 * Admin UI internationalization.
 *
 * Scope: strings in the admin interface (the "UI language"). This is deliberately separate
 * from content localization (per-document `locale`), which uses the `?locale=` query and a
 * different request variable. See PLAN.md / issue #363.
 *
 * Templates are plain functions that never receive the Hono context, so `t()` reads the
 * current request's language through Hono's `contextStorage()` (AsyncLocalStorage). Outside a
 * request — unit tests that call a template directly, cron handlers — it falls back to English.
 */
import { getContext } from 'hono/context-storage'
import { escapeHtml } from '../utils/sanitize'
import { en } from './locales/en'
import { ja } from './locales/ja'
import {
  DEFAULT_UI_LANGUAGE,
  SUPPORTED_UI_LANGUAGES,
  type MessageKey,
  type MessageTree,
  type UiLanguage,
} from './types'

export * from './types'

const coreMessages: Record<UiLanguage, MessageTree> = {
  en: en as unknown as MessageTree,
  ja: ja as MessageTree,
}

/** namespace → language → dictionary, populated by plugins via `registerMessages`. */
const pluginMessages = new Map<string, Map<string, MessageTree>>()

export function isSupportedUiLanguage(value: unknown): value is UiLanguage {
  return typeof value === 'string' && (SUPPORTED_UI_LANGUAGES as readonly string[]).includes(value)
}

/** Narrow any stored/user-supplied value to a supported UI language, falling back to English. */
export function toUiLanguage(value: unknown): UiLanguage {
  return isSupportedUiLanguage(value) ? value : DEFAULT_UI_LANGUAGE
}

/** The UI language of the current request, or English when called outside a request. */
export function getUiLanguage(): UiLanguage {
  try {
    const c = getContext<{ Variables: { uiLanguage?: UiLanguage } }>()
    return toUiLanguage(c.get('uiLanguage'))
  } catch {
    return DEFAULT_UI_LANGUAGE
  }
}

/**
 * Register a plugin's messages for one language. Keys are then addressed as
 * `t('<namespace>:<dot.path>')`. Calling again for the same namespace/language merges
 * shallowly at the top level (later registrations win).
 */
export function registerMessages(namespace: string, language: string, messages: MessageTree): void {
  if (!namespace || namespace.includes(':')) {
    throw new Error(`[i18n] invalid message namespace: "${namespace}"`)
  }
  let byLang = pluginMessages.get(namespace)
  if (!byLang) {
    byLang = new Map()
    pluginMessages.set(namespace, byLang)
  }
  byLang.set(language, { ...(byLang.get(language) ?? {}), ...messages })
}

function lookup(tree: MessageTree | undefined, path: string): string | undefined {
  let node: string | MessageTree | undefined = tree
  for (const part of path.split('.')) {
    if (node === undefined || typeof node === 'string') return undefined
    node = node[part]
  }
  return typeof node === 'string' ? node : undefined
}

function resolve(key: string, language: UiLanguage): string | undefined {
  const sep = key.indexOf(':')
  if (sep === -1) {
    return lookup(coreMessages[language], key) ?? lookup(coreMessages[DEFAULT_UI_LANGUAGE], key)
  }
  const byLang = pluginMessages.get(key.slice(0, sep))
  const path = key.slice(sep + 1)
  return lookup(byLang?.get(language), path) ?? lookup(byLang?.get(DEFAULT_UI_LANGUAGE), path)
}

/**
 * Translate `key` into the current request's UI language.
 *
 * Fallback chain: requested language → English → the key itself (so a missing key is visible
 * rather than blank). `{name}` placeholders are replaced with `params[name]`, **HTML-escaped**,
 * so user-controlled values are safe to pass. Dictionary strings themselves are trusted.
 */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  return translate(getUiLanguage(), key, params)
}

/** Same as `t()` but for an explicit language — for code that already knows the target. */
export function translate(
  language: UiLanguage,
  key: MessageKey,
  params?: Record<string, string | number>
): string {
  const message = resolve(key, language) ?? key
  if (!params) return message
  return message.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? escapeHtml(String(params[name])) : match
  )
}

/** Test-only: drop every plugin-registered dictionary. */
export function resetPluginMessagesForTesting(): void {
  pluginMessages.clear()
}
