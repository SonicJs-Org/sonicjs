import type { en } from './locales/en'

/** UI languages the admin ships translations for. `en` is the fallback for every key. */
export const SUPPORTED_UI_LANGUAGES = ['en', 'ja'] as const
export type UiLanguage = (typeof SUPPORTED_UI_LANGUAGES)[number]
export const DEFAULT_UI_LANGUAGE: UiLanguage = 'en'

type Widen<T> = T extends string ? string : { [K in keyof T]?: Widen<T[K]> }

/** Shape every non-English locale must follow: same keys as `en`, all optional. */
export type LocaleMessages = Widen<typeof en>

/** Dot-path of every leaf in the English dictionary, e.g. `'nav.content'`. */
type LeafPaths<T, P extends string = ''> = {
  [K in keyof T & string]: T[K] extends string ? `${P}${K}` : LeafPaths<T[K], `${P}${K}.`>
}[keyof T & string]

export type CoreMessageKey = LeafPaths<typeof en>

/**
 * Plugin-registered keys are addressed as `'<namespace>:<dot.path>'` (see `registerMessages`).
 * They are not type-checked against a dictionary.
 */
export type PluginMessageKey = `${string}:${string}`

export type MessageKey = CoreMessageKey | PluginMessageKey

/** Nested plain-string dictionary accepted by `registerMessages`. */
export interface MessageTree {
  [key: string]: string | MessageTree
}
