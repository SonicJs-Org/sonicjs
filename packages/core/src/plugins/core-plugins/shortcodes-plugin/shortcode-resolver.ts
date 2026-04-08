/**
 * Shortcode Resolver
 *
 * Scans strings for [[shortcode_name param="value"]] tokens and replaces them
 * by calling registered handler functions.
 *
 * Token syntax: [[name]] or [[name param1="value1" param2="value2"]]
 * Unresolved shortcodes (no handler) are left as-is.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type ShortcodeHandler = (
  params: Record<string, string>,
  context?: any
) => string | Promise<string>

// ─── Handler Registry ────────────────────────────────────────────────────────

const handlerRegistry = new Map<string, ShortcodeHandler>()

/**
 * Register a shortcode handler function.
 * Call this at module load time to make handlers available.
 */
export function registerShortcodeHandler(key: string, handler: ShortcodeHandler): void {
  handlerRegistry.set(key, handler)
}

/**
 * Get all registered handler keys.
 */
export function getRegisteredHandlers(): string[] {
  return Array.from(handlerRegistry.keys())
}

/**
 * Check if a handler is registered.
 */
export function hasHandler(key: string): boolean {
  return handlerRegistry.has(key)
}

// ─── Parser ──────────────────────────────────────────────────────────────────

const SHORTCODE_PATTERN = /\[\[(\w+)([^\]]*)\]\]/g

/**
 * Parse shortcode parameters from a string like: param1="value1" param2="value2"
 */
export function parseShortcodeParams(paramStr: string): Record<string, string> {
  const params: Record<string, string> = {}
  const regex = /(\w+)="([^"]*)"/g
  let match
  while ((match = regex.exec(paramStr)) !== null) {
    params[match[1]] = match[2]
  }
  return params
}

// ─── Resolver ────────────────────────────────────────────────────────────────

/**
 * Resolve all [[shortcode]] tokens in a string.
 * Calls registered handlers and replaces tokens with output.
 * Unknown shortcodes are left as-is.
 */
export async function resolveShortcodes(
  text: string,
  context?: any
): Promise<string> {
  if (!text) return text
  // Quick check before running regex
  if (!text.includes('[[')) return text

  SHORTCODE_PATTERN.lastIndex = 0
  const replacements: Array<{ match: string; replacement: string }> = []

  let m
  while ((m = SHORTCODE_PATTERN.exec(text)) !== null) {
    const name = m[1]
    const paramStr = m[2]
    const params = parseShortcodeParams(paramStr)
    const handler = handlerRegistry.get(name)

    if (handler) {
      try {
        const result = await handler(params, context)
        // Handlers must return strings (inline HTML or plain text).
        // This is the contract: shortcodes resolve to content that can
        // live inside rich text — not components, not objects.
        if (typeof result === 'string') {
          replacements.push({ match: m[0], replacement: result })
        } else {
          replacements.push({ match: m[0], replacement: `<!-- shortcode ${name}: handler returned non-string -->` })
        }
      } catch {
        replacements.push({ match: m[0], replacement: `<!-- shortcode error: ${name} -->` })
      }
    }
    // Unknown shortcodes (no handler) left as-is
  }

  let result = text
  for (const r of replacements) {
    result = result.replace(r.match, r.replacement)
  }
  return result
}

/**
 * Recursively resolve shortcodes in an object's string values.
 */
export async function resolveShortcodesInObject(
  obj: any,
  context?: any
): Promise<any> {
  if (!obj) return obj

  if (typeof obj === 'string') {
    return resolveShortcodes(obj, context)
  }

  if (Array.isArray(obj)) {
    return Promise.all(obj.map(item => resolveShortcodesInObject(item, context)))
  }

  if (typeof obj === 'object') {
    const result: Record<string, any> = {}
    for (const [key, value] of Object.entries(obj)) {
      result[key] = await resolveShortcodesInObject(value, context)
    }
    return result
  }

  return obj
}

// ─── Built-in Handlers ───────────────────────────────────────────────────────

registerShortcodeHandler('current_date', (params) => {
  const now = new Date()
  const format = params.format || 'MMMM D, YYYY'
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
  const monthsShort = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  return format
    .replace('YYYY', String(now.getFullYear()))
    .replace('YY', String(now.getFullYear()).slice(-2))
    .replace('MMMM', months[now.getMonth()])
    .replace('MMM', monthsShort[now.getMonth()])
    .replace('MM', String(now.getMonth() + 1).padStart(2, '0'))
    .replace('DD', String(now.getDate()).padStart(2, '0'))
    .replace('D', String(now.getDate()))
})

registerShortcodeHandler('phone_link', (params) => {
  const number = params.number || ''
  const digits = number.replace(/\D/g, '')
  return `<a href="tel:+1${digits}" class="text-blue-600 hover:underline">${number}</a>`
})

registerShortcodeHandler('cta_button', (params) => {
  const text = params.text || 'Learn More'
  const url = params.url || '/'
  const style = params.style || 'primary'
  const colors = style === 'primary'
    ? 'bg-blue-600 hover:bg-blue-700 text-white'
    : 'bg-zinc-200 hover:bg-zinc-300 text-zinc-900'
  return `<a href="${url}" class="inline-block rounded-lg px-6 py-3 font-semibold ${colors} transition-colors">${text}</a>`
})

registerShortcodeHandler('plan_count', (params) => {
  const type = params.type || 'residential'
  return `<span data-shortcode="plan_count" data-type="${type}" class="font-semibold">1,000+</span>`
})

registerShortcodeHandler('provider_rating', (params) => {
  const format = params.format || 'stars'
  const display = format === 'numeric' ? '4.2/5' : '★★★★☆'
  return `<span data-shortcode="provider_rating" data-provider="${params.provider || ''}" class="text-yellow-500">${display}</span>`
})
