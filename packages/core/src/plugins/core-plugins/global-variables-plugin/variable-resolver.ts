/**
 * Variable Resolver
 *
 * Scans strings for {variable_key} tokens and replaces them
 * with values from the global variables map.
 *
 * Token syntax: {key} where key matches /^[a-z0-9_]+$/
 * Unresolved tokens are left as-is so editors can see what's missing.
 */

// Matches {variable_key} — only lowercase alphanumeric + underscores
const TOKEN_PATTERN = /\{([a-z0-9_]+)\}/g

/**
 * Replace all {variable_key} tokens in a string with their values.
 * Unresolved tokens remain unchanged.
 */
export function resolveVariables(
  text: string,
  variables: Map<string, string>
): string {
  if (!text || variables.size === 0) return text

  return text.replace(TOKEN_PATTERN, (match, key) => {
    const value = variables.get(key)
    return value !== undefined ? value : match
  })
}

/**
 * Recursively resolve variables in an object's string values.
 * Handles nested objects, arrays, and the `data` field of content items.
 */
export function resolveVariablesInObject(
  obj: any,
  variables: Map<string, string>
): any {
  if (!obj || variables.size === 0) return obj

  if (typeof obj === 'string') {
    return resolveVariables(obj, variables)
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => resolveVariablesInObject(item, variables))
  }

  if (typeof obj === 'object') {
    const result: Record<string, any> = {}
    for (const [key, value] of Object.entries(obj)) {
      result[key] = resolveVariablesInObject(value, variables)
    }
    return result
  }

  return obj
}

// ============================================================================
// In-memory variable cache (shared with index.ts via import)
// ============================================================================

let variableCache: Map<string, string> | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 300_000 // 5 minutes

export function getVariablesCached(): Map<string, string> | null {
  const now = Date.now()
  if (variableCache && (now - cacheTimestamp) < CACHE_TTL_MS) {
    return variableCache
  }
  return null
}

export function setVariablesCache(map: Map<string, string>): void {
  variableCache = map
  cacheTimestamp = Date.now()
}

export function invalidateVariablesCache(): void {
  variableCache = null
  cacheTimestamp = 0
}

/**
 * Resolve variables in a content object using the database.
 * Fetches variables from DB (with caching) and resolves tokens.
 * Safe to call even if the global_variables table doesn't exist yet.
 */
export async function resolveContentVariables(
  contentData: any,
  db: any
): Promise<any> {
  if (!db || !contentData) return contentData

  try {
    // Check cache first
    let variables = getVariablesCached()

    if (!variables) {
      const { results } = await db.prepare(
        'SELECT key, value FROM global_variables WHERE is_active = 1'
      ).all()

      variables = new Map<string, string>()
      for (const row of results || []) {
        variables.set((row as any).key, (row as any).value)
      }
      setVariablesCache(variables)
    }

    if (variables.size === 0) return contentData

    return resolveVariablesInObject(contentData, variables)
  } catch {
    // Table may not exist yet — silently return original data
    return contentData
  }
}
