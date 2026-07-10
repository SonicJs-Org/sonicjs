const enc = encodeURIComponent

function append(params: string[], key: string, value: unknown): void {
  if (value === undefined || value === null) return
  params.push(`${enc(key)}=${enc(String(value))}`)
}

/**
 * Serialize a query object into a URL query string.
 *
 * Special handling:
 *   where   → where[field][op]=value or where[field][]=v (array)
 *   filter  → filter[field]=value
 *   facet   → facet[field]=value
 *   cursor  → cursor_updated_at + cursor_id
 *   resolveVariables → resolve_variables
 *   arrays (fields, include) → comma-separated string
 */
export function serializeQuery(obj: Record<string, unknown>): string {
  const params: string[] = []

  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined || value === null) continue

    if (key === 'where') {
      const where = value as Record<string, unknown>
      for (const [field, condition] of Object.entries(where)) {
        if (condition === undefined || condition === null) continue

        if (Array.isArray(condition)) {
          for (const v of condition) append(params, `where[${field}][]`, v)
        } else if (typeof condition === 'object') {
          const ops = condition as Record<string, unknown>
          for (const [op, opValue] of Object.entries(ops)) {
            if (opValue === undefined || opValue === null) continue
            if (Array.isArray(opValue)) {
              for (const v of opValue) append(params, `where[${field}][]`, v)
            } else {
              append(params, `where[${field}][${op}]`, opValue)
            }
          }
        } else {
          append(params, `where[${field}][equals]`, condition)
        }
      }
    } else if (key === 'filter' || key === 'facet') {
      const map = value as Record<string, unknown>
      for (const [field, v] of Object.entries(map)) {
        append(params, `${key}[${field}]`, v)
      }
    } else if (key === 'cursor') {
      const cursor = value as { updatedAt: number; id: string }
      append(params, 'cursor_updated_at', cursor.updatedAt)
      append(params, 'cursor_id', cursor.id)
    } else if (key === 'resolveVariables') {
      append(params, 'resolve_variables', value)
    } else if (Array.isArray(value)) {
      // fields, include → comma-separated
      append(params, key, value.join(','))
    } else {
      append(params, key, value)
    }
  }

  return params.join('&')
}
