/**
 * Query Filter Builder for SonicJS AI
 * Supports comprehensive filtering with AND/OR logic
 * Compatible with D1 Database (SQLite)
 */

export type FilterOperator =
  | 'equals'
  | 'not_equals'
  | 'greater_than'
  | 'greater_than_equal'
  | 'less_than'
  | 'less_than_equal'
  | 'like'
  | 'contains'
  | 'in'
  | 'not_in'
  | 'all'
  | 'exists'
  | 'near'
  | 'within'
  | 'intersects'

export interface FilterCondition {
  field: string
  operator: FilterOperator
  value: any
}

export interface FilterGroup {
  and?: FilterCondition[]
  or?: FilterCondition[]
}

export interface QueryFilter {
  where?: FilterGroup
  limit?: number
  offset?: number
  sort?: {
    field: string
    order: 'asc' | 'desc'
  }[]
}

export interface QueryResult {
  sql: string
  params: any[]
  errors: string[]
}

/**
 * Validate sort order value - only 'asc' or 'desc' are allowed.
 * Returns the validated lowercase value, defaulting to 'asc' for invalid input.
 */
export function validateSortOrder(order: any): 'asc' | 'desc' {
  if (typeof order === 'string') {
    const normalized = order.toLowerCase().trim()
    if (normalized === 'asc' || normalized === 'desc') {
      return normalized
    }
  }
  return 'asc'
}

/**
 * Query Filter Builder
 * Converts filter objects into SQL WHERE clauses with parameterized queries
 */
export class QueryFilterBuilder {
  private params: any[] = []
  private errors: string[] = []

  /**
   * Build a complete SQL query from filter object
   */
  build(baseTable: string, filter: QueryFilter): QueryResult {
    this.params = []
    this.errors = []

    let sql = `SELECT * FROM ${baseTable}`

    // Build WHERE clause
    if (filter.where) {
      const whereClause = this.buildWhereClause(filter.where)
      if (whereClause) {
        sql += ` WHERE ${whereClause}`
      }
    }

    // Build ORDER BY clause
    if (filter.sort && filter.sort.length > 0) {
      const orderClauses = filter.sort
        .map(s => `${this.sanitizeFieldName(s.field)} ${this.sanitizeSortOrder(s.order)}`)
        .join(', ')
      sql += ` ORDER BY ${orderClauses}`
    }

    // Build LIMIT clause
    if (filter.limit) {
      sql += ` LIMIT ?`
      this.params.push(filter.limit)
    }

    // Build OFFSET clause
    if (filter.offset) {
      sql += ` OFFSET ?`
      this.params.push(filter.offset)
    }

    return {
      sql,
      params: this.params,
      errors: this.errors
    }
  }

  /**
   * Build WHERE clause from filter group
   */
  private buildWhereClause(group: FilterGroup): string {
    const clauses: string[] = []

    // Handle AND conditions
    if (group.and && group.and.length > 0) {
      const andClauses = group.and
        .map(condition => this.buildCondition(condition))
        .filter(clause => clause !== null)

      if (andClauses.length > 0) {
        clauses.push(`(${andClauses.join(' AND ')})`)
      }
    }

    // Handle OR conditions
    if (group.or && group.or.length > 0) {
      const orClauses = group.or
        .map(condition => this.buildCondition(condition))
        .filter(clause => clause !== null)

      if (orClauses.length > 0) {
        clauses.push(`(${orClauses.join(' OR ')})`)
      }
    }

    return clauses.join(' AND ')
  }

  /**
   * Build a single condition
   */
  private buildCondition(condition: FilterCondition): string | null {
    const field = this.sanitizeFieldName(condition.field)

    switch (condition.operator) {
      case 'equals':
        return this.buildEquals(field, condition.value)

      case 'not_equals':
        return this.buildNotEquals(field, condition.value)

      case 'greater_than':
        return this.buildComparison(field, '>', condition.value)

      case 'greater_than_equal':
        return this.buildComparison(field, '>=', condition.value)

      case 'less_than':
        return this.buildComparison(field, '<', condition.value)

      case 'less_than_equal':
        return this.buildComparison(field, '<=', condition.value)

      case 'like':
        return this.buildLike(field, condition.value)

      case 'contains':
        return this.buildContains(field, condition.value)

      case 'in':
        return this.buildIn(field, condition.value)

      case 'not_in':
        return this.buildNotIn(field, condition.value)

      case 'all':
        return this.buildAll(field, condition.value)

      case 'exists':
        return this.buildExists(field, condition.value)

      case 'near':
        this.errors.push(`'near' operator not supported in SQLite. Use spatial extension or application-level filtering.`)
        return null

      case 'within':
        this.errors.push(`'within' operator not supported in SQLite. Use spatial extension or application-level filtering.`)
        return null

      case 'intersects':
        this.errors.push(`'intersects' operator not supported in SQLite. Use spatial extension or application-level filtering.`)
        return null

      default:
        this.errors.push(`Unknown operator: ${condition.operator}`)
        return null
    }
  }

  /**
   * Build equals condition
   */
  private buildEquals(field: string, value: any): string {
    if (value === null) {
      return `${field} IS NULL`
    }
    this.params.push(value)
    return `${field} = ?`
  }

  /**
   * Build not equals condition
   */
  private buildNotEquals(field: string, value: any): string {
    if (value === null) {
      return `${field} IS NOT NULL`
    }
    this.params.push(value)
    return `${field} != ?`
  }

  /**
   * Build comparison condition (>, >=, <, <=)
   */
  private buildComparison(field: string, operator: string, value: any): string {
    this.params.push(value)
    return `${field} ${operator} ?`
  }

  /**
   * Build LIKE condition (case-insensitive, all words must be present)
   */
  private buildLike(field: string, value: string): string {
    const words = value.split(/\s+/).filter(w => w.length > 0)

    if (words.length === 0) {
      return `1=1` // No-op condition
    }

    const conditions = words.map(word => {
      this.params.push(`%${word}%`)
      return `${field} LIKE ?`
    })

    return `(${conditions.join(' AND ')})`
  }

  /**
   * Build CONTAINS condition (case-insensitive substring)
   */
  private buildContains(field: string, value: string): string {
    this.params.push(`%${value}%`)
    return `${field} LIKE ?`
  }

  /**
   * Build IN condition
   */
  private buildIn(field: string, value: any): string {
    let values: any[]

    if (typeof value === 'string') {
      // Parse comma-delimited string
      values = value.split(',').map(v => v.trim()).filter(v => v.length > 0)
    } else if (Array.isArray(value)) {
      values = value
    } else {
      values = [value]
    }

    if (values.length === 0) {
      return `1=0` // No values means no matches
    }

    const placeholders = values.map(v => {
      this.params.push(v)
      return '?'
    }).join(', ')

    return `${field} IN (${placeholders})`
  }

  /**
   * Build NOT IN condition
   */
  private buildNotIn(field: string, value: any): string {
    let values: any[]

    if (typeof value === 'string') {
      // Parse comma-delimited string
      values = value.split(',').map(v => v.trim()).filter(v => v.length > 0)
    } else if (Array.isArray(value)) {
      values = value
    } else {
      values = [value]
    }

    if (values.length === 0) {
      return `1=1` // No values means all match
    }

    const placeholders = values.map(v => {
      this.params.push(v)
      return '?'
    }).join(', ')

    return `${field} NOT IN (${placeholders})`
  }

  /**
   * Build ALL condition (value must contain all items in list)
   * For SQLite, we'll check if a JSON array contains all values
   */
  private buildAll(field: string, value: any): string {
    let values: any[]

    if (typeof value === 'string') {
      values = value.split(',').map(v => v.trim()).filter(v => v.length > 0)
    } else if (Array.isArray(value)) {
      values = value
    } else {
      values = [value]
    }

    if (values.length === 0) {
      return `1=1`
    }

    // For SQLite, check if field contains all values using JSON functions
    // This assumes the field is a JSON array or comma-separated string
    const conditions = values.map(val => {
      this.params.push(`%${val}%`)
      return `${field} LIKE ?`
    })

    return `(${conditions.join(' AND ')})`
  }

  /**
   * Build EXISTS condition
   */
  private buildExists(field: string, value: boolean): string {
    if (value) {
      return `${field} IS NOT NULL AND ${field} != ''`
    } else {
      return `(${field} IS NULL OR ${field} = '')`
    }
  }

  /**
   * Sanitize field names to prevent SQL injection
   */
  private sanitizeFieldName(field: string): string {
    // Allow alphanumeric, underscores, dots (for JSON fields)
    const sanitized = field.replace(/[^a-zA-Z0-9_$.]/g, '')

    // Handle JSON field access (e.g., data.title -> json_extract(data, '$.title'))
    if (sanitized.includes('.')) {
      const [table, ...path] = sanitized.split('.')
      return `json_extract(${table}, '$.${path.join('.')}')`
    }

    return sanitized
  }

  /**
   * Sanitize sort order to prevent SQL injection
   * Only allows 'ASC' or 'DESC', defaults to 'ASC' for any other value
   */
  private sanitizeSortOrder(order: string): string {
    const normalized = String(order).toUpperCase().trim()
    if (normalized === 'ASC' || normalized === 'DESC') {
      return normalized
    }
    return 'ASC'
  }

  /**
   * Parse filter from query string
   */
  static parseFromQuery(query: Record<string, any>): QueryFilter {
    const filter: QueryFilter = {}

    // Parse where clause from 'where' parameter (JSON string)
    if (query.where) {
      try {
        filter.where = typeof query.where === 'string'
          ? JSON.parse(query.where)
          : query.where
      } catch (e) {
        console.error('Failed to parse where clause:', e)
      }
    }

    // Initialize where clause if not present
    if (!filter.where) {
      filter.where = { and: [] }
    }
    if (!filter.where.and) {
      filter.where.and = []
    }

    // Parse simple field filters (status, collection_id, etc.)
    // These are convenience parameters that get converted to WHERE conditions
    const simpleFieldMappings: Record<string, string> = {
      'status': 'status',
      'collection_id': 'collection_id'
    }

    for (const [queryParam, dbField] of Object.entries(simpleFieldMappings)) {
      if (query[queryParam]) {
        filter.where.and.push({
          field: dbField,
          operator: 'equals',
          value: query[queryParam]
        })
      }
    }

    // Parse limit
    if (query.limit) {
      filter.limit = Math.min(parseInt(query.limit), 1000) // Max 1000
    }

    // Parse offset
    if (query.offset) {
      filter.offset = parseInt(query.offset)
    }

    // Parse sort
    if (query.sort) {
      try {
        const parsed = typeof query.sort === 'string'
          ? JSON.parse(query.sort)
          : query.sort
        // Validate and sanitize sort entries
        if (Array.isArray(parsed)) {
          filter.sort = parsed
            .filter((s: any) => s && typeof s.field === 'string')
            .map((s: any) => ({
              field: s.field,
              order: validateSortOrder(s.order)
            }))
        }
      } catch (e) {
        console.error('Failed to parse sort clause:', e)
      }
    }

    return filter
  }
}

/**
 * Helper function to build query from filter
 */
export function buildQuery(table: string, filter: QueryFilter): QueryResult {
  const builder = new QueryFilterBuilder()
  return builder.build(table, filter)
}
