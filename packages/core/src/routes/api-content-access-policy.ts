import type { FilterCondition, FilterGroup, QueryFilter } from '../utils/query-filter'

function canReadNonPublicContent(userRole?: string): boolean {
  return userRole === 'admin' || userRole === 'editor'
}

function isStatusCondition(condition: FilterCondition): boolean {
  return condition.field === 'status'
}

function stripStatusConditions(group?: FilterGroup): FilterGroup | undefined {
  if (!group) {
    return undefined
  }

  const and = group.and?.filter(condition => !isStatusCondition(condition))
  const or = group.or?.filter(condition => !isStatusCondition(condition))

  const normalizedGroup: FilterGroup = {}

  if (and && and.length > 0) {
    normalizedGroup.and = and
  }

  if (or && or.length > 0) {
    normalizedGroup.or = or
  }

  return normalizedGroup
}

export function normalizePublicContentFilter(filter: QueryFilter, userRole?: string): QueryFilter {
  if (canReadNonPublicContent(userRole)) {
    return filter
  }

  const normalizedFilter: QueryFilter = {
    ...filter,
    where: stripStatusConditions(filter.where)
  }

  if (!normalizedFilter.where) {
    normalizedFilter.where = { and: [] }
  }

  if (!normalizedFilter.where.and) {
    normalizedFilter.where.and = []
  }

  normalizedFilter.where.and.push({
    field: 'status',
    operator: 'equals',
    value: 'published'
  })

  return normalizedFilter
}
