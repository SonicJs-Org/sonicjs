import type { SearchResult, InterleaveOutput } from '../types'

/**
 * Team Draft Interleaving — merge results from two rankers into a single list.
 * Each item is tagged with its origin (control/treatment) for click attribution.
 * Pure functions, no external dependencies.
 */

/**
 * Team Draft interleave: alternately pick from two ranked lists.
 * A coin flip decides who picks first each round. Duplicates are skipped.
 */
export function teamDraftInterleave(
  controlResults: SearchResult[],
  treatmentResults: SearchResult[],
  limit: number
): InterleaveOutput {
  const results: SearchResult[] = []
  const origins: Record<string, 'control' | 'treatment'> = {}
  const seen = new Set<string>()

  let ci = 0 // control pointer
  let ti = 0 // treatment pointer

  while (results.length < limit && (ci < controlResults.length || ti < treatmentResults.length)) {
    // Coin flip: who picks first this round
    const controlFirst = Math.random() < 0.5

    const order: Array<{ list: SearchResult[]; ptr: () => number; advance: () => void; origin: 'control' | 'treatment' }> = [
      { list: controlResults, ptr: () => ci, advance: () => { ci++ }, origin: 'control' },
      { list: treatmentResults, ptr: () => ti, advance: () => { ti++ }, origin: 'treatment' },
    ]
    if (!controlFirst) order.reverse()

    for (const { list, ptr, advance, origin } of order) {
      if (results.length >= limit) break
      // Pick the next unseen item from this list
      while (ptr() < list.length) {
        const item = list[ptr()]!
        advance()
        if (!seen.has(item.id)) {
          seen.add(item.id)
          results.push(item)
          origins[item.id] = origin
          break
        }
      }
    }
  }

  return { results, origins }
}

/**
 * Credit a click to its originating variant.
 * Returns undefined if the content_id isn't in the origin map (unattributed click).
 */
export function creditClick(
  origins: Record<string, 'control' | 'treatment'>,
  contentId: string
): 'control' | 'treatment' | undefined {
  return origins[contentId]
}

/**
 * Compute preference score from per-query win counts.
 * preference > 0.5 means treatment is preferred.
 * Returns null if no decisive queries.
 */
export function computePreference(
  controlWins: number,
  treatmentWins: number
): number | null {
  const total = controlWins + treatmentWins
  if (total === 0) return null
  return treatmentWins / total
}
