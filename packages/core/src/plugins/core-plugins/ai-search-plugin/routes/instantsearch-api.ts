/**
 * InstantSearch-Compatible API
 *
 * Algolia-protocol endpoint that enables any InstantSearch.js / React / Vue
 * frontend to use SonicJS search as a drop-in replacement for Algolia.
 *
 * Usage (client-side):
 *   const searchClient = {
 *     search(requests) {
 *       return fetch('/api/instantsearch', {
 *         method: 'POST',
 *         headers: { 'Content-Type': 'application/json' },
 *         body: JSON.stringify({ requests })
 *       }).then(r => r.json());
 *     }
 *   };
 */

import { Hono } from 'hono'
import type { Bindings } from '../../../../app'
import { AISearchService } from '../services/ai-search'
import { InstantSearchAdapter } from '../services/instantsearch-adapter'
import type { InstantSearchRequest, InstantSearchMultiResponse } from '../types'

const instantSearchRoutes = new Hono<{ Bindings: Bindings }>()

/**
 * POST /api/instantsearch
 *
 * Accepts Algolia multi-search format:
 *   { requests: [{ indexName, params: { query, page, hitsPerPage, ... } }] }
 *
 * Returns Algolia-compatible response:
 *   { results: [{ hits, nbHits, page, nbPages, hitsPerPage, processingTimeMS, ... }] }
 */
instantSearchRoutes.post('/', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX

    const searchService = new AISearchService(db, ai, vectorize)
    const adapter = new InstantSearchAdapter(db)

    // Parse request
    const body = await c.req.json<{ requests?: InstantSearchRequest[] }>()

    if (!body.requests || !Array.isArray(body.requests)) {
      return c.json(
        { message: 'Invalid request format. Expected { requests: [...] }', status: 400 },
        400
      )
    }

    // Check if plugin is enabled
    const settings = await searchService.getSettings()
    if (!settings?.enabled) {
      return c.json({
        results: body.requests.map((req) => emptyResult(req)),
      } as InstantSearchMultiResponse)
    }

    // Process all search requests in parallel
    const results = await Promise.all(
      body.requests.map(async (request) => {
        const requestStart = Date.now()
        try {
          const sonicQuery = await adapter.toSonicQuery(request, settings)
          const sonicResponse = await searchService.search(sonicQuery)
          return adapter.toInstantSearchResult(
            sonicResponse,
            request,
            Date.now() - requestStart
          )
        } catch (error) {
          console.error('[InstantSearch] Request error:', error)
          return emptyResult(request, Date.now() - requestStart)
        }
      })
    )

    return c.json({ results } as InstantSearchMultiResponse)
  } catch (error) {
    console.error('[InstantSearch] Error:', error)
    return c.json(
      { message: 'Search request failed', status: 500 },
      500
    )
  }
})

/** Build a well-formed empty result so InstantSearch.js never crashes. */
function emptyResult(request: InstantSearchRequest, processingTimeMS = 0) {
  const params = request.params || {}
  return {
    hits: [],
    nbHits: 0,
    page: params.page ?? 0,
    nbPages: 0,
    hitsPerPage: params.hitsPerPage ?? 20,
    processingTimeMS,
    query: params.query || '',
    params: '',
    exhaustiveNbHits: true,
    index: request.indexName,
  }
}

export default instantSearchRoutes
