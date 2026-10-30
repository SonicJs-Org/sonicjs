/**
 * AI Search Plugin — Payload-shaped port.
 *
 * Advanced search via Cloudflare AI Search: semantic queries, full-text,
 * filters, autocomplete, dynamic collection discovery.
 *
 * @example
 * ```typescript
 * import { AISearchService } from '@sonicjs-cms/core/plugins'
 *
 * const service = new AISearchService(db, aiSearch)
 * const results = await service.search({
 *   query: 'blog posts about security',
 *   mode: 'ai',
 *   filters: { collections: [1, 2] }
 * })
 * ```
 */

import { definePlugin } from '../../sdk/define-plugin'
import { AISearchService } from './services/ai-search'
import { IndexManager } from './services/indexer'
import adminRoutes from './routes/admin'
import apiRoutes from './routes/api'
import manifest from './manifest.json'

export const aiSearchPlugin = definePlugin({
  id: manifest.id,
  version: manifest.version,
  name: manifest.name,
  description: manifest.description,
  sonicjsVersionRange: '^3.0.0',
  author: { name: manifest.author },

  register(app) {
    app.route('/admin/plugins/ai-search', adminRoutes as any)
    app.route('/api/search', apiRoutes as any)
  },
})

// Re-exports
// Exported so app.ts can mount /api/search ahead of the generic /api/:collection
// catch-all, which would otherwise shadow it (see app.ts).
export { apiRoutes as aiSearchApiRoutes }
export { AISearchService }
export { IndexManager }
export type {
  AISearchSettings,
  SearchQuery,
  SearchResponse,
  SearchResult,
  CollectionInfo,
  IndexStatus,
} from './types'
