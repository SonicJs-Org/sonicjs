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
    // NOTE: /api/search is mounted in app.ts BEFORE the /api/:collection catch-all. Plugin
    // register() runs after that catch-all, so mounting it here would be shadowed.
  },
})

// Re-exports
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
