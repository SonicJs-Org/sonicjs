import { PluginBuilder } from '../../sdk/plugin-builder'
import { AISearchService } from './services/ai-search'
import { IndexManager } from './services/indexer'
import adminRoutes from './routes/admin'
import apiRoutes from './routes/api'
import manifest from './manifest.json'

/**
 * AI Search Plugin
 * 
 * Provides advanced search capabilities using Cloudflare AI Search.
 * Features:
 * - Semantic/AI-powered search with natural language queries
 * - Traditional keyword search
 * - Full-text search across all content collections
 * - Advanced filtering (collections, dates, status, tags)
 * - Autocomplete suggestions
 * - Search analytics
 * - Dynamic collection discovery and indexing
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

export const aiSearchPlugin = new PluginBuilder({
  // Use manifest.id (not manifest.name) so the plugin's name matches its
  // DB row id — mountPluginManagerRoutes' isPluginEnabled gate looks up
  // `plugins.id`, and a mismatch returns 404 on every request.
  name: manifest.id,
  version: manifest.version,
  description: manifest.description,
  author: { name: manifest.author },
})
  .metadata({
    description: manifest.description,
    author: { name: manifest.author },
  })
  .addService('aiSearch', AISearchService)
  .addService('indexManager', IndexManager)
  .addRoute('/admin/plugins/ai-search', adminRoutes as any)
  .addRoute('/api/search', apiRoutes as any)
  .build()

// Export services and types for easy import
export { AISearchService } from './services/ai-search'
export { IndexManager } from './services/indexer'
export type {
  AISearchSettings,
  SearchQuery,
  SearchResponse,
  SearchResult,
  CollectionInfo,
  IndexStatus,
} from './types'
