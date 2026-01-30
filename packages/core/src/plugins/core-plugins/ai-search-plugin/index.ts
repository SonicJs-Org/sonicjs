import { PluginBuilder } from '../../sdk/plugin-builder'
import manifest from './manifest.json'
import adminRoutes from './routes/admin'
import apiRoutes from './routes/api'
import integrationGuideRoutes from './routes/integration-guide'
import testPageRoutes from './routes/test-page'
import { AISearchService } from './services/ai-search'
import { IndexManager } from './services/indexer'

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
  name: manifest.name,
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
  .addRoute('/admin/plugins/ai-search', testPageRoutes as any)
  .addRoute('/admin/plugins/ai-search', integrationGuideRoutes as any)
  .build()

// Export services and types for easy import
export { AISearchService } from './services/ai-search'
export { IndexManager } from './services/indexer'
export type {
  AISearchSettings, CollectionInfo,
  IndexStatus, SearchQuery,
  SearchResponse,
  SearchResult
} from './types'

