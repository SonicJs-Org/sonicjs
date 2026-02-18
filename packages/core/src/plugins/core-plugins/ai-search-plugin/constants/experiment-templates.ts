/**
 * Experiment Templates & Testable Settings
 *
 * Static data for the A/B Tests admin UI — template picker, visual settings
 * editor, and recommendation engine. Pure data, no runtime dependencies.
 */

export interface ExperimentTemplate {
  id: string
  name: string
  description: string
  category: 'relevance' | 'performance' | 'features' | 'comprehensive'
  mode: 'ab' | 'interleave'
  mode_rationale: string
  traffic_pct: number
  split_ratio: number
  min_searches: number
  overrides: Record<string, unknown>
  why: string
  good_for: string
}

export interface TestableSetting {
  key: string
  label: string
  type: 'number' | 'boolean'
  default_value: number | boolean
  min?: number
  max?: number
  step?: number
}

export const DEFAULT_SETTINGS: Record<string, number | boolean> = {
  fts5_title_boost: 5.0,
  fts5_slug_boost: 2.0,
  fts5_body_boost: 1.0,
  query_rewriting_enabled: false,
  reranking_enabled: true,
  query_synonyms_enabled: true,
  results_limit: 20,
  cache_duration: 1,
  facets_enabled: false,
}

export const TESTABLE_SETTINGS: TestableSetting[] = [
  { key: 'fts5_title_boost', label: 'Title Weight', type: 'number', default_value: 5.0, min: 0, max: 20, step: 0.5 },
  { key: 'fts5_slug_boost', label: 'Slug Weight', type: 'number', default_value: 2.0, min: 0, max: 10, step: 0.5 },
  { key: 'fts5_body_boost', label: 'Body Weight', type: 'number', default_value: 1.0, min: 0, max: 10, step: 0.5 },
  { key: 'query_rewriting_enabled', label: 'Query Rewriting', type: 'boolean', default_value: false },
  { key: 'reranking_enabled', label: 'Reranking', type: 'boolean', default_value: true },
  { key: 'query_synonyms_enabled', label: 'Synonyms', type: 'boolean', default_value: true },
  { key: 'results_limit', label: 'Results per Page', type: 'number', default_value: 20, min: 5, max: 100, step: 5 },
  { key: 'cache_duration', label: 'Cache Duration (hours)', type: 'number', default_value: 1, min: 0, max: 24, step: 1 },
  { key: 'facets_enabled', label: 'Faceted Search', type: 'boolean', default_value: false },
]

export const EXPERIMENT_TEMPLATES: ExperimentTemplate[] = [
  {
    id: 'title-boost',
    name: 'Title Relevance Boost',
    description: 'Double the title weight to prioritize title matches over body content',
    category: 'relevance',
    mode: 'interleave',
    mode_rationale: 'Interleaving converges faster for relevance changes — users see both rankings side-by-side',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 200,
    overrides: { fts5_title_boost: 10 },
    why: 'Title matches are often the strongest relevance signal. Doubling the weight can significantly improve result quality for sites with descriptive titles.',
    good_for: 'Sites with descriptive, keyword-rich titles',
  },
  {
    id: 'body-focus',
    name: 'Body Content Focus',
    description: 'Increase body weight to surface results from long-form content',
    category: 'relevance',
    mode: 'interleave',
    mode_rationale: 'Interleaving converges faster for relevance changes — users see both rankings side-by-side',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 200,
    overrides: { fts5_body_boost: 3 },
    why: 'Blogs and documentation often have the best matches buried in body text. Boosting body weight helps surface these.',
    good_for: 'Blogs, documentation sites, long-form content',
  },
  {
    id: 'query-rewriting',
    name: 'Enable Query Rewriting',
    description: 'Use AI to rewrite ambiguous queries for better recall',
    category: 'features',
    mode: 'ab',
    mode_rationale: 'A/B split is better for feature toggles — measures overall impact on user satisfaction',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 300,
    overrides: { query_rewriting_enabled: true },
    why: 'Query rewriting can dramatically reduce zero-result searches by expanding or reformulating user queries.',
    good_for: 'Sites with high zero-result rates or ambiguous queries',
  },
  {
    id: 'disable-reranking',
    name: 'Disable Reranking',
    description: 'Skip the reranking step to test if it improves speed without hurting quality',
    category: 'performance',
    mode: 'ab',
    mode_rationale: 'A/B split measures the impact on click-through rate when reranking is removed',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 200,
    overrides: { reranking_enabled: false },
    why: 'Reranking adds latency. If your initial ranking is good enough, disabling it can improve response times.',
    good_for: 'Speed-critical sites with acceptable baseline relevance',
  },
  {
    id: 'compact-results',
    name: 'Compact Results',
    description: 'Reduce results per page from 20 to 10 to increase visibility of top results',
    category: 'performance',
    mode: 'ab',
    mode_rationale: 'A/B split measures whether fewer results leads to higher engagement with top results',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 300,
    overrides: { results_limit: 10 },
    why: 'Showing fewer results focuses user attention on the best matches. Can improve CTR if your ranking is good.',
    good_for: 'Sites with low CTR or when users rarely scroll past first few results',
  },
  {
    id: 'enable-facets',
    name: 'Enable Faceted Search',
    description: 'Turn on faceted search to let users filter results by collection and fields',
    category: 'features',
    mode: 'ab',
    mode_rationale: 'A/B split measures whether facets improve user engagement and reduce zero-result frustration',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 300,
    overrides: { facets_enabled: true },
    why: 'Facets help users narrow down results, especially useful for sites with diverse content across multiple collections.',
    good_for: 'Multi-collection sites with diverse content types',
  },
  {
    id: 'aggressive-title-slug',
    name: 'Aggressive Title + Slug',
    description: 'Maximize title and slug weights together for URL-keyword-heavy sites',
    category: 'relevance',
    mode: 'interleave',
    mode_rationale: 'Interleaving converges faster for relevance changes — users see both rankings side-by-side',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 200,
    overrides: { fts5_title_boost: 10, fts5_slug_boost: 5 },
    why: 'When URLs contain meaningful keywords, boosting slug weight alongside title weight reinforces exact-match relevance.',
    good_for: 'Sites with descriptive URLs and keyword-rich slugs',
  },
  {
    id: 'full-ai-enhancement',
    name: 'Full AI Enhancement',
    description: 'Enable both query rewriting and synonyms for maximum recall',
    category: 'comprehensive',
    mode: 'interleave',
    mode_rationale: 'Interleaving lets you compare enhanced vs baseline results on the same queries',
    traffic_pct: 100,
    split_ratio: 0.5,
    min_searches: 300,
    overrides: { query_rewriting_enabled: true, query_synonyms_enabled: true },
    why: 'Combining query rewriting with synonym expansion provides the widest recall improvement, ideal for reducing zero-result rates.',
    good_for: 'Sites with high zero-result rates or diverse query vocabulary',
  },
]
