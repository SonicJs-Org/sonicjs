/**
 * Benchmark Service — BEIR Evaluation (KV-Backed)
 *
 * Provides seeding, purging, and evaluation of BEIR benchmark datasets
 * against the AI Search plugin's search modes.
 *
 * Dataset data (corpus, queries, qrels) is stored in KV and loaded on demand.
 * Supports multiple datasets: SciFact, NFCorpus, FiQA-2018, etc.
 *
 * Metrics computed: nDCG@k, Precision@k, Recall@k, MRR
 */

import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import {
  BENCHMARK_DATASETS,
  type DatasetInfo,
  type BenchmarkDocument,
  type BenchmarkQuery,
  type BenchmarkQrel,
} from '../data/benchmark-datasets'

// --- Result Types ---

export interface BenchmarkResults {
  mode: string
  limit: number
  corpus_size: number
  queries_evaluated: number
  total_time_ms: number
  avg_query_time_ms: number
  metrics: {
    ndcg_at_k: number
    precision_at_k: number
    recall_at_k: number
    mrr: number
  }
  per_query: PerQueryResult[]
}

export interface PerQueryResult {
  query_id: string
  query_text: string
  ndcg: number
  precision: number
  recall: number
  mrr: number
  hits: number
  expected: number
  returned: number
  query_time_ms: number
}

export interface SeedResult {
  seeded: number
  skipped: boolean
}

export interface SeedProgress {
  phase: 'inserting' | 'complete'
  inserted: number
  total: number
}

interface BenchmarkData {
  corpus: BenchmarkDocument[]
  queries: BenchmarkQuery[]
  qrels: BenchmarkQrel[]
}

export class BenchmarkService {
  private dataset: string
  private data: BenchmarkData | null = null
  private idPrefix: string
  private collectionId: string

  constructor(
    private db: D1Database,
    private kv: KVNamespace,
    private vectorize?: any,
    dataset: string = 'scifact'
  ) {
    this.dataset = dataset
    this.idPrefix = `beir-${dataset}-`
    this.collectionId = `benchmark-${dataset}-collection`
    if (!BENCHMARK_DATASETS.find((d) => d.id === dataset)) {
      throw new Error(`Unknown benchmark dataset: ${dataset}`)
    }
  }

  /**
   * Load dataset from KV on first access. Cached for lifetime of the service instance.
   */
  private async loadData(): Promise<BenchmarkData> {
    if (this.data) return this.data

    const [corpus, queries, qrels] = await Promise.all([
      this.kv.get<BenchmarkDocument[]>(
        `benchmark:${this.dataset}:corpus`,
        'json'
      ),
      this.kv.get<BenchmarkQuery[]>(
        `benchmark:${this.dataset}:queries`,
        'json'
      ),
      this.kv.get<BenchmarkQrel[]>(
        `benchmark:${this.dataset}:qrels`,
        'json'
      ),
    ])

    if (!corpus || !queries || !qrels) {
      throw new Error(
        `Benchmark dataset "${this.dataset}" not found in KV. Run: npx tsx scripts/generate-benchmark-data.ts --dataset ${this.dataset}`
      )
    }

    this.data = { corpus, queries, qrels }
    return this.data
  }

  /**
   * Get the subset of corpus documents: only those referenced in qrels + noise.
   * Deterministic selection (sorted by ID) so results are reproducible.
   */
  private async getSubsetCorpus(): Promise<BenchmarkDocument[]> {
    const { corpus, qrels } = await this.loadData()
    const relevantDocIds = new Set(qrels.map((qr) => qr.doc_id))
    const relevantDocs = corpus.filter((doc) => relevantDocIds.has(doc._id))
    // Deterministic noise: sorted by ID, take first 200 non-relevant
    const noiseDocs = corpus
      .filter((doc) => !relevantDocIds.has(doc._id))
      .slice(0, 200)
    return [...relevantDocs, ...noiseDocs]
  }

  /**
   * Seed benchmark documents into the content table.
   * Uses a dedicated collection per dataset created on-the-fly.
   * Idempotent — skips if data already exists.
   */
  async seed(
    authorId: string,
    useSubset: boolean = true,
    onProgress?: (progress: SeedProgress) => void
  ): Promise<SeedResult> {
    // Check if already seeded
    const existing = await this.db
      .prepare(
        `SELECT COUNT(*) as count FROM content WHERE id LIKE '${this.idPrefix}%'`
      )
      .first<{ count: number }>()

    if (existing && existing.count > 0) {
      return { seeded: existing.count, skipped: true }
    }

    // Ensure a benchmark collection exists
    const collectionId = await this.ensureBenchmarkCollection()

    // Choose corpus based on subset flag
    const { corpus: fullCorpus } = await this.loadData()
    const corpus = useSubset ? await this.getSubsetCorpus() : fullCorpus

    const now = Date.now()
    const batchSize = 50
    let inserted = 0

    for (let i = 0; i < corpus.length; i += batchSize) {
      const batch = corpus.slice(i, i + batchSize)

      const batchOps = batch.map((doc) => {
        const id = `${this.idPrefix}${doc._id}`
        const slug = `${this.idPrefix}${doc._id}`
        // Wrap in <p> tags for richtext editor compatibility, escape HTML entities
        const safeText = doc.text
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
        const data = JSON.stringify({
          content: `<p>${safeText}</p>`,
          excerpt: doc.text.substring(0, 200),
          tags: [`beir-${this.dataset}`, 'benchmark'],
        })

        return this.db
          .prepare(
            `INSERT OR IGNORE INTO content
             (id, collection_id, slug, title, data, status, author_id, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 'published', ?, ?, ?)`
          )
          .bind(id, collectionId, slug, doc.title, data, authorId, now, now)
      })

      await this.db.batch(batchOps)
      inserted += batch.length

      if (onProgress) {
        onProgress({
          phase: 'inserting',
          inserted,
          total: corpus.length,
        })
      }
    }

    if (onProgress) {
      onProgress({
        phase: 'complete',
        inserted: corpus.length,
        total: corpus.length,
      })
    }

    return { seeded: corpus.length, skipped: false }
  }

  /**
   * Remove all benchmark documents and related index entries for this dataset.
   */
  async purge(): Promise<number> {
    // Delete from content (also removes from FTS5 via sync tracking)
    const result = await this.db
      .prepare(
        `DELETE FROM content WHERE id LIKE '${this.idPrefix}%'`
      )
      .run()

    // Clean up FTS5 index entries
    try {
      await this.db.batch([
        this.db.prepare(
          `DELETE FROM content_fts WHERE content_id LIKE '${this.idPrefix}%'`
        ),
        this.db.prepare(
          `DELETE FROM content_fts_sync WHERE content_id LIKE '${this.idPrefix}%'`
        ),
      ])
    } catch (error) {
      // FTS5 tables might not exist yet
      console.warn('[BenchmarkService] FTS5 cleanup skipped:', error)
    }

    // Remove the benchmark collection itself
    try {
      await this.db
        .prepare('DELETE FROM collections WHERE id = ?')
        .bind(this.collectionId)
        .run()
    } catch (error) {
      console.warn('[BenchmarkService] Collection cleanup skipped:', error)
    }

    // Remove index meta
    try {
      await this.db
        .prepare(
          'DELETE FROM ai_search_index_meta WHERE collection_id = ?'
        )
        .bind(this.collectionId)
        .run()
    } catch (error) {
      // Table might not exist
    }

    // Clean up Vectorize vectors for benchmark data
    if (this.vectorize) {
      try {
        const { corpus } = await this.loadData()
        const vectorIds: string[] = []
        for (const doc of corpus) {
          // Chunk IDs are {idPrefix}{docId}-chunk-{0..N}
          for (let i = 0; i < 5; i++) {
            vectorIds.push(`${this.idPrefix}${doc._id}-chunk-${i}`)
          }
        }

        // Vectorize deleteByIds accepts up to 1000 IDs per call
        const batchSize = 1000
        for (let i = 0; i < vectorIds.length; i += batchSize) {
          const batch = vectorIds.slice(i, i + batchSize)
          await this.vectorize.deleteByIds(batch)
        }
        console.log(
          `[BenchmarkService] Deleted up to ${vectorIds.length} vectors from Vectorize`
        )
      } catch (error) {
        console.warn(
          '[BenchmarkService] Vectorize cleanup error (non-fatal):',
          error
        )
      }
    }

    return result.meta?.changes || 0
  }

  /**
   * Run benchmark queries against a search function and compute IR metrics.
   */
  async evaluate(
    searchFn: (
      query: string,
      mode: string,
      limit: number
    ) => Promise<{ results: Array<{ id: string }> }>,
    mode: string = 'fts5',
    limit: number = 10,
    maxQueries: number = 0
  ): Promise<BenchmarkResults> {
    const { corpus, queries, qrels } = await this.loadData()
    const startTime = Date.now()
    const perQuery: PerQueryResult[] = []

    // Build qrels lookup: query_id -> Map<doc_id, score>
    const qrelsMap = new Map<string, Map<string, number>>()
    for (const qrel of qrels) {
      if (!qrelsMap.has(qrel.query_id))
        qrelsMap.set(qrel.query_id, new Map())
      qrelsMap.get(qrel.query_id)!.set(qrel.doc_id, qrel.score)
    }

    // Only evaluate queries that have relevance judgments
    const queriesWithJudgments = queries.filter(
      (q) => qrelsMap.has(q._id) && qrelsMap.get(q._id)!.size > 0
    )

    const queriesToRun =
      maxQueries > 0
        ? queriesWithJudgments.slice(0, maxQueries)
        : queriesWithJudgments

    let totalNDCG = 0
    let totalPrecision = 0
    let totalRecall = 0
    let totalMRR = 0

    for (const query of queriesToRun) {
      const relevantDocs = qrelsMap.get(query._id)!

      const queryStart = Date.now()
      let response: { results: Array<{ id: string }> }

      try {
        response = await searchFn(query.text, mode, limit)
      } catch (error) {
        console.error(
          `[BenchmarkService] Search error for query ${query._id}:`,
          error
        )
        perQuery.push({
          query_id: query._id,
          query_text: query.text,
          ndcg: 0,
          precision: 0,
          recall: 0,
          mrr: 0,
          hits: 0,
          expected: relevantDocs.size,
          returned: 0,
          query_time_ms: Date.now() - queryStart,
        })
        continue
      }

      const queryTime = Date.now() - queryStart

      // Extract BEIR doc IDs from content IDs (strip dataset prefix)
      const rankedDocIds = response.results.map((r) =>
        r.id.startsWith(this.idPrefix)
          ? r.id.slice(this.idPrefix.length)
          : r.id
      )

      const ndcg = computeNDCG(rankedDocIds, relevantDocs, limit)
      const precision = computePrecision(rankedDocIds, relevantDocs, limit)
      const recall = computeRecall(rankedDocIds, relevantDocs)
      const mrr = computeMRR(rankedDocIds, relevantDocs)

      totalNDCG += ndcg
      totalPrecision += precision
      totalRecall += recall
      totalMRR += mrr

      perQuery.push({
        query_id: query._id,
        query_text: query.text,
        ndcg,
        precision,
        recall,
        mrr,
        hits: rankedDocIds.filter((id) => relevantDocs.has(id)).length,
        expected: relevantDocs.size,
        returned: rankedDocIds.length,
        query_time_ms: queryTime,
      })
    }

    const totalTime = Date.now() - startTime
    const evaluated = queriesToRun.length

    return {
      mode,
      limit,
      corpus_size: corpus.length,
      queries_evaluated: evaluated,
      total_time_ms: totalTime,
      avg_query_time_ms:
        evaluated > 0 ? Math.round(totalTime / evaluated) : 0,
      metrics: {
        ndcg_at_k: evaluated > 0 ? totalNDCG / evaluated : 0,
        precision_at_k: evaluated > 0 ? totalPrecision / evaluated : 0,
        recall_at_k: evaluated > 0 ? totalRecall / evaluated : 0,
        mrr: evaluated > 0 ? totalMRR / evaluated : 0,
      },
      per_query: perQuery,
    }
  }

  /**
   * Get the list of query IDs that have relevance judgments, optionally limited.
   */
  async getEvaluableQueryIds(maxQueries: number = 0): Promise<string[]> {
    const { queries, qrels } = await this.loadData()

    const qrelsMap = new Map<string, Map<string, number>>()
    for (const qrel of qrels) {
      if (!qrelsMap.has(qrel.query_id))
        qrelsMap.set(qrel.query_id, new Map())
      qrelsMap.get(qrel.query_id)!.set(qrel.doc_id, qrel.score)
    }

    const ids = queries
      .filter((q) => qrelsMap.has(q._id) && qrelsMap.get(q._id)!.size > 0)
      .map((q) => q._id)

    return maxQueries > 0 ? ids.slice(0, maxQueries) : ids
  }

  /**
   * Evaluate a batch of queries by their IDs.
   * Returns per-query results for the batch so the client can accumulate and compute aggregates.
   */
  async evaluateBatch(
    searchFn: (
      query: string,
      mode: string,
      limit: number
    ) => Promise<{ results: Array<{ id: string }> }>,
    mode: string,
    limit: number,
    queryIds: string[]
  ): Promise<PerQueryResult[]> {
    const { queries, qrels } = await this.loadData()

    // Build qrels lookup
    const qrelsMap = new Map<string, Map<string, number>>()
    for (const qrel of qrels) {
      if (!qrelsMap.has(qrel.query_id))
        qrelsMap.set(qrel.query_id, new Map())
      qrelsMap.get(qrel.query_id)!.set(qrel.doc_id, qrel.score)
    }

    // Build query lookup
    const queryMap = new Map(queries.map((q) => [q._id, q]))

    const results: PerQueryResult[] = []

    for (const qid of queryIds) {
      const query = queryMap.get(qid)
      const relevantDocs = qrelsMap.get(qid)
      if (!query || !relevantDocs) continue

      const queryStart = Date.now()
      let response: { results: Array<{ id: string }> }

      try {
        response = await searchFn(query.text, mode, limit)
      } catch (error) {
        console.error(
          `[BenchmarkService] Search error for query ${qid}:`,
          error
        )
        results.push({
          query_id: qid,
          query_text: query.text,
          ndcg: 0,
          precision: 0,
          recall: 0,
          mrr: 0,
          hits: 0,
          expected: relevantDocs.size,
          returned: 0,
          query_time_ms: Date.now() - queryStart,
        })
        continue
      }

      const queryTime = Date.now() - queryStart
      const rankedDocIds = response.results.map((r) =>
        r.id.startsWith(this.idPrefix)
          ? r.id.slice(this.idPrefix.length)
          : r.id
      )

      const ndcg = computeNDCG(rankedDocIds, relevantDocs, limit)
      const precision = computePrecision(rankedDocIds, relevantDocs, limit)
      const recall = computeRecall(rankedDocIds, relevantDocs)
      const mrr = computeMRR(rankedDocIds, relevantDocs)

      results.push({
        query_id: qid,
        query_text: query.text,
        ndcg,
        precision,
        recall,
        mrr,
        hits: rankedDocIds.filter((id) => relevantDocs.has(id)).length,
        expected: relevantDocs.size,
        returned: rankedDocIds.length,
        query_time_ms: queryTime,
      })
    }

    return results
  }

  /**
   * Get dataset metadata from the compiled-in registry (no KV needed).
   */
  getMeta(): DatasetInfo {
    return BENCHMARK_DATASETS.find((d) => d.id === this.dataset)!
  }

  getCorpusSize(): number {
    return this.getMeta().corpus_size
  }

  getQueryCount(): number {
    return this.getMeta().query_count
  }

  getDatasetId(): string {
    return this.dataset
  }

  getIdPrefix(): string {
    return this.idPrefix
  }

  getCollectionId(): string {
    return this.collectionId
  }

  async getSubsetSize(): Promise<number> {
    const subset = await this.getSubsetCorpus()
    return subset.length
  }

  /**
   * Check if benchmark data is currently seeded for this dataset.
   */
  async isSeeded(): Promise<{ seeded: boolean; count: number }> {
    const result = await this.db
      .prepare(
        `SELECT COUNT(*) as count FROM content WHERE id LIKE '${this.idPrefix}%'`
      )
      .first<{ count: number }>()
    const count = result?.count || 0
    return { seeded: count > 0, count }
  }

  /**
   * Check if dataset data exists in KV.
   */
  async isDataAvailable(): Promise<boolean> {
    // Just check if the queries key exists (smallest key)
    const queries = await this.kv.get(
      `benchmark:${this.dataset}:queries`
    )
    return queries !== null
  }

  /**
   * Ensure a benchmark collection exists in the collections table.
   * Returns the collection ID.
   */
  private async ensureBenchmarkCollection(): Promise<string> {
    const existing = await this.db
      .prepare('SELECT id FROM collections WHERE id = ?')
      .bind(this.collectionId)
      .first<{ id: string }>()

    if (existing) {
      return this.collectionId
    }

    const meta = this.getMeta()
    const schema = JSON.stringify({
      type: 'object',
      properties: {
        title: { type: 'string', title: 'Title', required: true },
        content: { type: 'string', title: 'Content', format: 'richtext' },
        excerpt: { type: 'string', title: 'Excerpt' },
        tags: { type: 'array', title: 'Tags', items: { type: 'string' } },
      },
      required: ['title'],
    })

    await this.db
      .prepare(
        `INSERT OR IGNORE INTO collections (id, name, display_name, description, schema, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 1, unixepoch(), unixepoch())`
      )
      .bind(
        this.collectionId,
        `benchmark_${this.dataset}`,
        `${meta.name} Benchmark`,
        meta.description,
        schema
      )
      .run()

    return this.collectionId
  }
}

// --- IR Metric Functions ---

/**
 * Normalized Discounted Cumulative Gain at k
 * Measures ranking quality — are relevant docs ranked higher?
 */
function computeNDCG(
  ranked: string[],
  qrels: Map<string, number>,
  k: number
): number {
  let dcg = 0
  for (let i = 0; i < Math.min(ranked.length, k); i++) {
    const rel = qrels.get(ranked[i]!) || 0
    dcg += rel / Math.log2(i + 2) // log2(rank + 1), rank is 1-indexed
  }

  // Ideal DCG: sort relevance scores descending
  const ideal = Array.from(qrels.values())
    .sort((a, b) => b - a)
    .slice(0, k)
  let idcg = 0
  for (let i = 0; i < ideal.length; i++) {
    idcg += ideal[i]! / Math.log2(i + 2)
  }

  return idcg === 0 ? 0 : dcg / idcg
}

/**
 * Precision at k
 * What fraction of top-k results are relevant?
 */
function computePrecision(
  ranked: string[],
  qrels: Map<string, number>,
  k: number
): number {
  const topK = ranked.slice(0, k)
  const hits = topK.filter((id) => (qrels.get(id) || 0) > 0).length
  return hits / k
}

/**
 * Recall at k
 * What fraction of all relevant docs appear in the results?
 */
function computeRecall(
  ranked: string[],
  qrels: Map<string, number>
): number {
  const totalRelevant = Array.from(qrels.values()).filter(
    (v) => v > 0
  ).length
  if (totalRelevant === 0) return 0
  const hits = ranked.filter((id) => (qrels.get(id) || 0) > 0).length
  return hits / totalRelevant
}

/**
 * Mean Reciprocal Rank
 * How early does the first relevant result appear?
 */
function computeMRR(
  ranked: string[],
  qrels: Map<string, number>
): number {
  for (let i = 0; i < ranked.length; i++) {
    if ((qrels.get(ranked[i]!) || 0) > 0) return 1 / (i + 1)
  }
  return 0
}
