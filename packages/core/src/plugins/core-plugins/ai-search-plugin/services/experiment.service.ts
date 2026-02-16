import type {
  Experiment,
  ExperimentStatus,
  ExperimentMode,
  ExperimentMetrics,
  VariantMetrics,
  AISearchSettings,
} from '../types'

/**
 * Analytics Engine dataset binding type (minimal — Cloudflare Workers types).
 * writeDataPoint() is fire-and-forget (non-blocking, returns void).
 */
interface AnalyticsEngineDataset {
  writeDataPoint(data: {
    indexes?: string[]
    blobs?: (string | null)[]
    doubles?: number[]
  }): void
}

interface ExperimentRow {
  id: string
  name: string
  description: string | null
  status: string
  mode: string
  traffic_pct: number
  split_ratio: number
  variants: string
  metrics: string | null
  winner: string | null
  confidence: number | null
  min_searches: number
  started_at: number | null
  ended_at: number | null
  created_at: number
  updated_at: number
}

function rowToExperiment(row: ExperimentRow): Experiment {
  return {
    ...row,
    status: row.status as ExperimentStatus,
    mode: row.mode as ExperimentMode,
    variants: JSON.parse(row.variants),
    metrics: row.metrics ? JSON.parse(row.metrics) : null,
  }
}

export class ExperimentService {
  constructor(
    private db: D1Database,
    private kv?: KVNamespace,
    private analytics?: AnalyticsEngineDataset
  ) {}

  // =============================================
  // CRUD
  // =============================================

  async getAll(options?: { status?: ExperimentStatus; mode?: ExperimentMode; limit?: number; offset?: number }): Promise<Experiment[]> {
    const conditions: string[] = []
    const params: (string | number)[] = []

    if (options?.status) {
      conditions.push('status = ?')
      params.push(options.status)
    }
    if (options?.mode) {
      conditions.push('mode = ?')
      params.push(options.mode)
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''
    const limit = options?.limit || 50
    const offset = options?.offset || 0

    const rows = await this.db
      .prepare(`SELECT * FROM ai_search_experiments ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .bind(...params, limit, offset)
      .all<ExperimentRow>()

    return (rows.results || []).map(rowToExperiment)
  }

  async getById(id: string): Promise<Experiment | null> {
    const row = await this.db
      .prepare('SELECT * FROM ai_search_experiments WHERE id = ?')
      .bind(id)
      .first<ExperimentRow>()
    return row ? rowToExperiment(row) : null
  }

  async create(data: {
    name: string
    description?: string
    mode?: ExperimentMode
    traffic_pct?: number
    split_ratio?: number
    variants: { control: Partial<AISearchSettings>; treatment: Partial<AISearchSettings> }
    min_searches?: number
  }): Promise<Experiment> {
    const id = `exp-${crypto.randomUUID().slice(0, 8)}`
    const now = Date.now()
    await this.db
      .prepare(`
        INSERT INTO ai_search_experiments (id, name, description, mode, traffic_pct, split_ratio, variants, min_searches, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        data.name,
        data.description || null,
        data.mode || 'ab',
        data.traffic_pct ?? 100,
        data.split_ratio ?? 0.5,
        JSON.stringify(data.variants),
        data.min_searches ?? 100,
        now,
        now
      )
      .run()

    return (await this.getById(id))!
  }

  async update(id: string, data: {
    name?: string
    description?: string
    mode?: ExperimentMode
    traffic_pct?: number
    split_ratio?: number
    variants?: { control: Partial<AISearchSettings>; treatment: Partial<AISearchSettings> }
    min_searches?: number
  }): Promise<Experiment | null> {
    const existing = await this.getById(id)
    if (!existing) return null
    if (existing.status !== 'draft') {
      throw new Error('Can only update experiments in draft status')
    }

    const sets: string[] = []
    const params: (string | number | null)[] = []

    if (data.name !== undefined) { sets.push('name = ?'); params.push(data.name) }
    if (data.description !== undefined) { sets.push('description = ?'); params.push(data.description) }
    if (data.mode !== undefined) { sets.push('mode = ?'); params.push(data.mode) }
    if (data.traffic_pct !== undefined) { sets.push('traffic_pct = ?'); params.push(data.traffic_pct) }
    if (data.split_ratio !== undefined) { sets.push('split_ratio = ?'); params.push(data.split_ratio) }
    if (data.variants !== undefined) { sets.push('variants = ?'); params.push(JSON.stringify(data.variants)) }
    if (data.min_searches !== undefined) { sets.push('min_searches = ?'); params.push(data.min_searches) }

    if (sets.length === 0) return existing

    sets.push('updated_at = ?')
    params.push(Date.now())
    params.push(id)

    await this.db
      .prepare(`UPDATE ai_search_experiments SET ${sets.join(', ')} WHERE id = ?`)
      .bind(...params)
      .run()

    return this.getById(id)
  }

  async delete(id: string): Promise<boolean> {
    const existing = await this.getById(id)
    if (!existing) return false
    if (existing.status !== 'draft' && existing.status !== 'archived') {
      throw new Error('Can only delete experiments in draft or archived status')
    }
    await this.db.prepare('DELETE FROM ai_search_experiments WHERE id = ?').bind(id).run()
    return true
  }

  // =============================================
  // Lifecycle
  // =============================================

  async start(id: string): Promise<Experiment> {
    const existing = await this.getById(id)
    if (!existing) throw new Error('Experiment not found')
    if (existing.status !== 'draft' && existing.status !== 'paused') {
      throw new Error(`Cannot start experiment in ${existing.status} status`)
    }

    // Only one experiment can be running at a time
    const running = await this.getAll({ status: 'running' })
    const conflict = running[0]
    if (conflict) {
      throw new Error(`Another experiment is already running: ${conflict.name} (${conflict.id})`)
    }

    const now = Date.now()
    await this.db
      .prepare('UPDATE ai_search_experiments SET status = ?, started_at = COALESCE(started_at, ?), updated_at = ? WHERE id = ?')
      .bind('running', now, now, id)
      .run()

    // Cache active experiment config in KV for fast lookup on every search
    if (this.kv) {
      const experiment = await this.getById(id)
      await this.kv.put('experiment:active', JSON.stringify(experiment), { expirationTtl: 86400 })
    }

    return (await this.getById(id))!
  }

  async pause(id: string): Promise<Experiment> {
    const existing = await this.getById(id)
    if (!existing) throw new Error('Experiment not found')
    if (existing.status !== 'running') {
      throw new Error('Can only pause running experiments')
    }

    await this.db
      .prepare('UPDATE ai_search_experiments SET status = ?, updated_at = ? WHERE id = ?')
      .bind('paused', Date.now(), id)
      .run()

    if (this.kv) await this.kv.delete('experiment:active')
    return (await this.getById(id))!
  }

  async complete(id: string, winner?: string): Promise<Experiment> {
    const existing = await this.getById(id)
    if (!existing) throw new Error('Experiment not found')
    if (existing.status !== 'running' && existing.status !== 'paused') {
      throw new Error(`Cannot complete experiment in ${existing.status} status`)
    }

    const now = Date.now()
    await this.db
      .prepare('UPDATE ai_search_experiments SET status = ?, winner = ?, ended_at = ?, updated_at = ? WHERE id = ?')
      .bind('completed', winner || existing.winner, now, now, id)
      .run()

    if (this.kv) await this.kv.delete('experiment:active')
    return (await this.getById(id))!
  }

  async archive(id: string): Promise<Experiment> {
    const existing = await this.getById(id)
    if (!existing) throw new Error('Experiment not found')
    if (existing.status !== 'completed') {
      throw new Error('Can only archive completed experiments')
    }

    await this.db
      .prepare('UPDATE ai_search_experiments SET status = ?, updated_at = ? WHERE id = ?')
      .bind('archived', Date.now(), id)
      .run()

    return (await this.getById(id))!
  }

  // =============================================
  // Active Experiment Lookup (called on every search)
  // =============================================

  async getActiveExperiment(): Promise<Experiment | null> {
    // KV cache first (<2ms)
    if (this.kv) {
      try {
        const cached = await this.kv.get('experiment:active', 'json')
        if (cached) return cached as Experiment
      } catch { /* fall through to D1 */ }
    }

    // D1 fallback
    const row = await this.db
      .prepare("SELECT * FROM ai_search_experiments WHERE status = 'running' LIMIT 1")
      .first<ExperimentRow>()

    if (!row) return null

    const experiment = rowToExperiment(row)
    // Populate KV cache for next request
    if (this.kv) {
      try {
        await this.kv.put('experiment:active', JSON.stringify(experiment), { expirationTtl: 86400 })
      } catch { /* non-critical */ }
    }
    return experiment
  }

  // =============================================
  // Variant Assignment
  // =============================================

  /**
   * Deterministic variant assignment via FNV-1a hash.
   * Same user + experiment always gets the same variant.
   */
  assignVariant(experimentId: string, userId: string, splitRatio: number = 0.5): 'control' | 'treatment' {
    const hash = fnv1a(`${userId}:${experimentId}`)
    return (hash % 100) < (splitRatio * 100) ? 'treatment' : 'control'
  }

  /**
   * Check if a user should be enrolled in the experiment based on traffic_pct.
   */
  shouldEnroll(experimentId: string, userId: string, trafficPct: number): boolean {
    const hash = fnv1a(`enroll:${userId}:${experimentId}`)
    return (hash % 100) < trafficPct
  }

  // =============================================
  // Event Tracking
  // =============================================

  trackSearchEvent(data: {
    experimentId: string
    variantId: string
    query: string
    searchMode: string
    userId: string
    searchId: string
    resultsCount: number
    responseTimeMs: number
  }): void {
    if (this.analytics) {
      this.analytics.writeDataPoint({
        indexes: [data.experimentId],
        blobs: [data.variantId, data.query, data.searchMode, data.userId, data.searchId],
        doubles: [data.resultsCount, data.responseTimeMs, 0, 0],
      })
    } else {
      // D1 fallback (local dev / no Analytics Engine binding)
      this.db
        .prepare(`
          INSERT INTO ai_search_experiment_events (id, experiment_id, event_type, variant_id, query, search_mode, user_id, search_id, results_count, response_time_ms, created_at)
          VALUES (?, ?, 'search', ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          crypto.randomUUID(),
          data.experimentId,
          data.variantId,
          data.query,
          data.searchMode,
          data.userId,
          data.searchId,
          data.resultsCount,
          data.responseTimeMs,
          Date.now()
        )
        .run()
        .catch((e) => console.error('[ExperimentService] D1 search event tracking failed:', e))
    }
  }

  trackClickEvent(data: {
    experimentId: string
    variantId: string
    searchId: string
    contentId: string
    clickPosition: number
  }): void {
    if (this.analytics) {
      this.analytics.writeDataPoint({
        indexes: [data.experimentId],
        blobs: [data.variantId, data.searchId, data.contentId],
        doubles: [1, data.clickPosition],
      })
    } else {
      // D1 fallback
      this.db
        .prepare(`
          INSERT INTO ai_search_experiment_events (id, experiment_id, event_type, variant_id, search_id, content_id, click_position, created_at)
          VALUES (?, ?, 'click', ?, ?, ?, ?, ?)
        `)
        .bind(
          crypto.randomUUID(),
          data.experimentId,
          data.variantId,
          data.searchId,
          data.contentId,
          data.clickPosition,
          Date.now()
        )
        .run()
        .catch((e) => console.error('[ExperimentService] D1 click event tracking failed:', e))
    }
  }

  // =============================================
  // Experiment Evaluation (called by cron)
  // =============================================

  async evaluateExperiment(id: string): Promise<ExperimentMetrics | null> {
    const experiment = await this.getById(id)
    if (!experiment || experiment.status !== 'running') return null

    let metrics: ExperimentMetrics

    if (this.analytics) {
      metrics = await this.evaluateFromAnalyticsEngine(id)
    } else {
      metrics = await this.evaluateFromD1(id)
    }

    // Update experiment with latest metrics
    const now = Date.now()
    await this.db
      .prepare('UPDATE ai_search_experiments SET metrics = ?, confidence = ?, updated_at = ? WHERE id = ?')
      .bind(JSON.stringify(metrics), metrics.confidence, now, id)
      .run()

    // Auto-complete if significance reached and minimum searches met
    const totalSearches = metrics.control.searches + metrics.treatment.searches
    if (metrics.significant && totalSearches >= experiment.min_searches) {
      const winner = metrics.control.ctr >= metrics.treatment.ctr ? 'control' : 'treatment'
      await this.complete(id, winner)
    }

    // Update KV cache with fresh metrics
    if (this.kv) {
      const updated = await this.getById(id)
      if (updated && updated.status === 'running') {
        await this.kv.put('experiment:active', JSON.stringify(updated), { expirationTtl: 86400 })
      }
    }

    return metrics
  }

  private async evaluateFromD1(experimentId: string): Promise<ExperimentMetrics> {
    // Aggregate search events
    const searchRows = await this.db
      .prepare(`
        SELECT variant_id,
               COUNT(*) as searches,
               SUM(CASE WHEN results_count = 0 THEN 1 ELSE 0 END) as zero_results,
               AVG(response_time_ms) as avg_response_time
        FROM ai_search_experiment_events
        WHERE experiment_id = ? AND event_type = 'search'
        GROUP BY variant_id
      `)
      .bind(experimentId)
      .all<{ variant_id: string; searches: number; zero_results: number; avg_response_time: number }>()

    // Aggregate click events
    const clickRows = await this.db
      .prepare(`
        SELECT variant_id,
               COUNT(*) as clicks,
               AVG(click_position) as avg_position
        FROM ai_search_experiment_events
        WHERE experiment_id = ? AND event_type = 'click'
        GROUP BY variant_id
      `)
      .bind(experimentId)
      .all<{ variant_id: string; clicks: number; avg_position: number }>()

    return this.buildMetrics(searchRows.results || [], clickRows.results || [])
  }

  private async evaluateFromAnalyticsEngine(_experimentId: string): Promise<ExperimentMetrics> {
    // Analytics Engine SQL API queries would go here.
    // For now, fall back to D1 — Analytics Engine SQL API requires
    // account-level API token + HTTP fetch, which is better suited
    // for a cron handler that has the account credentials.
    // The cron handler will implement this path.
    return this.evaluateFromD1(_experimentId)
  }

  private buildMetrics(
    searchRows: Array<{ variant_id: string; searches: number; zero_results: number; avg_response_time: number }>,
    clickRows: Array<{ variant_id: string; clicks: number; avg_position: number }>
  ): ExperimentMetrics {
    const getVariant = (rows: Array<{ variant_id: string;[k: string]: any }>, variant: string) =>
      rows.find((r) => r.variant_id === variant)

    const controlSearches = getVariant(searchRows, 'control')
    const treatmentSearches = getVariant(searchRows, 'treatment')
    const controlClicks = getVariant(clickRows, 'control')
    const treatmentClicks = getVariant(clickRows, 'treatment')

    const cSearches = controlSearches?.searches || 0
    const tSearches = treatmentSearches?.searches || 0
    const cClicks = controlClicks?.clicks || 0
    const tClicks = treatmentClicks?.clicks || 0

    const control: VariantMetrics = {
      searches: cSearches,
      clicks: cClicks,
      ctr: cSearches > 0 ? cClicks / cSearches : 0,
      zero_result_rate: cSearches > 0 ? (controlSearches?.zero_results || 0) / cSearches : 0,
      avg_click_position: controlClicks?.avg_position || 0,
      avg_response_time_ms: controlSearches?.avg_response_time || 0,
    }

    const treatment: VariantMetrics = {
      searches: tSearches,
      clicks: tClicks,
      ctr: tSearches > 0 ? tClicks / tSearches : 0,
      zero_result_rate: tSearches > 0 ? (treatmentSearches?.zero_results || 0) / tSearches : 0,
      avg_click_position: treatmentClicks?.avg_position || 0,
      avg_response_time_ms: treatmentSearches?.avg_response_time || 0,
    }

    const chi2 = chiSquared(cClicks, cSearches, tClicks, tSearches)
    const confidence = chi2ToConfidence(chi2)

    return {
      control,
      treatment,
      confidence,
      significant: confidence >= 0.95,
    }
  }
}

// =============================================
// Statistical Functions
// =============================================

/**
 * Chi-squared test for CTR difference between two variants.
 * Returns chi-squared statistic (1 degree of freedom).
 */
function chiSquared(
  controlClicks: number,
  controlImpressions: number,
  treatmentClicks: number,
  treatmentImpressions: number
): number {
  if (controlImpressions === 0 || treatmentImpressions === 0) return 0

  const controlNoClick = controlImpressions - controlClicks
  const treatmentNoClick = treatmentImpressions - treatmentClicks
  const total = controlImpressions + treatmentImpressions
  const totalClicks = controlClicks + treatmentClicks
  const totalNoClicks = controlNoClick + treatmentNoClick

  if (totalClicks === 0 || totalNoClicks === 0) return 0

  const eCC = (controlImpressions * totalClicks) / total
  const eCN = (controlImpressions * totalNoClicks) / total
  const eTC = (treatmentImpressions * totalClicks) / total
  const eTN = (treatmentImpressions * totalNoClicks) / total

  return (
    ((controlClicks - eCC) ** 2 / eCC) +
    ((controlNoClick - eCN) ** 2 / eCN) +
    ((treatmentClicks - eTC) ** 2 / eTC) +
    ((treatmentNoClick - eTN) ** 2 / eTN)
  )
}

/**
 * Convert chi-squared statistic to approximate confidence level.
 * Uses lookup thresholds for 1 df (sufficient precision for A/B testing).
 */
function chi2ToConfidence(chi2: number): number {
  if (chi2 >= 10.83) return 0.999
  if (chi2 >= 6.63) return 0.99
  if (chi2 >= 3.84) return 0.95
  if (chi2 >= 2.71) return 0.90
  if (chi2 >= 1.32) return 0.75
  return chi2 / 3.84 * 0.95 // Linear interpolation below 0.75
}

// =============================================
// Hash Function
// =============================================

/** FNV-1a 32-bit hash — deterministic, fast, good distribution for variant assignment */
function fnv1a(str: string): number {
  let hash = 0x811c9dc5
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193)
  }
  return hash >>> 0 // Ensure unsigned
}
