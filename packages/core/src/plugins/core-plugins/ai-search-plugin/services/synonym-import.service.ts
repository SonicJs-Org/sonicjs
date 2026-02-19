import type { D1Database } from '@cloudflare/workers-types'
import { RecommendationService, fnv1aHash } from './recommendation.service'

export interface ImportResult {
  parsed: number
  corpus_matched: number
  queued: number
  skipped_existing: number
  skipped_threshold: number
  skipped_format: number
  errors: string[]
}

export interface ImportOptions {
  min_occurrences: number
  import_source?: string
}

interface ParsedEntry {
  terms: string[]
  type: 'bidirectional' | 'one_way'
  source_term?: string
}

/**
 * Synonym Import Service
 *
 * Parses CSV and Elasticsearch synonyms.txt files, filters entries against the
 * content corpus via FTS5, deduplicates via fingerprint, and queues matching
 * pairs as recommendations in the Agent tab for admin review.
 */
export class SynonymImportService {
  constructor(
    private db: D1Database,
  ) {}

  async importCsv(content: string, options: ImportOptions): Promise<ImportResult> {
    return this.processImport(content, 'csv', options)
  }

  async importSynonymsTxt(content: string, options: ImportOptions): Promise<ImportResult> {
    return this.processImport(content, 'txt', options)
  }

  private async processImport(
    content: string,
    format: 'csv' | 'txt',
    options: ImportOptions
  ): Promise<ImportResult> {
    const lines = content.split('\n')
    const result: ImportResult = {
      parsed: 0,
      corpus_matched: 0,
      queued: 0,
      skipped_existing: 0,
      skipped_threshold: 0,
      skipped_format: 0,
      errors: [],
    }

    const recService = new RecommendationService(this.db)
    const runId = await recService.createRun()
    const startTime = Date.now()

    try {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? ''
        const entry = format === 'txt'
          ? this.parseSynonymsTxtLine(line)
          : this.parseCsvLine(line)

        if (!entry) {
          // Only count as skipped_format if the line has content (not blank/comment)
          const trimmed = line.trim()
          if (trimmed && !trimmed.startsWith('#')) {
            result.skipped_format++
            if (result.errors.length < 10) {
              result.errors.push(`Line ${i + 1}: could not parse "${trimmed.slice(0, 60)}"`)
            }
          }
          continue
        }
        result.parsed++

        // Corpus filter: at least one term must appear in content
        let maxOccurrences = 0
        for (const term of entry.terms) {
          const count = await this.checkCorpusPresence(term)
          maxOccurrences = Math.max(maxOccurrences, count)
        }

        if (maxOccurrences === 0) continue
        result.corpus_matched++

        if (maxOccurrences < options.min_occurrences) {
          result.skipped_threshold++
          continue
        }

        // Fingerprint dedup — sorted terms for consistency
        const sortedTerms = [...entry.terms].sort().join('|')
        const fingerprint = fnv1aHash(`synonym:${sortedTerms}`)

        const queued = await this.queueRecommendation(
          recService,
          entry,
          fingerprint,
          options.import_source || 'uploaded-file',
          runId,
        )

        if (queued) result.queued++
        else result.skipped_existing++
      }

      await recService.completeRun(runId, result.queued, Date.now() - startTime)
    } catch (error) {
      await recService.failRun(runId, error instanceof Error ? error.message : String(error))
      throw error
    }

    return result
  }

  /**
   * Parse a CSV line.
   * One-way: "PS5 -> PlayStation 5" or "PS5 → PlayStation 5"
   * Bidirectional: "couch, sofa, settee"
   */
  private parseCsvLine(line: string): ParsedEntry | null {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return null

    // One-way detection: arrow notation
    if (trimmed.includes('\u2192') || trimmed.includes('->')) {
      const [left, right] = trimmed.split(/\u2192|->/).map(s => s.trim())
      if (!left || !right) return null
      const targets = right.split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
      if (targets.length === 0) return null
      return {
        terms: [left.toLowerCase(), ...targets],
        type: 'one_way',
        source_term: left.toLowerCase(),
      }
    }

    // Bidirectional: comma-separated
    const terms = trimmed.split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
    if (terms.length < 2) return null

    return { terms: [...new Set(terms)], type: 'bidirectional' }
  }

  /**
   * Parse an Elasticsearch/Solr synonyms.txt line.
   * One-way: "PS5 => PlayStation 5, PS 5"
   * Bidirectional: "couch, sofa, settee"
   */
  private parseSynonymsTxtLine(line: string): ParsedEntry | null {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return null

    // Explicit mapping: left => right (one-way)
    if (trimmed.includes('=>')) {
      const [left, right] = trimmed.split('=>').map(s => s.trim())
      if (!left || !right) return null
      const targets = right.split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
      if (targets.length === 0) return null
      return {
        terms: [left.toLowerCase(), ...targets],
        type: 'one_way',
        source_term: left.toLowerCase(),
      }
    }

    // Bidirectional: comma-separated
    const terms = trimmed.split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
    if (terms.length < 2) return null
    return { terms: [...new Set(terms)], type: 'bidirectional' }
  }

  /**
   * Check how many content items contain a term via FTS5.
   */
  private async checkCorpusPresence(term: string): Promise<number> {
    try {
      const sanitized = term.replace(/['"(){}[\]*:^~!@#$%&]/g, '').trim()
      if (!sanitized) return 0

      const row = await this.db
        .prepare('SELECT COUNT(*) as cnt FROM content_fts WHERE content_fts MATCH ?')
        .bind('"' + sanitized + '"')
        .first<{ cnt: number }>()

      return row?.cnt ?? 0
    } catch {
      return 0
    }
  }

  /**
   * Queue a parsed synonym entry as a recommendation for admin review.
   * Returns true if queued, false if fingerprint already exists.
   */
  private async queueRecommendation(
    recService: RecommendationService,
    entry: ParsedEntry,
    fingerprint: string,
    importSource: string,
    runId: string,
  ): Promise<boolean> {
    // Check fingerprint dedup
    const existing = await this.db
      .prepare("SELECT id FROM ai_search_recommendations WHERE fingerprint = ? AND status IN ('pending', 'applied') LIMIT 1")
      .bind(fingerprint)
      .first()

    if (existing) return false

    const direction = entry.type === 'one_way' ? '\u2192' : '='
    const title = entry.type === 'one_way'
      ? `Import: "${entry.source_term}" ${direction} "${entry.terms.filter(t => t !== entry.source_term).join(', ')}"`
      : `Import: "${entry.terms.join('" = "')}"`

    const description = entry.type === 'one_way'
      ? `Imported one-way synonym: searching "${entry.source_term}" will also match "${entry.terms.filter(t => t !== entry.source_term).join('", "')}".`
      : `Imported synonym group: ${entry.terms.join(', ')} will be treated as equivalent.`

    await recService.insertRecommendation({
      id: crypto.randomUUID().replace(/-/g, ''),
      category: 'synonym',
      title,
      description,
      supporting_data: {
        terms: entry.terms,
        synonym_type: entry.type,
        source_term: entry.source_term || null,
        import_source: importSource,
      },
      action_payload: {
        terms: entry.terms,
        synonym_type: entry.type,
        source_term: entry.source_term || null,
      },
      fingerprint,
      run_id: runId,
      import_source: importSource,
    })

    return true
  }
}
