import { z } from 'zod'

/**
 * Typed display config for `view_displays.config` — the ONE source of
 * truth for what a saved View renders as. This is the anti-rot contract: the
 * dormant table is being activated, and the failure mode to avoid is the one
 * `media.metadata` fell into — a versionless TEXT blob of arbitrary nested keys,
 * reached via `json_extract(json_extract(...))`, with no discriminant and no
 * schema, so it could never be validated or migrated.
 *
 * Every property below exists to make one of those impossible by construction:
 *  1. Discriminated union on `type` (mirrors the SQL `display_type` column).
 *  2. `config.type === row.display_type` — asserted by the repository on every
 *     read/write (zod cannot see the SQL column).
 *  3. `.strict()` — unknown keys are REJECTED, never preserved (no blob creep).
 *  4. `version` literal — the single place a future `v1 → v2` upgrade can run.
 *  5. Bounded values — `pageSize` clamped 1..100; `columns` validated against the
 *     view's projection at write time via {@link assertColumnsInProjection}.
 *  6. Total round-trip — {@link serializeDisplayConfig} re-validates on write.
 */
export const TableDisplayConfigSchema = z
  .object({
    type: z.literal('table'),
    version: z.literal(1),
    /**
     * Ordered column whitelist. Empty `[]` is the explicit "all view-projected
     * columns" sentinel (mirrors `ColumnConfig.fields` semantics, where empty =
     * all), resolved at render time. The public/embed surface (PR-C) forbids
     * empty=all and requires an explicit non-empty whitelist to avoid leaking
     * system columns.
     */
    columns: z.array(z.string()),
    pageSize: z.number().int().min(1).max(100),
    // Pagination mode (PR-4). Default 'offset' → existing configs back-fill, byte-identical.
    // 'cursor' opts into keyset pagination (requires a structural view sort — guarded at the routes).
    paginate: z.enum(['offset', 'cursor']).default('offset'),
  })
  .strict()

/**
 * Cards display: each row renders as a card with a prominent `titleField` heading
 * plus `fields` shown as label:value. The visible set ({@link displayVisibleColumns})
 * is `[titleField, ...fields]` — the SAME set the SQL projection, the publish/config
 * validation, and the template all consume, so nothing un-whitelisted can leak.
 */
export const CardsDisplayConfigSchema = z
  .object({
    type: z.literal('cards'),
    version: z.literal(1),
    titleField: z.string().min(1), // non-empty heading — a blank would render an empty card head
    fields: z.array(z.string()),
    pageSize: z.number().int().min(1).max(100),
    // Pagination mode (PR-4). Default 'offset' → existing configs back-fill, byte-identical.
    // 'cursor' opts into keyset pagination (requires a structural view sort — guarded at the routes).
    paginate: z.enum(['offset', 'cursor']).default('offset'),
  })
  .strict()

export const ViewDisplayConfigSchema = z.discriminatedUnion('type', [
  TableDisplayConfigSchema,
  CardsDisplayConfigSchema,
])

export type TableDisplayConfig = z.infer<typeof TableDisplayConfigSchema>
export type CardsDisplayConfig = z.infer<typeof CardsDisplayConfigSchema>
export type ViewDisplayConfig = z.infer<typeof ViewDisplayConfigSchema>

/** The display kinds that exist today — mirrors the union discriminants. */
export const DISPLAY_TYPES = ['table', 'cards'] as const
export type DisplayType = (typeof DISPLAY_TYPES)[number]

/**
 * The ONE visible-field set a display exposes — the whitelist consumed by the SQL
 * projection (`executePublic`), the publish/config validation, AND the render
 * templates. Keeping all three on this single source is what prevents a
 * non-visible/system column from leaking. For `cards`, `titleField` is folded in
 * and deduped (a `titleField` that also appears in `fields` must not project twice).
 */
export function displayVisibleColumns(config: ViewDisplayConfig): string[] {
  if (config.type === 'table') return config.columns
  return [...new Set([config.titleField, ...config.fields])]
}

const MIN_PAGE_SIZE = 1
const MAX_PAGE_SIZE = 100
const DEFAULT_PAGE_SIZE = 25

/** Thrown on any violation of the fail-closed display-config contract. */
export class DisplayConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DisplayConfigError'
  }
}

/**
 * Fail-CLOSED parse of a stored `config` blob. Bad JSON, an unknown discriminant,
 * an unknown key, a bad `version`, or a `config.type` that disagrees with the
 * row's `display_type` all THROW {@link DisplayConfigError} — it never falls back
 * to a partial/blob value (contrast the deliberately fail-OPEN `parseJsonConfig`
 * in view-service.ts, which must NOT back this parser).
 */
export function parseDisplayConfig(
  raw: string | null | undefined,
  displayType: string
): ViewDisplayConfig {
  if (raw == null || raw === '') {
    throw new DisplayConfigError('display config is empty')
  }
  let json: unknown
  try {
    json = JSON.parse(raw)
  } catch {
    throw new DisplayConfigError('display config is not valid JSON')
  }
  const result = ViewDisplayConfigSchema.safeParse(json)
  if (!result.success) {
    const detail = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')
    throw new DisplayConfigError(`invalid display config: ${detail}`)
  }
  const config = result.data
  // Invariant 2: the JSON discriminant must equal the SQL display_type column,
  // so the two can never drift.
  if (config.type !== displayType) {
    throw new DisplayConfigError(
      `display config type "${config.type}" does not match display_type "${displayType}"`
    )
  }
  return config
}

/** Re-validates before stringifying so a malformed object can never be stored. */
export function serializeDisplayConfig(config: ViewDisplayConfig): string {
  return JSON.stringify(ViewDisplayConfigSchema.parse(config))
}

/**
 * Invariant 5 (projection-bound). Every non-sentinel column must be one the view
 * actually projects, else the cell renders blank. zod cannot see the projection,
 * so this is a separate write-time check used wherever a caller supplies an
 * explicit column list (a future display editor / the PR-C public whitelist).
 * The empty `[]` "all" sentinel is trivially in-projection.
 */
export function assertColumnsInProjection(
  config: ViewDisplayConfig,
  effectiveColumns: string[]
): void {
  // Type-agnostic: validate the display's VISIBLE set (table columns or cards
  // titleField+fields). A cards config must be checked too — otherwise a
  // `titleField`/`field` set to a system column (`created_by`) or anything outside
  // the projection would pass and then be SELECTed into the public embed (leak).
  const visible = displayVisibleColumns(config)
  // The table empty=all sentinel (`columns: []`) is trivially in-projection.
  if (visible.length === 0) return
  const allowed = new Set(effectiveColumns)
  const stray = visible.filter((c) => !allowed.has(c))
  if (stray.length > 0) {
    throw new DisplayConfigError(`display columns not in the view projection: ${stray.join(', ')}`)
  }
}

function clampPageSize(n: number | null | undefined): number {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < MIN_PAGE_SIZE) return DEFAULT_PAGE_SIZE
  return Math.min(Math.floor(n), MAX_PAGE_SIZE)
}

/**
 * The effective default `table` config for a view, derived purely from the view's
 * own saved projection (`columns_config.fields`) and `page_size` — no schema
 * query. Used both to auto-provision a display row on save (PR-A) and as the
 * render-time fallback for a view with no stored display row (PR-B), so both
 * paths render identically. `columns` is `⊆` the projection by construction
 * (it IS the projection, or the empty=all sentinel).
 */
export function deriveDefaultTableConfig(input: {
  columnsFields?: string[] | null
  pageSize?: number | null
}): TableDisplayConfig {
  const fields = input.columnsFields ?? []
  return {
    type: 'table',
    version: 1,
    columns: Array.isArray(fields) ? [...fields] : [],
    pageSize: clampPageSize(input.pageSize),
    paginate: 'offset', // MUST-FIX 3: `paginate` is now a required output prop of the inferred type
  }
}
