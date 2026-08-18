import type { D1Database } from '@cloudflare/workers-types'
import {
  type ViewDisplayConfig,
  parseDisplayConfig,
  serializeDisplayConfig,
} from './display-config'

/** A persisted display row, with its `config` already parsed and validated. */
export interface ViewDisplay {
  id: string
  viewId: string
  displayType: string
  path: string | null
  config: ViewDisplayConfig
  /** Public-display opt-in gate: false = admin-only, true = published at `path`. */
  isPublic: boolean
  /** Unguessable share token ('_'-prefixed), or null until first published. */
  shareToken: string | null
  createdAt: number
  updatedAt: number
}

interface ViewDisplayRow {
  id: string
  view_id: string
  display_type: string
  path: string | null
  config: string
  is_public: number
  share_token: string | null
  created_at: number
  updated_at: number
}

const SELECT_COLS = `id, view_id, display_type, path, config, is_public, share_token, created_at, updated_at`

/**
 * Mint an unguessable share token: `_` + 16 random bytes (128 bits) as lowercase
 * hex. The `_` prefix is a char no valid `path` can start with
 * (`DISPLAY_PATH_RE` first-char class is `[a-z0-9]`), so the token and path value
 * spaces are provably disjoint — a path-or-token lookup can never match two rows.
 * Uses the CSPRNG (`crypto.getRandomValues`), never `Math.random`.
 */
export function generateShareToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return `_${hex}`
}

/**
 * Data access for `view_displays`. PR-A manages exactly one default
 * `table` display per view (`display_type='table'`); PR-C1 adds the public
 * opt-in (`is_public` + unique `path`).
 *
 * The table has no UNIQUE constraint on `(view_id, display_type)`, so the
 * per-view upsert is SELECT-then-INSERT/UPDATE, not `ON CONFLICT`. `path` DOES
 * have a partial unique index (this migration), so a duplicate publish path is a
 * constraint error caught at the route.
 */
export class ViewDisplayRepository {
  constructor(
    private readonly db: D1Database,
    private readonly tenantId: string = 'default',
  ) {}

  private mapRow(row: ViewDisplayRow): ViewDisplay {
    return {
      id: row.id,
      viewId: row.view_id,
      displayType: row.display_type,
      path: row.path,
      config: parseDisplayConfig(row.config, row.display_type),
      isPublic: row.is_public === 1,
      shareToken: row.share_token,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }
  }

  /**
   * The PUBLIC read by EITHER the canonical `path` OR the share token. Gates on
   * `is_public = 1` exactly like {@link getByPath}, so an unpublished display's
   * token 404s. The path/token value-spaces are disjoint (token is `_`-prefixed),
   * so the `OR` matches at most one row.
   *
   * `path` is tenant-scoped (it's per-tenant-unique — two tenants may legally publish
   * the same slug); `share_token` deliberately is NOT — it's a random, unguessable
   * secret that is itself the full lookup key for an anonymous request that has no
   * other way to know which tenant a token belongs to (see migrations.ts header).
   */
  async getByPathOrToken(slug: string): Promise<ViewDisplay | null> {
    const row = await this.db
      .prepare(`SELECT ${SELECT_COLS} FROM view_displays WHERE ((path = ? AND tenant_id = ?) OR share_token = ?) AND is_public = 1 LIMIT 1`)
      .bind(slug, this.tenantId, slug)
      .first<ViewDisplayRow>()
    return row ? this.mapRow(row) : null
  }

  /**
   * The default `table` display for a view, or `null` if none is stored yet.
   * Throws {@link DisplayConfigError} if a row exists but its `config` is corrupt
   * (fail-closed) — the read surface decides whether to fall back to a derived
   * default. `view_id` is already a tenant-scoped lookup by construction (the
   * caller only ever has a `view_id` from a tenant-filtered `views` read), but the
   * extra `tenant_id` filter is cheap, correct, and defense-in-depth.
   */
  async getDefault(viewId: string): Promise<ViewDisplay | null> {
    // Keyed on view_id ALONE — one display per view, of WHATEVER type (table or
    // cards). Re-keying on `display_type='table'` would miss a cards-switched row.
    const row = await this.db
      .prepare(`SELECT ${SELECT_COLS} FROM view_displays WHERE view_id = ? AND tenant_id = ? LIMIT 1`)
      .bind(viewId, this.tenantId)
      .first<ViewDisplayRow>()
    return row ? this.mapRow(row) : null
  }

  /**
   * The PUBLIC read: the published display at a slug. Gates on `is_public = 1`
   * (mirrors `forms.is_public`) so an unpublished display is never served.
   * Unused outside this class today — kept tenant-scoped for the same reason as
   * {@link getByPathOrToken}'s `path` branch, so it can't become a silent leak if
   * a future caller reaches for it.
   */
  async getByPath(path: string): Promise<ViewDisplay | null> {
    const row = await this.db
      .prepare(`SELECT ${SELECT_COLS} FROM view_displays WHERE path = ? AND tenant_id = ? AND is_public = 1 LIMIT 1`)
      .bind(path, this.tenantId)
      .first<ViewDisplayRow>()
    return row ? this.mapRow(row) : null
  }

  /**
   * The view id that currently owns a `path` FOR THIS TENANT, IGNORING `is_public`
   * (an unpublished display keeps its slug). Used for the publish-time uniqueness
   * pre-check — the partial unique index (now `UNIQUE(tenant_id, path)`) is the
   * real guard, this gives a friendly error first. Must be tenant-scoped: `path` is
   * only unique per-tenant now, so an unscoped check would report a false
   * collision against another tenant's identically-named slug.
   */
  async findPathOwner(path: string): Promise<string | null> {
    const row = await this.db
      .prepare(`SELECT view_id FROM view_displays WHERE path = ? AND tenant_id = ? LIMIT 1`)
      .bind(path, this.tenantId)
      .first<{ view_id: string }>()
    return row?.view_id ?? null
  }

  /**
   * Insert or update the view's single default `table` display, mirroring the
   * view's saved projection. Idempotent (called on every view save).
   *
   * A PUBLISHED display is left untouched: once an operator has chosen an explicit
   * public column whitelist, a later view re-save must NOT silently reset those
   * columns (which could re-introduce the empty=all sentinel and leak system
   * columns on the public surface). Returns the display id.
   */
  async upsertDefault(viewId: string, config: ViewDisplayConfig, now: number): Promise<string> {
    const serialized = serializeDisplayConfig(config)
    const existing = await this.db
      .prepare(`SELECT id, is_public, display_type FROM view_displays WHERE view_id = ? AND tenant_id = ? LIMIT 1`)
      .bind(viewId, this.tenantId)
      .first<{ id: string; is_public: number; display_type: string }>()

    if (existing) {
      if (existing.is_public === 1) {
        // Published: preserve the operator's explicit whitelist — nothing to sync.
        return existing.id
      }
      if (existing.display_type !== 'table') {
        // A non-table display (cards) chosen via the picker — a view re-save must
        // NOT silently reset it to a derived table config.
        return existing.id
      }
      await this.db
        .prepare(`UPDATE view_displays SET config = ?, updated_at = ? WHERE id = ?`)
        .bind(serialized, now, existing.id)
        .run()
      return existing.id
    }

    // Deterministic, collision-proof id (one display row per view — same convention as
    // setPublished/setConfig; the id is opaque, every lookup is by view_id).
    const id = `${viewId}-display`
    await this.db
      .prepare(
        `INSERT INTO view_displays (id, tenant_id, view_id, display_type, path, config, is_public, created_at, updated_at)
         VALUES (?, ?, ?, 'table', NULL, ?, 0, ?, ?)`
      )
      .bind(id, this.tenantId, viewId, serialized, now, now)
      .run()
    return id
  }

  /**
   * Publish the view's default display at `path`: sets `is_public = 1`, the slug,
   * and the explicit column whitelist (the caller has already validated
   * non-empty `⊆` projection + a `status` column on the collection). Upserts the
   * row if it doesn't exist yet. A duplicate `path` raises the partial unique
   * index error — the caller catches it. Returns the display id.
   */
  /** Mint a share token guaranteed free of the (astronomically improbable) collision. */
  private async mintUniqueToken(): Promise<string> {
    for (let i = 0; i < 5; i++) {
      const token = generateShareToken()
      // Deliberately NOT tenant-scoped — share_token is globally unique by design
      // (see class/migrations.ts header), so the collision check must be too.
      const clash = await this.db
        .prepare(`SELECT 1 FROM view_displays WHERE share_token = ? LIMIT 1`)
        .bind(token)
        .first()
      if (!clash) return token
    }
    throw new Error('could not mint a unique share token')
  }

  async setPublished(
    viewId: string,
    config: ViewDisplayConfig,
    path: string,
    now: number
  ): Promise<{ id: string; shareToken: string }> {
    const serialized = serializeDisplayConfig(config)
    const existing = await this.db
      .prepare(`SELECT id, share_token FROM view_displays WHERE view_id = ? AND tenant_id = ? LIMIT 1`)
      .bind(viewId, this.tenantId)
      .first<{ id: string; share_token: string | null }>()

    if (existing) {
      // Keep an existing token (stable share link across re-publishes); mint one if
      // this is the row's first publish. display_type is written from config.type so
      // a cards config stores 'cards' (parseDisplayConfig invariant-2 holds on read).
      const shareToken = existing.share_token ?? (await this.mintUniqueToken())
      await this.db
        .prepare(`UPDATE view_displays SET display_type = ?, config = ?, path = ?, is_public = 1, share_token = ?, updated_at = ? WHERE id = ?`)
        .bind(config.type, serialized, path, shareToken, now, existing.id)
        .run()
      return { id: existing.id, shareToken }
    }

    const id = `${viewId}-display`
    const shareToken = await this.mintUniqueToken()
    await this.db
      .prepare(
        `INSERT INTO view_displays (id, tenant_id, view_id, display_type, path, config, is_public, share_token, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`
      )
      .bind(id, this.tenantId, viewId, config.type, path, serialized, shareToken, now, now)
      .run()
    return { id, shareToken }
  }

  /**
   * Set the view's display TYPE + config (the picker backend), keeping `is_public`
   * and `path`. Writes `display_type` from `config.type`. Inserts if the view has
   * no display row yet. The caller validates the visible set ⊆ projection first.
   */
  async setConfig(viewId: string, config: ViewDisplayConfig, now: number): Promise<string> {
    const serialized = serializeDisplayConfig(config)
    const existing = await this.db
      .prepare(`SELECT id FROM view_displays WHERE view_id = ? AND tenant_id = ? LIMIT 1`)
      .bind(viewId, this.tenantId)
      .first<{ id: string }>()

    if (existing) {
      await this.db
        .prepare(`UPDATE view_displays SET display_type = ?, config = ?, updated_at = ? WHERE id = ?`)
        .bind(config.type, serialized, now, existing.id)
        .run()
      return existing.id
    }

    const id = `${viewId}-display`
    await this.db
      .prepare(
        `INSERT INTO view_displays (id, tenant_id, view_id, display_type, path, config, is_public, created_at, updated_at)
         VALUES (?, ?, ?, ?, NULL, ?, 0, ?, ?)`
      )
      .bind(id, this.tenantId, viewId, config.type, serialized, now, now)
      .run()
    return id
  }

  /**
   * Unpublish the view's display: flips `is_public = 0`. The `path` is KEPT so a
   * later re-publish reuses the same slug (the partial unique index tolerates it,
   * since the slug stays unique to this view).
   */
  async unpublish(viewId: string, now: number): Promise<void> {
    await this.db
      .prepare(`UPDATE view_displays SET is_public = 0, updated_at = ? WHERE view_id = ? AND tenant_id = ?`)
      .bind(now, viewId, this.tenantId)
      .run()
  }
}
