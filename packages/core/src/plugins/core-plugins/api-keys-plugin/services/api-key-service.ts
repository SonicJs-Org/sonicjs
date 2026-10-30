import { D1Database } from '@cloudflare/workers-types'
import type { Document, QueryableField } from '../../../../schemas/document'
import { createDocumentSchema } from '../../../../schemas/document'
import { DocumentsService } from '../../../../services/documents'

/**
 * Programmatic API keys, built on the document model (no new table — R-rules).
 *
 * better-auth 1.6.x ships no apiKey plugin, so SonicJS provides long-lived,
 * per-user keys for headless / server-to-server REST access here. A key is one
 * `api_key` document:
 *   - the plaintext secret (`sk_<hex>`) is shown exactly once, at creation;
 *   - only its SHA-256 hash is stored (`q_apikey_hash`), so a DB leak cannot
 *     reconstruct usable keys;
 *   - `q_apikey_user_id` powers per-user listing; `q_apikey_revoked` lets the
 *     resolve query skip revoked keys with an indexed predicate.
 *
 * Resolution (an `x-api-key` / `Authorization: Bearer sk_…` header on an API
 * request) looks up the hash, checks revoke + expiry, then loads the owning
 * `auth_user` so the request runs as that user with their role.
 *
 * The `api_key` document type + its q_apikey_* generated columns are registered
 * in the core document-type seed (document-types-seed.ts), so the columns exist
 * at boot — before the resolve middleware can run.
 */

export const API_KEY_QUERYABLE: QueryableField[] = [
  { name: 'keyHash', kind: 'scalar', type: 'text', column: 'q_apikey_hash' },
  { name: 'userId', kind: 'scalar', type: 'text', column: 'q_apikey_user_id' },
  { name: 'revoked', kind: 'scalar', type: 'integer', column: 'q_apikey_revoked' },
]

const KEY_PREFIX = 'sk_'
/** Bytes of randomness in the secret (→ 48 hex chars after `sk_`). */
const KEY_BYTES = 24
/** Chars of the secret shown in listings, e.g. `sk_1a2b3c4d`. */
const DISPLAY_PREFIX_LEN = KEY_PREFIX.length + 8

export interface CreatedApiKey {
  id: string
  /** Full secret — returned ONCE, never persisted or retrievable again. */
  key: string
  name: string
  prefix: string
  expiresAt: number | null
}

export interface ApiKeySummary {
  id: string
  name: string
  prefix: string
  createdAt: number
  lastUsedAt: number | null
  expiresAt: number | null
}

export interface ResolvedApiKeyUser {
  userId: string
  email: string
  role: string
  isSuperAdmin: boolean
}

/** Generate a random `sk_<hex>` secret using Web Crypto (Workers + Node 18+). */
export function generateApiKeySecret(): string {
  const bytes = new Uint8Array(KEY_BYTES)
  crypto.getRandomValues(bytes)
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return KEY_PREFIX + hex
}

/** SHA-256 hex digest of the full secret. */
export async function hashApiKey(secret: string): Promise<string> {
  const data = new TextEncoder().encode(secret)
  const digest = await crypto.subtle.digest('SHA-256', data)
  const view = new Uint8Array(digest)
  let hex = ''
  for (const b of view) hex += b.toString(16).padStart(2, '0')
  return hex
}

export class ApiKeyService {
  constructor(private db: D1Database, private tenantId = 'default') {}

  private docService(): DocumentsService {
    return new DocumentsService(this.db, {
      queryableFields: API_KEY_QUERYABLE,
      tenantId: this.tenantId,
      maxVersionsPerRoot: 1,
    })
  }

  /** Count a user's active (non-revoked) keys — used to enforce the per-user cap. */
  async countForUser(userId: string): Promise<number> {
    const row = await this.db
      .prepare(
        `SELECT COUNT(*) AS c FROM documents
         WHERE type_id = 'api_key' AND tenant_id = ? AND is_current_draft = 1
           AND deleted_at IS NULL AND q_apikey_user_id = ? AND q_apikey_revoked = 0`,
      )
      .bind(this.tenantId, userId)
      .first<{ c: number }>()
    return row?.c ?? 0
  }

  /**
   * Mint a new key for a user. The returned `key` is the only time the plaintext
   * exists outside the caller — it is hashed before storage.
   */
  async create(input: { userId: string; name: string; expiresAt?: number | null }): Promise<CreatedApiKey> {
    const name = input.name.trim() || 'API Key'
    const secret = generateApiKeySecret()
    const keyHash = await hashApiKey(secret)
    const prefix = secret.slice(0, DISPLAY_PREFIX_LEN)
    const expiresAt = input.expiresAt ?? null

    const doc = await this.docService().create(
      createDocumentSchema.parse({
        typeId: 'api_key',
        tenantId: this.tenantId,
        title: name,
        ownerId: input.userId,
        publishOnCreate: true,
        data: {
          name,
          userId: input.userId,
          keyHash,
          keyPrefix: prefix,
          revoked: 0,
          lastUsedAt: null,
          expiresAt,
        },
      }),
      input.userId,
    )

    return { id: doc.rootId, key: secret, name, prefix, expiresAt }
  }

  /** List a user's non-revoked keys (metadata only — never the secret or hash). */
  async list(userId: string): Promise<ApiKeySummary[]> {
    const res = await this.db
      .prepare(
        `SELECT root_id, data, created_at FROM documents
         WHERE type_id = 'api_key' AND tenant_id = ? AND is_current_draft = 1
           AND deleted_at IS NULL AND q_apikey_user_id = ? AND q_apikey_revoked = 0
         ORDER BY created_at DESC`,
      )
      .bind(this.tenantId, userId)
      .all<{ root_id: string; data: string; created_at: number }>()

    return (res.results ?? []).map((row) => {
      const d = JSON.parse(row.data) as Record<string, any>
      return {
        id: row.root_id,
        name: d.name ?? 'API Key',
        prefix: d.keyPrefix ?? '',
        createdAt: row.created_at,
        lastUsedAt: d.lastUsedAt ?? null,
        expiresAt: d.expiresAt ?? null,
      }
    })
  }

  /**
   * Revoke (hard-delete) a key owned by `userId`. Credentials are erased, not
   * soft-flagged. Returns false if the key does not exist or is not owned by
   * the caller (no information leak about other users' keys).
   */
  async revoke(rootId: string, userId: string): Promise<boolean> {
    const row = await this.db
      .prepare(
        `SELECT q_apikey_user_id AS owner FROM documents
         WHERE root_id = ? AND tenant_id = ? AND type_id = 'api_key' AND is_current_draft = 1 AND deleted_at IS NULL`,
      )
      .bind(rootId, this.tenantId)
      .first<{ owner: string }>()
    if (!row || row.owner !== userId) return false

    await this.docService().erase(rootId, this.tenantId)
    return true
  }

  /**
   * Resolve a presented secret to its owning user, or null. Rejects unknown,
   * revoked, expired keys and inactive users. Best-effort updates lastUsedAt.
   */
  async resolve(secret: string): Promise<ResolvedApiKeyUser | null> {
    if (!secret || !secret.startsWith(KEY_PREFIX)) return null
    const keyHash = await hashApiKey(secret)

    const keyRow = await this.db
      .prepare(
        `SELECT root_id, data FROM documents
         WHERE type_id = 'api_key' AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
           AND q_apikey_hash = ? AND q_apikey_revoked = 0
         LIMIT 1`,
      )
      .bind(this.tenantId, keyHash)
      .first<{ root_id: string; data: string }>()
    if (!keyRow) return null

    const d = JSON.parse(keyRow.data) as Record<string, any>
    if (d.expiresAt != null && Date.now() > Number(d.expiresAt)) return null

    const user = await this.db
      .prepare(`SELECT id, email, role, is_active, is_super_admin FROM auth_user WHERE id = ?`)
      .bind(d.userId)
      .first<{ id: string; email: string; role: string; is_active: number; is_super_admin: number }>()
    if (!user || user.is_active !== 1) return null

    // Best-effort usage stamp; never block auth on a write failure.
    try {
      await this.touchLastUsed(keyRow.root_id, d)
    } catch {
      /* non-fatal */
    }

    return {
      userId: user.id,
      email: user.email,
      role: user.role ?? 'viewer',
      isSuperAdmin: user.is_super_admin === 1,
    }
  }

  /** Update lastUsedAt in-place (single-version type, no history churn). */
  private async touchLastUsed(rootId: string, data: Record<string, any>): Promise<void> {
    const next = JSON.stringify({ ...data, lastUsedAt: Date.now() })
    await this.db
      .prepare(
        `UPDATE documents SET data = ? WHERE root_id = ? AND tenant_id = ? AND type_id = 'api_key' AND is_current_draft = 1`,
      )
      .bind(next, rootId, this.tenantId)
      .run()
  }
}
