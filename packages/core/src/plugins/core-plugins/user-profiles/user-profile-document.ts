/**
 * User profile storage backed by the document model.
 *
 * A user's profile is a single `user_profile` document (is_auth type), one per
 * user, addressed by `slug = userId`. The existing unique-slug index enforces
 * one-profile-per-user and indexes the lookup, so no profile-specific table is
 * needed. The current draft IS the live profile (profiles are not draft/publish
 * content); `maxVersionsPerRoot: 1` keeps the version chain from growing.
 *
 * `data` shape:
 *   { displayName?, bio?, company?, jobTitle?, website?, location?, dateOfBirth?,
 *     custom: { ...registry-defined custom fields } }
 *
 * Typed fields and custom fields share one document but live in separate
 * namespaces (custom under `data.custom`) so the two writers never collide.
 */
import { D1Database } from '@cloudflare/workers-types'
import type { DocumentRow } from '../../../schemas/document'
import { DocumentsService } from '../../../services/documents'

export const USER_PROFILE_TYPE_ID = 'user_profile'

/** Typed profile fields (everything that used to be a column on auth_user_profiles). */
export interface ProfileTypedFields {
  displayName?: string | null
  bio?: string | null
  company?: string | null
  jobTitle?: string | null
  website?: string | null
  location?: string | null
  dateOfBirth?: number | null
}

export interface ProfileDocumentData extends ProfileTypedFields {
  custom: Record<string, any>
}

function emptyProfile(): ProfileDocumentData {
  return { custom: {} }
}

function service(db: D1Database): DocumentsService {
  // No queryable fields; a profile is a single mutable record (one version).
  return new DocumentsService(db, { tenantId: 'default', maxVersionsPerRoot: 1, queryableFields: [] })
}

/** Read the current profile document for a user. Returns an empty profile when none exists. */
export async function readProfileData(db: D1Database, userId: string): Promise<ProfileDocumentData> {
  const row = await db
    .prepare(
      `SELECT data FROM documents
       WHERE type_id = ? AND tenant_id = 'default' AND slug = ?
         AND is_current_draft = 1 AND deleted_at IS NULL`,
    )
    .bind(USER_PROFILE_TYPE_ID, userId)
    .first<Pick<DocumentRow, 'data'>>()

  if (!row?.data) return emptyProfile()
  try {
    const parsed = JSON.parse(row.data) as Partial<ProfileDocumentData>
    return { ...parsed, custom: parsed.custom ?? {} }
  } catch {
    return emptyProfile()
  }
}

/**
 * Upsert a user's profile document, merging `patch` into existing data.
 * Top-level typed fields are shallow-merged; `patch.custom` is shallow-merged
 * into `data.custom`. Creates the document on first write.
 */
export async function writeProfileData(
  db: D1Database,
  userId: string,
  patch: Partial<ProfileTypedFields> & { custom?: Record<string, any> },
  updatedBy?: string,
): Promise<void> {
  const existing = await readProfileData(db, userId)
  const { custom: patchCustom, ...patchTyped } = patch
  const merged: ProfileDocumentData = {
    ...existing,
    ...patchTyped,
    custom: { ...existing.custom, ...(patchCustom ?? {}) },
  }

  const svc = service(db)
  const rootRow = await db
    .prepare(
      `SELECT root_id FROM documents
       WHERE type_id = ? AND tenant_id = 'default' AND slug = ?
         AND is_current_draft = 1 AND deleted_at IS NULL`,
    )
    .bind(USER_PROFILE_TYPE_ID, userId)
    .first<{ root_id: string }>()

  const data = merged as unknown as Record<string, unknown>
  if (rootRow?.root_id) {
    await svc.saveDraft(rootRow.root_id, { data, title: merged.displayName ?? null }, updatedBy)
  } else {
    await svc.create(
      {
        typeId: USER_PROFILE_TYPE_ID,
        tenantId: 'default',
        locale: 'default',
        parentRootId: '',
        slug: userId,
        title: merged.displayName ?? null,
        sortOrder: 0,
        visible: true,
        data,
        metadata: {},
        ownerId: userId,
        publishOnCreate: false,
      },
      updatedBy,
    )
  }
}
