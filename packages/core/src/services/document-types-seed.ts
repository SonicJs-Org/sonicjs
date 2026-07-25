import { D1Database } from '@cloudflare/workers-types'
import { z } from 'zod'
import { DocumentTypeRegistry } from './document-type-registry'
import { getCollectionRegistry } from './collection-registry'
import type { Permission } from '../schemas/document'

// Passthrough schema: accepts any JSON object for POC types.
// Individual fields are validated at the queryable-field level; the full
// payload schema is a future enhancement (addDocumentType will accept Zod schemas).
const anyObject = z.record(z.string(), z.unknown())

// Registers the POC document types idempotently during bootstrap.
// These are the candidate types from the document model plan.
// Each call is a no-op if the type already exists and the schema hasn't changed.
export async function bootstrapDocumentTypes(db: D1Database): Promise<void> {
  const registry = new DocumentTypeRegistry(db)
  // Pre-warm cache: 1 SELECT for all types instead of N individual SELECTs.
  // register() will hit cache and early-return when schema is unchanged.
  await registry.preloadAll()

  // Site settings: internal singleton config — never surfaced in content admin.
  await registry.register({
    id: 'site_settings',
    name: 'site_settings',
    displayName: 'Site Settings',
    description: 'Global site configuration (internal; managed via admin settings UI)',
    source: 'system',
    schema: anyObject,
    settings: {
      internal: true,
      maxVersionsPerRoot: 1,
      baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] },
    },
    queryableFields: [],
  })

  // Blog post: the code-managed `blog_post` collection is backed by the document model.
  // The matching id (`blog_post` == collection name) is how content admin detects doc-backing.
  await registry.register({
    id: 'blog_post',
    name: 'blog_post',
    displayName: 'Blog Post',
    description: 'Blog post (document-backed; edited via the content collection UI)',
    source: 'system',
    schema: anyObject,
    settings: {
      versioning: true,
      baseGrants: { public: ['read'], admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'], editor: ['read', 'create', 'update', 'publish'], viewer: ['read'] },
      maxVersionsPerRoot: 50,
    },
    queryableFields: [
      { name: 'difficulty', kind: 'scalar', type: 'text', column: 'q_blog_difficulty' },
      { name: 'author',     kind: 'scalar', type: 'text', column: 'q_blog_author' },
    ],
  })

  // Plugin registry (document-backed plugin management)
  await registry.register({
    id: 'plugin',
    name: 'plugin',
    displayName: 'Plugin',
    description: 'System plugin record (managed by the plugin bootstrap service)',
    source: 'system',
    schema: anyObject,
    settings: {
      baseGrants: { admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'] },
      maxVersionsPerRoot: 1,
      internal: true,
    },
    queryableFields: [
      { name: 'status',   kind: 'scalar', type: 'text',    column: 'q_plugin_status' },
      { name: 'category', kind: 'scalar', type: 'text',    column: 'q_plugin_category' },
      { name: 'isCore',   kind: 'scalar', type: 'integer', column: 'q_plugin_is_core' },
    ],
  })

  // Tenant registry (document-backed multi-tenancy; rows managed by the multi-tenant plugin).
  // Tenant records are platform metadata and live under the 'default' tenant themselves.
  // Zero rows until the multi-tenant plugin is activated and used.
  await registry.register({
    id: 'tenant',
    name: 'tenant',
    displayName: 'Tenant',
    description: 'Tenant record (managed by the multi-tenant plugin; slug = tenant id)',
    source: 'system',
    schema: anyObject,
    settings: {
      baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] },
      maxVersionsPerRoot: 1,
      internal: true,
    },
    queryableFields: [
      { name: 'status', kind: 'scalar', type: 'text', column: 'q_tenant_status' },
      { name: 'domain', kind: 'scalar', type: 'text', column: 'q_tenant_domain' },
    ],
  })

  // User profile (auth-owned). One document per user, addressed by slug = userId.
  // Replaces the auth_user_profiles table. Typed fields + custom fields live in `data`.
  await registry.register({
    id: 'user_profile',
    name: 'user_profile',
    displayName: 'User Profile',
    description: 'Per-user profile record (auth-owned; one document per user, slug = userId)',
    source: 'system',
    isAuth: true,
    schema: anyObject,
    settings: {
      // Hidden from the content admin surfaces; a single mutable record (no version history).
      internal: true,
      maxVersionsPerRoot: 1,
      pii: true,
      baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] },
    },
    queryableFields: [],
  })

  // Media asset (document-authoritative media library). One document per uploaded R2 object.
  // Internal: managed via the media library + media selector, not offered as a content model.
  // Registering here both satisfies the documents.type_id FK and creates the q_media_* columns
  // (DocumentTypeRegistry.register → ensureScalarSchema). Must stay in sync with MEDIA_QUERYABLE
  // in services/media-documents.ts.
  await registry.register({
    id: 'media_asset',
    name: 'media_asset',
    displayName: 'Media Asset',
    description: 'Uploaded media file metadata (managed via the media library; backs an R2 object)',
    source: 'system',
    schema: anyObject,
    settings: {
      internal: true,
      maxVersionsPerRoot: 5,
      baseGrants: {
        public: ['read'],
        admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
        editor: ['read', 'create', 'update'],
        author: ['read', 'create'],
        viewer: ['read'],
      },
    },
    queryableFields: [
      { name: 'mimeType', kind: 'scalar', type: 'text', column: 'q_media_mime' },
      { name: 'folder', kind: 'scalar', type: 'text', column: 'q_media_folder' },
      { name: 'size', kind: 'scalar', type: 'integer', column: 'q_media_size' },
      { name: 'tags', kind: 'facet', type: 'text' },
    ],
  })

  // Plugin activity log (document-backed; replaces legacy plugin_activity_log table which was never migrated)
  await registry.register({
    id: 'plugin_activity',
    name: 'plugin_activity',
    displayName: 'Plugin Activity',
    description: 'Plugin lifecycle event log (installed/activated/deactivated/settings_updated/error)',
    source: 'system',
    schema: anyObject,
    settings: {
      internal: true,
      maxVersionsPerRoot: 1,
      baseGrants: { admin: ['read', 'create', 'manage'] },
    },
    queryableFields: [
      { name: 'pluginId', kind: 'scalar', type: 'text', column: 'q_plugin_activity_plugin_id' },
      { name: 'action',   kind: 'scalar', type: 'text', column: 'q_plugin_activity_action' },
    ],
  })

  // Security audit event (document-backed; replaces legacy security_events table)
  await registry.register({
    id: 'security_event',
    name: 'security_event',
    displayName: 'Security Event',
    description: 'Security audit event (login attempts, lockouts, suspicious activity)',
    source: 'system',
    schema: anyObject,
    settings: {
      internal: true,
      maxVersionsPerRoot: 1,
      baseGrants: { admin: ['read', 'create', 'manage'] },
    },
    queryableFields: [
      { name: 'eventType',  kind: 'scalar', type: 'text',    column: 'q_sa_event_type' },
      { name: 'severity',   kind: 'scalar', type: 'text',    column: 'q_sa_severity' },
      { name: 'userId',     kind: 'scalar', type: 'text',    column: 'q_sa_user_id' },
      { name: 'email',      kind: 'scalar', type: 'text',    column: 'q_sa_email' },
      { name: 'ipAddress',  kind: 'scalar', type: 'text',    column: 'q_sa_ip_address' },
      { name: 'blocked',    kind: 'scalar', type: 'integer', column: 'q_sa_blocked' },
    ],
  })

  // API key (document-backed programmatic access tokens; auth-owned, one document per key).
  // Stores only the SHA-256 hash of the secret (q_apikey_hash) — never the plaintext. PII/credential:
  // revoke hard-erases. See services/api-keys.ts (ApiKeyService) for the write/resolve paths.
  await registry.register({
    id: 'api_key',
    name: 'api_key',
    displayName: 'API Key',
    description: 'Programmatic API access key (auth-owned; only the secret hash is stored)',
    source: 'system',
    isAuth: true,
    schema: anyObject,
    settings: {
      internal: true,
      maxVersionsPerRoot: 1,
      pii: true,
      baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] },
    },
    queryableFields: [
      { name: 'keyHash', kind: 'scalar', type: 'text',    column: 'q_apikey_hash' },
      { name: 'userId',  kind: 'scalar', type: 'text',    column: 'q_apikey_user_id' },
      { name: 'revoked', kind: 'scalar', type: 'integer', column: 'q_apikey_revoked' },
    ],
  })

  // Analytics event (document-backed; replaces legacy analytics_events table)
  await registry.register({
    id: 'analytics_event',
    name: 'analytics_event',
    displayName: 'Analytics Event',
    description: 'Tracked analytics event (page view, user action, custom event)',
    source: 'system',
    schema: anyObject,
    settings: {
      internal: true,
      maxVersionsPerRoot: 1,
      baseGrants: { admin: ['read', 'create', 'manage'] },
    },
    queryableFields: [
      { name: 'event',     kind: 'scalar', type: 'text',    column: 'q_evt_event' },
      { name: 'category',  kind: 'scalar', type: 'text',    column: 'q_evt_category' },
      { name: 'userId',    kind: 'scalar', type: 'text',    column: 'q_evt_user_id' },
      { name: 'sessionId', kind: 'scalar', type: 'text',    column: 'q_evt_session_id' },
      { name: 'path',      kind: 'scalar', type: 'text',    column: 'q_evt_path' },
    ],
  })

  // ── RBAC (auth-owned). 3 document types replace 4 relational tables: ──────────
  //   rbac_role        slug = roleId,  data.grants[] embedded (replaces role_grants)
  //   rbac_verb        slug = verbId
  //   rbac_user_roles  slug = userId,  data.roleIds[] embedded (replaces user_roles)
  // All internal + is_auth so they never surface in content. See services/rbac.ts.
  for (const [id, displayName, description] of [
    ['rbac_role', 'RBAC Role', 'Role record with embedded grants (auth-owned)'],
    ['rbac_verb', 'RBAC Verb', 'Permission verb (auth-owned)'],
    ['rbac_user_roles', 'RBAC User Roles', "Per-user role assignments (auth-owned; slug = userId)"],
  ] as const) {
    await registry.register({
      id,
      name: id,
      displayName,
      description,
      source: 'system',
      isAuth: true,
      schema: anyObject,
      settings: {
        internal: true,
        maxVersionsPerRoot: 1,
        baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] },
      },
      queryableFields: [],
    })
  }
}

/**
 * Register a document type for every code-defined collection in the registry.
 *
 * Code-defined collections become document-backed automatically so that all
 * content writes against them flow through the documents repository. The
 * document type's id == collection name, matching how content admin detects
 * doc-backing.
 */
export async function autoRegisterCollectionDocumentTypes(db: D1Database): Promise<string[]> {
  const registry = new DocumentTypeRegistry(db)
  // Pre-warm cache so register() calls hit cache instead of doing N individual SELECTs.
  await registry.preloadAll()
  const collections = getCollectionRegistry().listActive()
  const registered: string[] = []

  for (const collection of collections) {
    // Skip system/internal collections that already have explicit document type
    // definitions in bootstrapDocumentTypes (e.g. blog_post is seeded above
    // with its own queryable fields). The explicit registration wins.
    if (collection.internal) continue
    if (collection.name === 'blog_post') continue

    try {
      const defaultGrants: Record<string, Permission[]> = {
        admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
        editor: ['read', 'create', 'update', 'publish'],
        viewer: ['read'],
      }
      const baseGrants: Record<string, Permission[]> = collection.access
        ? { ...defaultGrants, ...collection.access }
        : defaultGrants

      await registry.register({
        id: collection.name,
        name: collection.name,
        displayName: collection.displayName,
        description: collection.description,
        source: 'system',
        schema: anyObject,
        settings: {
          baseGrants,
          maxVersionsPerRoot: 50,
          ...(collection.versioning ? { versioning: true } : {}),
        },
        queryableFields: collection.queryableFields ?? [],
      })
      registered.push(collection.name)
    } catch (error) {
      console.error(`[document-types-seed] Failed to register collection "${collection.name}":`, error)
    }
  }

  return registered
}
