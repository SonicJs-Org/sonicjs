import { D1Database } from '@cloudflare/workers-types'
import { z } from 'zod'
import { DocumentTypeRegistry } from './document-type-registry'
import { getCollectionRegistry } from './collection-registry'

// Passthrough schema: accepts any JSON object for POC types.
// Individual fields are validated at the queryable-field level; the full
// payload schema is a future enhancement (addDocumentType will accept Zod schemas).
const anyObject = z.record(z.string(), z.unknown())

// Registers the POC document types idempotently during bootstrap.
// These are the candidate types from the document model plan.
// Each call is a no-op if the type already exists and the schema hasn't changed.
export async function bootstrapDocumentTypes(db: D1Database): Promise<void> {
  const registry = new DocumentTypeRegistry(db)

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
  const collections = getCollectionRegistry().listActive()
  const registered: string[] = []

  for (const collection of collections) {
    // Skip system/internal collections that already have explicit document type
    // definitions in bootstrapDocumentTypes (e.g. blog_post is seeded above
    // with its own queryable fields). The explicit registration wins.
    if (collection.internal) continue
    if (collection.name === 'blog_post') continue

    try {
      await registry.register({
        id: collection.name,
        name: collection.name,
        displayName: collection.displayName,
        description: collection.description,
        source: 'system',
        schema: anyObject,
        settings: {
          baseGrants: {
            public: ['read'],
            admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
            editor: ['read', 'create', 'update', 'publish'],
            viewer: ['read'],
          },
          maxVersionsPerRoot: 50,
        },
        queryableFields: [],
      })
      registered.push(collection.name)
    } catch (error) {
      console.error(`[document-types-seed] Failed to register collection "${collection.name}":`, error)
    }
  }

  return registered
}
