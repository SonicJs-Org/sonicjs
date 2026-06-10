import { D1Database } from '@cloudflare/workers-types'
import { z } from 'zod'
import { DocumentTypeRegistry } from './document-type-registry'

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
 * DB-driven collections are not auto-registered as document types by default.
 * Content types must be defined in code and registered explicitly.
 */
export async function autoRegisterCollectionDocumentTypes(db: D1Database): Promise<string[]> {
  void db
  return []
}
