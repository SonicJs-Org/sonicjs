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
    },
    queryableFields: [
      { name: 'status',   kind: 'scalar', type: 'text',    column: 'q_plugin_status' },
      { name: 'category', kind: 'scalar', type: 'text',    column: 'q_plugin_category' },
      { name: 'isCore',   kind: 'scalar', type: 'integer', column: 'q_plugin_is_core' },
    ],
  })

}

/**
 * DB-driven collections are not auto-registered as document types by default.
 * Content types must be defined in code and registered explicitly.
 */
export async function autoRegisterCollectionDocumentTypes(db: D1Database): Promise<string[]> {
  void db
  return []
}
