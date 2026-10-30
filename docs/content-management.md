# Content Management

SonicJS stores all content as **documents** in a unified repository. Collections define schemas; documents hold the data. This guide covers creating, publishing, and controlling access to content.

## Content Model

Every piece of content — blog posts, pages, media metadata, settings — is a document:

```
Collection (code-defined schema)
  → Document Type (registered at bootstrap)
    → Documents (versioned rows in the documents table)
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Collection** | Code-defined schema + display config (e.g. `blog_post`) |
| **Document Type** | Database registration of a collection's schema, settings, and queryable fields |
| **Document** | A content record — title, slug, data (JSON), status, timestamps |
| **Root ID** | Stable identifier across all versions of a document |
| **Version** | Each save creates a new version row; only one is `is_current_draft` |

## Content Status Workflow

Documents have two independent axes:

- **`is_current_draft`** — the working copy visible in the admin editor
- **`is_published`** — the live version served to public API consumers

```
Create (draft)
  → Save Draft (updates working copy)
  → Publish (creates a published snapshot; draft continues independently)
  → Unpublish (removes the published snapshot)
  → Archive (sets status to 'archived')
```

A published document stays live while editors save new drafts. Publishing promotes the current draft to a new published snapshot.

### Status Labels

| Status | Meaning |
|--------|---------|
| `draft` | Work in progress — not visible to public readers |
| `published` | Live — visible to users with `read` permission |
| `archived` | Hidden — preserved for reference but not served |

## Creating Content

### Admin Interface

1. Navigate to **Admin Panel → Content** (`/admin/content`)
2. Select a collection (e.g. "Blog Posts")
3. Click **New**
4. Fill in fields (title, slug, body, etc.)
5. Click **Save Draft** or **Publish**

### API

```typescript
// Create a document (requires authentication + create permission)
const res = await fetch('/api/documents', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    typeId: 'blog_post',
    title: 'My First Post',
    slug: 'my-first-post',
    data: {
      title: 'My First Post',
      content: '<p>Hello world</p>',
      author: userId,
    },
    publishOnCreate: true,
  }),
})
```

## Reading Content

### Public API

```bash
# List published content for a collection
curl http://localhost:8787/api/collections/blog-posts/content

# Get a single document by root ID
curl http://localhost:8787/api/documents/root/{rootId}

# Filter by data fields
curl "http://localhost:8787/api/content?collection=blog_post&filter[data.category]=tech"
```

### Access Control

**Collections default to deny for public access.** Anonymous requests only see content from collections that explicitly opt in:

```typescript
// In your collection config
export default {
  name: 'blog_post',
  displayName: 'Blog Post',
  schema: { /* ... */ },

  access: {
    public: ['read'],  // Allow unauthenticated read access
  },
} satisfies CollectionConfig
```

Without `access: { public: ['read'] }`, the collection's content is only visible to authenticated users with appropriate roles (admin, editor, viewer).

### Visibility Rules

| Caller | Sees |
|--------|------|
| Anonymous (no auth) | Published documents from collections with `public: ['read']` |
| Viewer | Published documents from collections granting viewer `read` |
| Editor | Published + drafts (current-draft view) |
| Admin | Everything including archived |

### Per-Document Overrides

Individual documents can have explicit `allow` or `deny` overrides in the `document_permissions` table, overriding the collection's base grants:

```typescript
// Deny public read on a specific document
await perms.grantPermission({
  tenantId: 'default',
  rootId: documentRootId,
  principalType: 'public',
  principalId: '*',
  permission: 'read',
  effect: 'deny',
})
```

**Precedence:** deny wins → explicit allow → base grants.

## Scheduled Publishing

Documents support time-windowed visibility:

```typescript
{
  scheduledAt: 1719849600,  // Unix timestamp (seconds) — visible after this time
  expiresAt: 1722528000,   // Unix timestamp (seconds) — hidden after this time
}
```

Public reads automatically filter by the schedule window. Authenticated reads bypass it.

## Content Versioning

Collections with `versioning: true` retain historical versions:

```typescript
export default {
  name: 'blog_post',
  displayName: 'Blog Post',
  schema: { /* ... */ },
  versioning: true,
} satisfies CollectionConfig
```

Each `saveDraft` creates a new version row. Old versions are pruned to `maxVersionsPerRoot` (default: 50). Without versioning, `saveDraft` updates the draft row in place.

## Defining Collections

Collections are code-defined in TypeScript files and registered at app startup:

```typescript
// src/collections/blog-posts.collection.ts
import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'blog_post',
  displayName: 'Blog Post',
  slug: 'blog-posts',
  description: 'Manage your blog posts',
  icon: '📝',

  schema: {
    type: 'object',
    properties: {
      title: { type: 'string', title: 'Title', required: true },
      slug: { type: 'slug', title: 'URL Slug', required: true },
      content: { type: 'lexical', title: 'Content', required: true },
      author: { type: 'user', title: 'Author', required: true },
    },
    required: ['title', 'slug', 'content', 'author'],
  },

  access: { public: ['read'] },

  listFields: ['title', 'author', 'status'],
  searchFields: ['title', 'content'],
  defaultSort: 'createdAt',
  defaultSortOrder: 'desc',

  managed: true,
  isActive: true,
} satisfies CollectionConfig
```

Register in your app entry point:

```typescript
// src/index.ts
import { registerCollections } from '@sonicjs-cms/core'
import blogPosts from './collections/blog-posts.collection'

registerCollections([blogPosts])
```

See [Collections Configuration](collections-config.md) for the full field type reference.

## Media

Media files (images, PDFs, videos) are stored in Cloudflare R2 with metadata tracked as `media_asset` documents. Upload via the admin media library or the `/api/media/upload` endpoint.

Supported formats: JPEG, PNG, GIF, WebP, SVG, PDF, MP4, WebM, MP3, WAV.

## Best Practices

1. **Use `access: { public: ['read'] }` intentionally** — only expose collections that should be publicly readable
2. **Leverage status workflow** — save drafts freely, publish when ready
3. **Use scheduled publishing** for time-sensitive content
4. **Enable versioning** for content that needs an audit trail
5. **Define collections in code** — configuration over UI means reproducible deployments

## Related Documentation

- [Authentication & Authorization](authentication.md) — ACL model, RBAC, public access
- [Collections Configuration](collections-config.md) — Field types and schema reference
- [API Reference](api-reference.md) — Content API endpoints
- [API Filtering](api-filtering.md) — Query parameter reference
