# Authentication & Authorization

SonicJS uses [Better Auth](https://www.better-auth.com/) for session management and a document-backed RBAC system for fine-grained access control. Content visibility is controlled through per-document-type **base grants** and optional per-document **ACL overrides**.

## Table of Contents

- [Overview](#overview)
- [Session Management](#session-management)
- [Auth Endpoints](#auth-endpoints)
- [Middleware](#middleware)
- [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
- [Content Access Control](#content-access-control)
- [Collection Access Configuration](#collection-access-configuration)
- [Admin Panel Access](#admin-panel-access)
- [Multi-Tenant Authentication](#multi-tenant-authentication)
- [Environment Variables](#environment-variables)
- [Implementing Auth in Custom Routes](#implementing-auth-in-custom-routes)
- [Security Best Practices](#security-best-practices)

## Overview

The auth stack has three layers:

1. **Better Auth** — session lifecycle, credential verification, OAuth, magic links, email OTP
2. **RBAC (Roles & Verbs)** — who can do what in the admin panel and API (stored as documents, managed via admin UI)
3. **Document ACL** — per-type base grants and per-document permission overrides that control public vs authenticated content visibility

```
Request → Better Auth session middleware → c.get('user')
                                            ↓
                              requireAuth()  →  requireRbac(resource, verb)
                                            ↓
                              Document ACL (baseGrants + document_permissions)
```

## Session Management

Better Auth manages sessions via HTTP-only cookies. No JWTs are issued for new sessions.

### Cookie

| Cookie | Purpose | Flags |
|--------|---------|-------|
| `better-auth.session_token` | Session identifier | `httpOnly`, `Secure`, `SameSite=Lax` |
| `csrf_token` | CSRF protection | `SameSite=Lax` (readable by JS) |

Sessions are stored in the `auth_session` D1 table and cached in Cloudflare KV (`CACHE_KV`) for fast lookups. Default expiration: **7 days**, with a 1-day refresh window.

### User Context

After the session middleware runs, authenticated requests have:

```typescript
const user = c.get('user')
// {
//   userId: string,       // auth_user.id
//   email: string,        // auth_user.email
//   role: string,         // projected from RBAC (e.g. 'admin', 'editor', 'viewer')
//   isSuperAdmin: boolean
// }
```

Anonymous requests have `c.get('user')` as `undefined`.

## Auth Endpoints

### Better Auth (auto-mounted)

These are provided by Better Auth and handle session lifecycle:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/sign-in/email` | Sign in with email + password |
| POST | `/auth/sign-up/email` | Register a new account |
| POST | `/auth/sign-out` | Invalidate session server-side |
| GET | `/auth/get-session` | Fetch current session |
| POST | `/auth/magic-link/send-link` | Send a magic link email |
| POST | `/auth/magic-link/verify-link` | Verify a magic link |
| POST | `/auth/email-otp/send-otp` | Send a 6-digit OTP |
| POST | `/auth/email-otp/verify-otp` | Verify an OTP |
| GET | `/auth/oauth/:provider` | Initiate OAuth flow (GitHub, Google) |

### SonicJS Custom Endpoints

These wrap Better Auth with SonicJS-specific logic (HTML forms, invitations, RBAC seeding):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/login` | Login page (HTML form) |
| POST | `/auth/login/form` | Form-based login (delegates to BA) |
| GET | `/auth/register` | Registration page (HTML form) |
| POST | `/auth/register/form` | Form-based registration |
| GET/POST | `/auth/logout` | Sign out + clear cookies |
| GET | `/auth/me` | Current user profile (requires auth) |
| POST | `/auth/refresh` | Sliding-session refresh (grace window) |
| POST | `/auth/request-password-reset` | Send password reset email |
| GET | `/auth/reset-password` | Password reset form |
| POST | `/auth/reset-password` | Process password reset |
| GET | `/auth/accept-invitation` | Invitation acceptance form |
| POST | `/auth/accept-invitation` | Process invitation |
| POST | `/auth/seed-admin` | Dev/test: create seed users |

### Login Example (API Client)

```bash
# Sign in and receive a session cookie
curl -X POST "http://localhost:8787/auth/sign-in/email" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "admin@sonicjs.com", "password": "sonicjs!"}'

# Use the session cookie for authenticated requests
curl "http://localhost:8787/admin/content" -b cookies.txt
```

### Login Example (Frontend)

```typescript
const res = await fetch('http://localhost:8787/auth/sign-in/email', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
})
```

`credentials: 'include'` is required so the browser sends/receives the session cookie.

## Middleware

### requireAuth()

Enforces authentication. Returns 401 (API) or redirects to `/auth/login` (HTML).

```typescript
import { requireAuth } from '@sonicjs-cms/core'

app.get('/api/protected', requireAuth(), (c) => {
  const user = c.get('user')
  return c.json({ userId: user.userId })
})
```

### requireRole()

Checks the legacy `auth_user.role` column. Prefer `requireRbac()` for new code.

```typescript
import { requireRole } from '@sonicjs-cms/core'

app.delete('/api/admin/users/:id',
  requireAuth(),
  requireRole('admin'),
  handler
)
```

### requireRbac()

Dynamic RBAC enforcement — checks live grants from `RbacService`.

```typescript
import { requireRbac } from '@sonicjs-cms/core'

app.get('/admin/content',
  requireAuth(),
  requireRbac('documents', 'read'),
  handler
)
```

### optionalAuth()

Populates `c.get('user')` if a session exists, but does not require it. Used by public API routes that return different content to authenticated vs anonymous users.

```typescript
import { optionalAuth } from '@sonicjs-cms/core'

app.get('/api/content', optionalAuth(), (c) => {
  const user = c.get('user') // may be undefined
  // Authenticated users see drafts; anonymous see published only
})
```

## Role-Based Access Control (RBAC)

RBAC is document-backed — roles, verbs, and grants are stored as documents (type `rbac_role`, `rbac_verb`, `rbac_user_roles`) and managed through the admin UI at `/admin/rbac`.

### Concepts

| Concept | Description |
|---------|-------------|
| **Role** | Named permission group (e.g. `admin`, `editor`). Users can hold multiple roles. |
| **Verb** | An action: `access`, `read`, `create`, `update`, `delete`, `manage` |
| **Resource** | What the action targets: `portal`, `documents`, `document_type:blog_post`, `rbac`, `*` |
| **Grant** | A `(resource, verb, scope)` tuple attached to a role |
| **Scope** | `any` (all documents), `own` (only user's own), `none` (denied) |

### Seeded Roles

On first bootstrap, `ensureSystemRbacSeed()` creates:

| Role | System? | Grants | Purpose |
|------|---------|--------|---------|
| **Administrator** | Yes (locked) | `*:manage` + `portal:access` + `rbac:manage` | Full access. Cannot be deleted. |
| **Editor** | No | `documents:manage`, `document_type:*:manage`, `portal:access`, `settings:read` | Content management |
| **Authenticated** | No | `document_type:*:read` | Signed-in users without admin access |
| **Public** | No | *(empty)* | Placeholder for future public-facing grants |

The `admin` role is the only locked system role. `editor`, `authenticated`, and `public` are deletable example roles that admins can customize or remove.

### Grant Resolution

```
can(userId, resource, verb)
  1. Load user's roles (from rbac_user_roles document)
  2. Merge all grants across roles
  3. Wildcard expansion: resource '*' matches everything; verb 'manage' implies all verbs
  4. Scope precedence: 'any' > 'own' > 'none'
  5. Return true if any matching grant has scope != 'none'
```

### Managing Roles (Admin UI)

Navigate to **Admin Panel → RBAC** (`/admin/rbac`). The UI has two tabs:

- **Permission Matrix** — visual grid of roles × resources × verbs with checkboxes
- **Roles & Verbs** — create/edit/delete roles and verbs, toggle Admin Panel access per role

### Managing Roles (Programmatic)

```typescript
import { RbacService } from '@sonicjs-cms/core'

const rbac = new RbacService(env.DB)

// Create a custom role
await rbac.createRole('Contributor', 'Content contributors')

// Set grants for a role
await rbac.setRoleGrants('role-contributor', [
  { resource: 'documents', verb: 'read' },
  { resource: 'documents', verb: 'create' },
  { resource: 'portal', verb: 'access' },
])

// Assign a role to a user
await rbac.addUserRoleByName(userId, 'contributor')

// Check permissions
const canEdit = await rbac.can(userId, 'documents', 'update')
```

### Legacy Role Projection

The `auth_user.role` column is a **derived projection** of RBAC roles. When `setUserRoles()` runs, it updates this column to the highest-precedence role name (`admin` > `editor` > custom > `viewer`). This keeps legacy code (`requireRole('admin')`, `c.get('user').role`) working without schema changes.

### Self-Lockout Protection

The RBAC service prevents removing all users who have both `portal:access` AND `rbac:manage`. This guards against accidentally locking everyone out of the admin panel.

## Content Access Control

Content visibility uses a two-layer ACL: **base grants** on document types and optional **per-document overrides**.

### How It Works

Every content API request resolves a **principal set**:

```typescript
// Anonymous request
principalSet = [{ type: 'public', id: '*' }]

// Authenticated request
principalSet = [
  { type: 'user', id: userId },
  { type: 'role', id: role },  // e.g. 'admin', 'editor'
]
```

When reading content, the ACL check runs:

```
isAllowed(principalSet, rootId, permission, typeSettings)
  1. Check document_permissions table for per-document overrides
  2. If any override is 'deny' → DENIED (deny wins)
  3. If any override is 'allow' → ALLOWED
  4. Fall back to baseGrants on the document type
```

### Base Grants

Each document type has `settings.baseGrants` — a map of principal keys to allowed permissions:

```typescript
{
  baseGrants: {
    public: ['read'],           // anonymous visitors can read
    admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
    editor: ['read', 'create', 'update', 'publish'],
    viewer: ['read'],
  }
}
```

**Key: `public`** — matches the `{ type: 'public', id: '*' }` principal (unauthenticated requests).

**Key: `admin`, `editor`, etc.** — matches `{ type: 'role', id: '<role>' }` principals.

### Per-Document Overrides

The `document_permissions` table allows explicit `allow` or `deny` per document per principal:

```typescript
import { DocumentPermissionsService } from '@sonicjs-cms/core'

const perms = new DocumentPermissionsService(env.DB)

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

### Deny-by-Default

**Collections default to no public access.** Unless a collection explicitly opts in via the `access` property, only authenticated users with appropriate roles (admin, editor) can access the content.

This matches the secure-by-default posture of Strapi and Payload CMS — you must explicitly enable public access per collection.

### Available Permissions

| Permission | Description |
|------------|-------------|
| `read` | View published content |
| `create` | Create new documents |
| `update` | Edit existing documents |
| `delete` | Remove documents |
| `publish` | Publish/unpublish documents |
| `manage` | Full access (implies all above) |

## Collection Access Configuration

Collections define their access control via the `access` property on `CollectionConfig`:

```typescript
import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'blog_post',
  displayName: 'Blog Post',
  schema: { type: 'object', properties: { /* ... */ } },

  // Opt in to public read access
  access: {
    public: ['read'],
  },

  managed: true,
  isActive: true,
} satisfies CollectionConfig
```

### Access Property Reference

The `access` property maps principal keys to arrays of permissions:

```typescript
access?: Record<string, ('read' | 'create' | 'update' | 'delete' | 'publish' | 'manage')[]>
```

**Principal keys:**
- `'public'` — unauthenticated visitors
- `'admin'`, `'editor'`, `'viewer'` — built-in RBAC roles
- Any custom role name

**Built-in defaults** (always applied, can be overridden):
- `admin: ['read', 'create', 'update', 'delete', 'publish', 'manage']`
- `editor: ['read', 'create', 'update', 'publish']`
- `viewer: ['read']`

The `access` entries merge on top of these defaults. To revoke a default, set the key to an empty array.

### Examples

**Public blog (anyone can read):**
```typescript
access: {
  public: ['read'],
}
```

**Internal-only (admin and editor defaults, no public):**
```typescript
// Omit `access` entirely — this is the default
```

**Public read + viewer can also create:**
```typescript
access: {
  public: ['read'],
  viewer: ['read', 'create'],
}
```

**Restrict editor to read-only:**
```typescript
access: {
  editor: ['read'],  // overrides default ['read', 'create', 'update', 'publish']
}
```

### How It Flows

```
CollectionConfig.access
  → autoRegisterCollectionDocumentTypes()
    → document_types.settings.baseGrants
      → DocumentPermissionsService.isAllowed()
        → API response (visible or 403/filtered)
```

## Admin Panel Access

The admin panel (`/admin/*`) is gated by two requirements:

1. **Authentication** — must be signed in (`requireAuth()`)
2. **Portal access** — must have the `portal:access` RBAC grant (`requireRbac('portal', 'access')`)

The seeded `admin` and `editor` roles include `portal:access`. Custom roles need it explicitly added via the RBAC admin UI.

Individual admin sections have additional RBAC requirements:

| Section | Required Grant |
|---------|---------------|
| Dashboard | `dashboard:read` |
| Content | `documents:read` |
| Media | `documents:read` |
| RBAC | `rbac:manage` |
| Settings | `settings:read` |
| Users | `users:read` |

Navigation items are stripped server-side based on the user's permission set — users only see sections they can access.

## Multi-Tenant Authentication

When the multi-tenant plugin is active:

- Tenant is resolved per request from headers, cookies, or subdomain
- Users can have different roles in different tenants
- `c.get('tenantRole')` holds the user's role in the active tenant
- Super-admins (`isSuperAdmin: true`) bypass tenant gates
- Document ACL is tenant-scoped — a deny in tenant A does not affect tenant B

Single-tenant deployments use the constant tenant ID `'default'`.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BETTER_AUTH_SECRET` | Yes | — | Session signing secret (16+ chars) |
| `BETTER_AUTH_URL` | No | Auto-detected | Base URL for auth callbacks |
| `JWT_EXPIRES_IN` | No | `30d` | Legacy JWT expiration (for refresh endpoint) |
| `JWT_REFRESH_GRACE_SECONDS` | No | `604800` (7d) | Grace window for token refresh |
| `CORS_ORIGINS` | No | — | Comma-separated allowed origins |
| `GITHUB_CLIENT_ID` | No | — | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | No | — | GitHub OAuth client secret |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth client secret |

### wrangler.toml Example

```toml
[vars]
BETTER_AUTH_SECRET = "your-secure-random-secret-at-least-16-chars"
CORS_ORIGINS = "http://localhost:8787,http://localhost:4321,https://yourdomain.com"

# Optional: OAuth providers
# GITHUB_CLIENT_ID = "..."
# GITHUB_CLIENT_SECRET = "..."
```

## Implementing Auth in Custom Routes

### Protected Route

```typescript
import { Hono } from 'hono'
import { requireAuth, requireRbac } from '@sonicjs-cms/core'

const app = new Hono()

app.get('/api/admin/stats',
  requireAuth(),
  requireRbac('dashboard', 'read'),
  (c) => {
    const user = c.get('user')
    return c.json({ stats: { /* ... */ }, requestedBy: user.email })
  }
)
```

### Public + Authenticated Hybrid

```typescript
import { optionalAuth } from '@sonicjs-cms/core'

app.get('/api/articles', optionalAuth(), async (c) => {
  const user = c.get('user')

  if (user?.role === 'admin' || user?.role === 'editor') {
    // Privileged: return drafts + published
    return c.json({ data: await getAllArticles() })
  }

  // Public: return only published (ACL-filtered)
  return c.json({ data: await getPublishedArticles() })
})
```

### Custom RBAC Check

```typescript
import { RbacService } from '@sonicjs-cms/core'

app.put('/api/content/:id', requireAuth(), async (c) => {
  const user = c.get('user')
  const rbac = new RbacService(c.env.DB)

  const scope = await rbac.getPermissionScope(user.userId, 'documents', 'update')

  if (scope === 'none') {
    return c.json({ error: 'Permission denied' }, 403)
  }

  if (scope === 'own') {
    // Only allow editing own documents
    const doc = await getDocument(c.req.param('id'))
    if (doc.ownerId !== user.userId) {
      return c.json({ error: 'Permission denied' }, 403)
    }
  }

  // scope === 'any': can edit anything
  return c.json({ updated: true })
})
```

## Security Best Practices

### 1. Set BETTER_AUTH_SECRET

Never use the development default in production. Generate a secure secret:

```bash
openssl rand -base64 32
```

### 2. Configure CORS

Set `CORS_ORIGINS` in `wrangler.toml` to your frontend origins. The middleware applies globally — including `/auth/*` routes.

```toml
CORS_ORIGINS = "https://yourdomain.com,https://admin.yourdomain.com"
```

### 3. Use credentials: 'include'

Frontend clients must include credentials so the session cookie is sent:

```typescript
fetch(url, { credentials: 'include', /* ... */ })
```

### 4. Validate Input at Boundaries

Use Zod schemas for all API inputs:

```typescript
import { z } from 'zod'
import { zValidator } from '@hono/zod-validator'

const schema = z.object({
  title: z.string().min(1).max(200),
  content: z.string(),
})

app.post('/api/content', requireAuth(), zValidator('json', schema), handler)
```

### 5. Escape HTML Output

All user-controlled values rendered into HTML must be escaped:

```typescript
import { escapeHtml } from '@sonicjs-cms/core'

const safe = escapeHtml(userInput)
```

### 6. Prefer requireRbac over requireRole

`requireRole()` checks a static column. `requireRbac()` checks live grants and respects the full permission model (wildcard resources, manage verb, scopes).

### 7. First User Gets Admin

The first user to register via the registration form automatically receives the `admin` role. Subsequent users default to `viewer`.

## Related Documentation

- [API Reference](api-reference.md) — Content API endpoints and authentication
- [Collections Configuration](collections-config.md) — Collection schema and access config
- [Content Management](content-management.md) — Draft/publish workflow
- [Deployment](deployment.md) — Production configuration
