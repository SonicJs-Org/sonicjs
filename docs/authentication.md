# Authentication & Security

SonicJS uses **Better Auth** for sign-in, sign-up, and sessions, with role-based access control (RBAC) and optional extension for social login, magic link, 2FA, and other methods.

## Extending Better Auth (custom login methods)

You can add your own login methods (e.g. Google, magic link, 2FA) by passing `auth.extendBetterAuth` when creating the app. The function receives SonicJS’s default Better Auth options; return a merged object with your additions.

**Example: add Google sign-in**

```typescript
// src/index.ts
import { createSonicJSApp } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

const config: SonicJSConfig = {
  auth: {
    extendBetterAuth: (defaults) => ({
      ...defaults,
      socialProviders: {
        google: {
          clientId: process.env.GOOGLE_CLIENT_ID!,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        },
      },
    }),
  },
  // ...collections, plugins, etc.
}

export default createSonicJSApp(config)
```

See [Better Auth docs](https://www.better-auth.com/docs) for `socialProviders`, `magicLink`, `twoFactor`, and other options. Required env: `BETTER_AUTH_SECRET`, `BETTER_AUTH_URL` (see [deployment.md](deployment.md)).

---

## Table of Contents

- [Overview](#overview)
- [Extending Better Auth](#extending-better-auth-custom-login-methods)
- [Authentication Flow](#authentication-flow)
- [Magic Link (Better Auth plugin)](#magic-link-better-auth-plugin)
- [Email OTP (Better Auth plugin)](#email-otp-better-auth-plugin)
- [Role-Based Access Control](#role-based-access-control)
- [Permission System](#permission-system)
- [Auth Routes & Endpoints](#auth-routes--endpoints)
- [Session Management](#session-management)
- [Implementing Authentication in Routes](#implementing-authentication-in-routes)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

SonicJS uses:

- **Better Auth** for sign-in, sign-up, sessions, and password hashing (session stored in DB and cookie)
- **Session cookie** `better-auth.session_token` (HTTP-only; configurable via Better Auth)
- **RBAC** — first user gets `admin`, others get `viewer` by default; registration gating via core-auth plugin
- **Optional extensions** — add magic link, email OTP, Google/GitHub, 2FA via `auth.extendBetterAuth`

Required env: `BETTER_AUTH_SECRET` (min 32 chars), `BETTER_AUTH_URL`. See [deployment.md](deployment.md).

## Authentication Flow

Sign-in and sign-up are handled by **Better Auth** at `/auth/*`. The login and registration HTML pages submit via JavaScript to Better Auth’s API.

### 1. User Registration

**Endpoint:** `POST /auth/sign-up/email` (Better Auth)

```typescript
// Request (JSON)
{
  "email": "user@example.com",
  "password": "securePassword123",
  "name": "John Doe"
  // optional: username, firstName, lastName per Better Auth user fields
}

// Response: session cookie set (better-auth.session_token), user object in body
```

**Process:**
1. Request goes to Better Auth; email/password validated and hashed by Better Auth
2. User created in `users` table; first user gets `admin` role via SonicJS database hooks, others get `viewer`
3. Session created; HTTP-only cookie `better-auth.session_token` set
4. Registration gating (e.g. “registration disabled”) is enforced by SonicJS before showing the register page

### 2. User Login

**Endpoint:** `POST /auth/sign-in/email` (Better Auth)

```typescript
// Request (JSON)
{
  "email": "user@example.com",
  "password": "securePassword123"
}

// Response: session cookie set, user/session in body
```

**Process:**
1. Better Auth verifies credentials and creates/updates session
2. Session cookie set; Hono middleware reads session and sets `c.set('user', { userId, email, role })` for routes

### 3. Session Refresh

Sessions are refreshed automatically by Better Auth (e.g. `session.updateAge`). `POST /auth/refresh` returns a message that refresh is handled by Better Auth; no manual token refresh is required.

## Magic Link (Better Auth plugin)

To add passwordless login via magic link, use Better Auth’s `magicLink` plugin in `auth.extendBetterAuth`. You must implement `sendMagicLink` (e.g. with your email service).

**1. Install any email dependency** your app uses (e.g. Resend, SendGrid).

**2. Extend Better Auth in your app config:**

```typescript
// src/index.ts (or wherever you call createSonicJSApp)
import { createSonicJSApp } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'
import { magicLink } from 'better-auth/plugins/magic-link'

const config: SonicJSConfig = {
  auth: {
    extendBetterAuth: (defaults) => ({
      ...defaults,
      plugins: [
        ...(defaults.plugins ?? []),
        magicLink({
          sendMagicLink: async ({ email, url }) => {
            // Send email with link: url (Better Auth handles token and callback)
            await yourEmailService.send({
              to: email,
              subject: 'Sign in to the app',
              html: `Click to sign in: <a href="${url}">${url}</a>`
            })
          }
        })
      ]
    })
  }
}

export default createSonicJSApp(config)
```

**3. Client-side:** Use Better Auth client with `magicLinkClient` and call `signIn.magicLink({ email, callbackURL })`. See [Better Auth – Magic Link](https://www.better-auth.com/docs/plugins/magic-link).

**4. Database:** If the magic link plugin adds tables, run Better Auth CLI migrate/generate and add any new migrations to your project.

## Email OTP (Better Auth plugin)

To add one-time password (OTP) sign-in via email, use Better Auth’s `emailOtp` plugin in `auth.extendBetterAuth` and implement `sendVerificationOTP`.

**1. Extend Better Auth in your app config:**

```typescript
// src/index.ts
import { createSonicJSApp } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'
import { emailOtp } from 'better-auth/plugins/email-otp'

const config: SonicJSConfig = {
  auth: {
    extendBetterAuth: (defaults) => ({
      ...defaults,
      plugins: [
        ...(defaults.plugins ?? []),
        emailOtp({
          async sendVerificationOTP({ email, otp, type }) {
            if (type === 'sign-in') {
              await yourEmailService.send({
                to: email,
                subject: 'Your sign-in code',
                body: `Your code is: ${otp}`
              })
            }
            // Handle type === 'email-verification' or 'forget-password' if needed
          }
        })
      ]
    })
  }
}

export default createSonicJSApp(config)
```

**2. Client-side:** Add `emailOtpClient` to the Better Auth client and use `authClient.emailOtp.sendVerificationOtp({ email, type: 'sign-in' })`, then verify the OTP with the client API. See [Better Auth – Email OTP](https://www.better-auth.com/docs/plugins/email-otp).

**3. Database:** If the plugin adds tables, run the Better Auth CLI and add migrations as needed.

## Password Security

Better Auth handles password hashing and verification for sign-in and sign-up. SonicJS keeps `AuthManager.hashPassword` and `AuthManager.verifyPassword` only for legacy flows (e.g. seed-admin); do not use them for new features. Password requirements and validation are configured in Better Auth.

## Role-Based Access Control

### Available Roles

| Role | Description | Typical Use Case |
|------|-------------|------------------|
| `admin` | Full system access | System administrators |
| `editor` | Content management | Content managers and editors |
| `viewer` | Read-only access | Basic users, guests |

**Note:** The `author` role exists in team contexts but not as a global role.

### Permission Matrix

| Permission Category | Admin | Editor | Viewer |
|---------------------|-------|--------|--------|
| **Content** | | | |
| Create content | ✅ | ✅ | ❌ |
| Read content | ✅ | ✅ | ✅ |
| Update content | ✅ | ✅ | ❌ |
| Delete content | ✅ | ❌ | ❌ |
| Publish content | ✅ | ✅ | ❌ |
| **Collections** | | | |
| Create collections | ✅ | ❌ | ❌ |
| Read collections | ✅ | ✅ | ✅ |
| Update collections | ✅ | ❌ | ❌ |
| Delete collections | ✅ | ❌ | ❌ |
| Manage fields | ✅ | ❌ | ❌ |
| **Media** | | | |
| Upload media | ✅ | ✅ | ❌ |
| Read media | ✅ | ✅ | ✅ |
| Update media | ✅ | ✅ | ❌ |
| Delete media | ✅ | ❌ | ❌ |
| **Users** | | | |
| Create/invite users | ✅ | ❌ | ❌ |
| Read users | ✅ | ✅ | ✅ |
| Update users | ✅ | ❌ | ❌ |
| Delete users | ✅ | ❌ | ❌ |
| Manage roles | ✅ | ❌ | ❌ |
| **Settings** | | | |
| Read settings | ✅ | ❌ | ❌ |
| Update settings | ✅ | ❌ | ❌ |
| View activity logs | ✅ | ❌ | ❌ |

### Role Middleware

```typescript
import { requireAuth, requireRole } from '../middleware/auth'

// Require authentication only
app.get('/protected', requireAuth(), (c) => {
  const user = c.get('user')
  return c.json({ message: 'Authenticated', user })
})

// Require specific role (single)
app.delete('/admin/users/:id',
  requireAuth(),
  requireRole('admin'),
  (c) => {
    // Admin-only endpoint
  }
)

// Require one of multiple roles
app.post('/content',
  requireAuth(),
  requireRole(['admin', 'editor']),
  (c) => {
    // Admin or editor can create content
  }
)
```

**Implementation:**

```typescript
export const requireRole = (requiredRole: string | string[]) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user')  // { userId, email, role } from Better Auth session

    if (!user) {
      return c.json({ error: 'Authentication required' }, 401)
    }

    const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole]

    if (!roles.includes(user.role)) {
      return c.json({ error: 'Insufficient permissions' }, 403)
    }

    return await next()
  }
}
```

## Permission System

SonicJS AI implements a granular permission system on top of RBAC.

### Permission Structure

```typescript
export interface Permission {
  id: string;           // e.g., 'perm_content_create'
  name: string;         // e.g., 'content.create'
  description: string;  // Human-readable description
  category: string;     // content, users, collections, media, settings
}

export interface UserPermissions {
  userId: string;
  role: string;
  permissions: string[];                    // Global permissions
  teamPermissions?: Record<string, string[]>; // Team-specific permissions
}
```

### Available Permissions

**Content Permissions:**
- `content.create` - Create new content
- `content.read` - View content
- `content.update` - Edit existing content
- `content.delete` - Delete content
- `content.publish` - Publish/unpublish content

**Collections Permissions:**
- `collections.create` - Create new collections
- `collections.read` - View collections
- `collections.update` - Edit collections
- `collections.delete` - Delete collections
- `collections.fields` - Manage collection fields

**Media Permissions:**
- `media.upload` - Upload media files
- `media.read` - View media files
- `media.update` - Edit media metadata
- `media.delete` - Delete media files

**Users Permissions:**
- `users.create` - Invite new users
- `users.read` - View user profiles
- `users.update` - Edit user profiles
- `users.delete` - Deactivate users
- `users.roles` - Manage user roles

**Settings Permissions:**
- `settings.read` - View system settings
- `settings.update` - Modify system settings
- `activity.read` - View activity logs

### Permission Manager

```typescript
import { PermissionManager } from '../middleware/permissions'

// Check if user has permission
const canEdit = await PermissionManager.hasPermission(
  db,
  userId,
  'content.update'
)

if (!canEdit) {
  return c.json({ error: 'Permission denied' }, 403)
}

// Check multiple permissions at once
const permissions = await PermissionManager.checkMultiplePermissions(
  db,
  userId,
  ['content.create', 'content.publish']
)

console.log(permissions)
// { 'content.create': true, 'content.publish': false }
```

### Permission Middleware

```typescript
import { requirePermission, requireAnyPermission } from '../middleware/permissions'

// Require specific permission
app.delete('/content/:id',
  requireAuth(),
  requirePermission('content.delete'),
  async (c) => {
    // User has content.delete permission
  }
)

// Require any of multiple permissions
app.post('/content/:id/publish',
  requireAuth(),
  requireAnyPermission(['content.publish', 'content.update']),
  async (c) => {
    // User has either content.publish OR content.update
  }
)
```

### Team-Based Permissions

```typescript
// Check team-specific permission
const canEditInTeam = await PermissionManager.hasPermission(
  db,
  userId,
  'content.update',
  teamId  // Optional team context
)

// Middleware with team context
app.put('/teams/:teamId/content/:contentId',
  requireAuth(),
  requirePermission('content.update', 'teamId'),
  async (c) => {
    // User has content.update permission in this specific team
  }
)
```

### Permission Caching

The PermissionManager implements in-memory caching:

```typescript
export class PermissionManager {
  private static permissionCache = new Map<string, UserPermissions>()
  private static cacheExpiry = new Map<string, number>()
  private static CACHE_TTL = 5 * 60 * 1000 // 5 minutes

  static async getUserPermissions(db: D1Database, userId: string): Promise<UserPermissions> {
    const cacheKey = `permissions:${userId}`
    const now = Date.now()

    // Check cache
    if (this.permissionCache.has(cacheKey)) {
      const expiry = this.cacheExpiry.get(cacheKey) || 0
      if (now < expiry) {
        return this.permissionCache.get(cacheKey)!
      }
    }

    // Fetch from database and cache...
  }

  // Clear cache when permissions change
  static clearUserCache(userId: string) {
    const cacheKey = `permissions:${userId}`
    this.permissionCache.delete(cacheKey)
    this.cacheExpiry.delete(cacheKey)
  }
}
```

## Auth Routes & Endpoints

### Better Auth API (`/auth/*`)

Sign-in and sign-up are handled by Better Auth. Key endpoints:

- **POST** `/auth/sign-in/email` — Login with `{ email, password }` (JSON). Sets session cookie.
- **POST** `/auth/sign-up/email` — Register with `{ email, password, name }` (JSON). Sets session cookie.
- **POST** `/auth/sign-out` — Log out; clears session cookie.

See [Better Auth docs](https://www.better-auth.com/docs) for the full API (e.g. OAuth, magic link, OTP).

### Login Page

**GET** `/auth/login`

Renders the login HTML form. The form submits via JavaScript to `POST /auth/sign-in/email`. Query parameters: `?error=<message>`, `?message=<message>`.

### Registration Page

**GET** `/auth/register`

Renders the registration HTML form. The form submits via JavaScript to `POST /auth/sign-up/email`. Registration can be gated (e.g. disabled except for first user).

### Legacy API (deprecated)

**POST** `/auth/login` and **POST** `/auth/register` return `410 Gone` with a message to use Better Auth endpoints (`/auth/sign-in/email`, `/auth/sign-up/email`) instead.

### Logout

**GET** `/auth/logout` or **POST** `/auth/logout`

Calls `POST /auth/sign-out` (Better Auth) and redirects to `/auth/login?message=You have been logged out successfully`. Session cookie is cleared by Better Auth.

### Get Current User

**GET** `/auth/me`

Requires authentication (session cookie). Returns the current user from the database.

```typescript
// Request: include session cookie (credentials: 'include' in browser)

// Response (200)
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "role": "viewer",
    "created_at": 1234567890000
  }
}
```

### Session Refresh

**POST** `/auth/refresh`

Requires authentication. Returns a message that session refresh is handled automatically by Better Auth; no new token is returned.

### Seed Admin User (Development)

**POST** `/auth/seed-admin`

Creates default admin user for testing. **Not for production use.**

```typescript
// Response (200)
{
  "message": "Admin user created successfully",
  "user": {
    "id": "admin-user-id",
    "email": "admin@sonicjs.com",
    "username": "admin",
    "role": "admin"
  }
}

// Default credentials
// Email: admin@sonicjs.com
// Password: sonicjs!
```

## Session Management

### Session Cookie

Better Auth manages sessions and sets an HTTP-only session cookie (default name: `better-auth.session_token`). Cookie options (expiration, secure, sameSite) are configured in Better Auth. SonicJS does not set a separate `auth_token` cookie for normal sign-in/sign-up.

### Session Storage

Sessions are stored in the `session` table (Better Auth schema). The Hono middleware calls `auth.api.getSession({ headers })` and, if a session exists, sets `c.set('user', { userId, email, role })` and `c.set('session', session)` for route handlers.

### requireAuth() Behavior

`requireAuth()` reads the user from context (populated by the global session middleware). It does not read an Authorization header or a separate token cookie; authentication is session-cookie based via Better Auth.

### Session Expiration

Session lifetime and refresh are configured in Better Auth (e.g. `session.expiresIn`, `session.updateAge`). When the session is missing or expired, the middleware does not set `user`, and `requireAuth()` returns 401 or redirects to login.

## User Invitation System

### Inviting Users

**POST** `/admin/users/invite` (admin-only)

```typescript
{
  "email": "newuser@example.com",
  "firstName": "Jane",
  "lastName": "Smith",
  "role": "editor"
}
```

Process:
1. Admin creates user record with `is_active = 0`
2. Unique `invitation_token` generated
3. Invitation email sent (or link returned for dev)
4. User account inactive until accepted

### Accepting Invitation

**GET** `/auth/accept-invitation?token=<invitation-token>`

Displays invitation acceptance form with:
- Pre-filled user details (name, email, role)
- Username input
- Password input
- Confirm password input

**POST** `/auth/accept-invitation`

```typescript
// Form data
{
  "token": "invitation-token",
  "username": "janesmith",
  "password": "securePassword123",
  "confirm_password": "securePassword123"
}
```

Process:
1. Validate invitation token
2. Check token expiration (7 days)
3. Verify username availability
4. Hash password
5. Activate user (`is_active = 1`)
6. Clear `invitation_token`
7. Auto-login (session set) and redirect to admin dashboard

### Invitation Expiration

Invitations expire after **7 days**:

```typescript
const invitationAge = Date.now() - invitedUser.invited_at
const maxAge = 7 * 24 * 60 * 60 * 1000 // 7 days

if (invitationAge > maxAge) {
  return c.json({ error: 'Invitation has expired' }, 400)
}
```

## Password Reset Flow

### Request Password Reset

**POST** `/auth/request-password-reset`

```typescript
// Form data
{
  "email": "user@example.com"
}

// Response (always success to prevent email enumeration)
{
  "success": true,
  "message": "If an account with this email exists, a password reset link has been sent.",
  "reset_link": "http://localhost:8787/auth/reset-password?token=..." // Dev only
}
```

Process:
1. Normalize email to lowercase
2. Look up user (returns success even if not found)
3. Generate unique `password_reset_token`
4. Set expiration: 1 hour
5. Update user record
6. Send reset email (or return link in dev)
7. Log activity

### Reset Password Form

**GET** `/auth/reset-password?token=<reset-token>`

Displays password reset form if token is valid and not expired.

### Reset Password

**POST** `/auth/reset-password`

```typescript
// Form data
{
  "token": "reset-token",
  "password": "newPassword123",
  "confirm_password": "newPassword123"
}
```

Process:
1. Validate reset token
2. Check expiration (1 hour)
3. Verify passwords match
4. Hash new password
5. Store old password in `password_history`
6. Update user with new password
7. Clear reset token
8. Log activity
9. Redirect to login

### Reset Token Expiration

Reset tokens expire after **1 hour**:

```typescript
const resetExpires = Date.now() + (60 * 60 * 1000) // 1 hour

if (Date.now() > user.password_reset_expires) {
  return c.json({ error: 'Reset token has expired' }, 400)
}
```

## Implementing Authentication in Routes

### Basic Authentication

```typescript
import { Hono } from 'hono'
import { requireAuth } from '../middleware/auth'

const app = new Hono()

// Public route
app.get('/public', (c) => {
  return c.json({ message: 'Public access' })
})

// Protected route
app.get('/protected', requireAuth(), (c) => {
  const user = c.get('user')
  return c.json({
    message: 'Authenticated access',
    userId: user.userId,
    email: user.email,
    role: user.role
  })
})
```

### Role-Based Routes

```typescript
import { requireAuth, requireRole } from '../middleware/auth'

// Admin only
app.delete('/admin/users/:id',
  requireAuth(),
  requireRole('admin'),
  async (c) => {
    const userId = c.req.param('id')
    // Delete user logic
    return c.json({ message: 'User deleted' })
  }
)

// Editor or Admin
app.post('/content',
  requireAuth(),
  requireRole(['admin', 'editor']),
  async (c) => {
    const data = await c.req.json()
    // Create content logic
    return c.json({ message: 'Content created' })
  }
)
```

### Permission-Based Routes

```typescript
import { requireAuth } from '../middleware/auth'
import { requirePermission, requireAnyPermission } from '../middleware/permissions'

// Single permission required
app.post('/content/:id/publish',
  requireAuth(),
  requirePermission('content.publish'),
  async (c) => {
    const contentId = c.req.param('id')
    // Publish content logic
    return c.json({ message: 'Content published' })
  }
)

// Any permission required
app.put('/content/:id',
  requireAuth(),
  requireAnyPermission(['content.update', 'content.publish']),
  async (c) => {
    const contentId = c.req.param('id')
    const data = await c.req.json()
    // Update content logic
    return c.json({ message: 'Content updated' })
  }
)

// Multiple permissions required
app.delete('/content/:id',
  requireAuth(),
  PermissionManager.requirePermissions(['content.delete', 'content.update']),
  async (c) => {
    const contentId = c.req.param('id')
    // Delete content logic
    return c.json({ message: 'Content deleted' })
  }
)
```

### Optional Authentication

```typescript
import { optionalAuth } from '../middleware/auth'

// Route accessible to both authenticated and anonymous users
app.get('/content/:id',
  optionalAuth(),
  async (c) => {
    const user = c.get('user') // May be undefined
    const contentId = c.req.param('id')

    if (user) {
      // Return full content for authenticated users
      return c.json({ content: fullContent })
    } else {
      // Return limited content for anonymous users
      return c.json({ content: publicContent })
    }
  }
)
```

### Custom Authorization Logic

```typescript
app.put('/content/:id',
  requireAuth(),
  async (c) => {
    const user = c.get('user')
    const contentId = c.req.param('id')
    const db = c.env.DB

    // Fetch content
    const content = await db.prepare('SELECT * FROM content WHERE id = ?')
      .bind(contentId)
      .first()

    // Custom authorization: user must be admin, editor, or content owner
    const canEdit =
      user.role === 'admin' ||
      user.role === 'editor' ||
      content.author_id === user.userId

    if (!canEdit) {
      return c.json({ error: 'You do not have permission to edit this content' }, 403)
    }

    // Update content logic
    return c.json({ message: 'Content updated' })
  }
)
```

### Activity Logging

```typescript
import { logActivity } from '../middleware/permissions'

app.delete('/content/:id',
  requireAuth(),
  requirePermission('content.delete'),
  async (c) => {
    const user = c.get('user')
    const contentId = c.req.param('id')
    const db = c.env.DB

    // Delete content
    await db.prepare('DELETE FROM content WHERE id = ?')
      .bind(contentId)
      .run()

    // Log the deletion
    await logActivity(
      db,
      user.userId,
      'content.deleted',
      'content',
      contentId,
      { title: 'Sample Content' },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.json({ message: 'Content deleted' })
  }
)
```

### Full Example: Content API

```typescript
import { Hono } from 'hono'
import { requireAuth, requireRole } from '../middleware/auth'
import { requirePermission } from '../middleware/permissions'
import { logActivity } from '../middleware/permissions'

const contentRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// List content (public)
contentRoutes.get('/', async (c) => {
  const db = c.env.DB
  const { results } = await db.prepare('SELECT * FROM content WHERE status = ?')
    .bind('published')
    .all()
  return c.json({ content: results })
})

// Get single content (public)
contentRoutes.get('/:id', async (c) => {
  const db = c.env.DB
  const content = await db.prepare('SELECT * FROM content WHERE id = ?')
    .bind(c.req.param('id'))
    .first()

  if (!content) {
    return c.json({ error: 'Content not found' }, 404)
  }

  return c.json({ content })
})

// Create content (requires content.create permission)
contentRoutes.post('/',
  requireAuth(),
  requirePermission('content.create'),
  async (c) => {
    const user = c.get('user')
    const db = c.env.DB
    const data = await c.req.json()

    const contentId = crypto.randomUUID()
    const now = Date.now()

    await db.prepare(`
      INSERT INTO content (id, title, body, author_id, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      contentId,
      data.title,
      data.body,
      user.userId,
      'draft',
      now,
      now
    ).run()

    // Log activity
    await logActivity(
      db, user.userId, 'content.created', 'content', contentId,
      { title: data.title },
      c.req.header('x-forwarded-for'),
      c.req.header('user-agent')
    )

    return c.json({ id: contentId, message: 'Content created' }, 201)
  }
)

// Update content (requires content.update permission OR ownership)
contentRoutes.put('/:id',
  requireAuth(),
  async (c) => {
    const user = c.get('user')
    const db = c.env.DB
    const contentId = c.req.param('id')
    const data = await c.req.json()

    // Check ownership or permission
    const content = await db.prepare('SELECT * FROM content WHERE id = ?')
      .bind(contentId)
      .first() as any

    if (!content) {
      return c.json({ error: 'Content not found' }, 404)
    }

    const canEdit =
      user.role === 'admin' ||
      user.role === 'editor' ||
      content.author_id === user.userId

    if (!canEdit) {
      return c.json({ error: 'Permission denied' }, 403)
    }

    await db.prepare('UPDATE content SET title = ?, body = ?, updated_at = ? WHERE id = ?')
      .bind(data.title, data.body, Date.now(), contentId)
      .run()

    await logActivity(
      db, user.userId, 'content.updated', 'content', contentId,
      { title: data.title },
      c.req.header('x-forwarded-for'),
      c.req.header('user-agent')
    )

    return c.json({ message: 'Content updated' })
  }
)

// Delete content (admin or editor only)
contentRoutes.delete('/:id',
  requireAuth(),
  requireRole(['admin', 'editor']),
  requirePermission('content.delete'),
  async (c) => {
    const user = c.get('user')
    const db = c.env.DB
    const contentId = c.req.param('id')

    await db.prepare('DELETE FROM content WHERE id = ?')
      .bind(contentId)
      .run()

    await logActivity(
      db, user.userId, 'content.deleted', 'content', contentId,
      {},
      c.req.header('x-forwarded-for'),
      c.req.header('user-agent')
    )

    return c.json({ message: 'Content deleted' })
  }
)

export { contentRoutes }
```

## Security Best Practices

### 1. Production Better Auth Secret

**Never use a weak or default secret in production.**

```bash
# Generate a secure random secret (min 32 characters)
openssl rand -base64 32

# Set as Wrangler secret
openssl rand -base64 32 | wrangler secret put BETTER_AUTH_SECRET --env production
```

Also set `BETTER_AUTH_URL` to your app’s public URL (e.g. `https://your-app.com`). See [deployment.md](deployment.md).

### 2. HTTPS Only

Use HTTPS in production so the session cookie is sent only over secure connections. Better Auth can be configured with `advanced.useSecureCookies` for production.

### 3. Rate Limiting

Implement rate limiting for auth endpoints:

```typescript
// Example with Cloudflare rate limiting
const RATE_LIMITS = {
  login: 5,        // 5 attempts
  register: 3,     // 3 attempts
  resetPassword: 2 // 2 attempts
}
```

### 4. Password Requirements

Enforce strong passwords:

```typescript
const strongPasswordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .regex(/[A-Z]/, 'Password must contain uppercase letter')
  .regex(/[a-z]/, 'Password must contain lowercase letter')
  .regex(/[0-9]/, 'Password must contain number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain special character')
```

### 5. Email Verification

Implement email verification:

```typescript
// On registration
const emailVerificationToken = crypto.randomUUID()

await db.prepare(`
  UPDATE users SET
    email_verified = 0,
    email_verification_token = ?
  WHERE id = ?
`).bind(emailVerificationToken, userId).run()

// Send verification email with token
```

### 6. Two-Factor Authentication (2FA)

Enable 2FA for sensitive accounts:

```sql
ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN two_factor_secret TEXT;
```

### 8. Audit Logging

Always log security-sensitive actions:

```typescript
await logActivity(
  db,
  user.userId,
  'user.login',
  'users',
  user.userId,
  { ip: ipAddress, userAgent },
  ipAddress,
  userAgent
)
```

### 8. Secure Headers

Set security headers:

```typescript
// In your main app
app.use('*', async (c, next) => {
  await next()
  c.header('X-Frame-Options', 'DENY')
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
})
```

### 10. Token Rotation

Implement token rotation for long-lived sessions:

```typescript
// Refresh token every 6 hours
const shouldRotate = (payload.iat + (6 * 60 * 60)) < Date.now() / 1000

if (shouldRotate) {
  const newToken = await AuthManager.generateToken(
    payload.userId,
    payload.email,
    payload.role
  )
  // Return new token in response header
  c.header('X-New-Token', newToken)
}
```

### 11. CORS Configuration

Configure CORS properly:

```typescript
import { cors } from 'hono/cors'

app.use('*', cors({
  origin: ['https://yourdomain.com'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}))
```

### 10. Input Validation

Always validate and sanitize input:

```typescript
import { z } from 'zod'
import { zValidator } from '@hono/zod-validator'

const updateUserSchema = z.object({
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
  email: z.string().email()
})

app.put('/user/:id',
  requireAuth(),
  zValidator('json', updateUserSchema),
  async (c) => {
    const data = c.req.valid('json') // Validated data
    // Update logic
  }
)
```

## Troubleshooting

### Session / Authentication Required

**Problem:** `Authentication required` or `Invalid or expired token`

**Solutions:**
1. Ensure the session cookie (`better-auth.session_token`) is sent with the request (browser: `credentials: 'include'`; same origin so cookies are sent by default).
2. Check that `BETTER_AUTH_SECRET` and `BETTER_AUTH_URL` are set correctly (same secret and URL used when the session was created).
3. If the session has expired, the user must sign in again via `/auth/sign-in/email` or your configured method (e.g. magic link, OTP).

### Permission Denied Errors

**Problem:** `Permission denied: content.update`

**Solutions:**
1. Check user role in database
2. Verify role_permissions mapping
3. Clear permission cache
4. Check team membership (for team permissions)

```sql
-- Check user role
SELECT role FROM users WHERE id = 'user-id';

-- Check role permissions
SELECT p.name
FROM role_permissions rp
JOIN permissions p ON rp.permission_id = p.id
WHERE rp.role = 'editor';

-- Check user's team permissions
SELECT tm.role, tm.permissions
FROM team_memberships tm
WHERE tm.user_id = 'user-id';
```

```typescript
// Clear permission cache
PermissionManager.clearUserCache(userId)
PermissionManager.clearAllCache()
```

### Cookie Not Set

**Problem:** Session cookie not being sent or received

**Solutions:**
1. Ensure `BETTER_AUTH_URL` matches the URL the user is visiting (same origin so cookies are sent).
2. In development (HTTP), Better Auth may set cookies with `secure: false`; in production use HTTPS and `useSecureCookies` if needed.
3. Check `sameSite` and domain; cross-site requests require correct CORS and cookie settings.
4. Check browser DevTools → Application → Cookies for the session cookie.

### Password Verification Failed

**Problem:** Valid password rejected at sign-in

**Solutions:**
1. Sign-in is handled by Better Auth; ensure the request is sent to `POST /auth/sign-in/email` with correct `email` and `password`.
2. Check that the user exists in the `users` table and that Better Auth’s password verification (and any custom adapter) is correct.
3. For legacy flows that use `AuthManager.verifyPassword` (e.g. seed-admin), ensure the stored hash was produced by the same method.

### Database Connection Issues

**Problem:** `User not found` or database errors

**Solutions:**
1. Check D1 database binding in wrangler.toml
2. Verify migrations have run
3. Check table structure

```bash
# Check D1 binding
wrangler d1 execute DB --command "SELECT * FROM users LIMIT 1"

# Check table exists
wrangler d1 execute DB --command "SELECT name FROM sqlite_master WHERE type='table'"

# Run migrations
wrangler d1 execute DB --file=./migrations/001_initial_schema.sql
```

### Invitation/Reset Token Issues

**Problem:** Token expired or invalid

**Solutions:**
1. Check token expiration timestamps
2. Verify token matches in database
3. Ensure token hasn't been used

```sql
-- Check invitation token
SELECT id, email, invitation_token, invited_at, is_active
FROM users
WHERE invitation_token = 'token-value';

-- Check password reset token
SELECT id, email, password_reset_token, password_reset_expires
FROM users
WHERE password_reset_token = 'token-value';
```

### Activity Logging Failures

**Problem:** Activity logs not being created

**Solutions:**
1. Check activity_logs table exists
2. Verify logActivity is awaited
3. Check for silent failures

```typescript
// Add error handling
try {
  await logActivity(db, userId, action, resourceType, resourceId, details, ip, ua)
} catch (error) {
  console.error('Failed to log activity:', error)
  // Continue - don't break main operation
}
```

## Related Documentation

- [User Management](user-management.md) - Managing users and roles
- [API Reference](api-reference.md) - Complete API documentation
- [Deployment](deployment.md) - Production deployment guide
- [Permissions](permissions.md) - Detailed permission system documentation
