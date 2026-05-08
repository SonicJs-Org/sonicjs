# Authentication & Security

SonicJS AI implements a comprehensive authentication and authorization system using JWT tokens, KV-based caching, and role-based access control (RBAC). This guide covers all aspects of user authentication, security, and permissions.

## Table of Contents

- [Overview](#overview)
- [Authentication Flow](#authentication-flow)
- [JWT Implementation](#jwt-implementation)
- [Token Caching with KV](#token-caching-with-kv)
- [Password Security](#password-security)
- [Role-Based Access Control](#role-based-access-control)
- [Permission System](#permission-system)
- [Auth Routes & Endpoints](#auth-routes--endpoints)
- [Session Management](#session-management)
- [User Invitation System](#user-invitation-system)
- [Password Reset Flow](#password-reset-flow)
- [Implementing Authentication in Routes](#implementing-authentication-in-routes)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

SonicJS AI uses a modern authentication architecture built on:

- **JWT (JSON Web Tokens)** for stateless authentication
- **Cloudflare KV** for token verification caching (5-minute TTL)
- **SHA-256 password hashing** with salt
- **RBAC (Role-Based Access Control)** for fine-grained permissions
- **HTTP-only cookies** and Bearer token support
- **Session tracking** with activity logging
- **Invitation-based user onboarding**

## Authentication Flow

### 1. User Registration

**Endpoint:** `POST /auth/register`

```typescript
// Request
{
  "email": "user@example.com",
  "password": "securePassword123",
  "username": "johndoe",
  "firstName": "John",
  "lastName": "Doe"
}

// Response
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "johndoe",
    "firstName": "John",
    "lastName": "Doe",
    "role": "viewer"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Process:**
1. Email normalized to lowercase
2. Check for duplicate email/username
3. Password hashed with SHA-256 + salt
4. User created with default role: `viewer`
5. JWT token generated (TTL from `JWT_EXPIRES_IN`, default 30 days)
6. HTTP-only cookie set
7. Token returned in response

### 2. User Login

**Endpoint:** `POST /auth/login`

```typescript
// Request
{
  "email": "user@example.com",
  "password": "securePassword123"
}

// Response
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "johndoe",
    "firstName": "John",
    "lastName": "Doe",
    "role": "viewer"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Process:**
1. Email normalized to lowercase
2. User lookup with KV caching
3. Password verification with SHA-256
4. JWT token generation
5. HTTP-only cookie set (TTL from `JWT_EXPIRES_IN`, default 30 days)
6. `last_login_at` timestamp updated
7. User cache invalidated to ensure fresh data

### 3. Token Refresh

**Endpoint:** `POST /auth/refresh`

```typescript
// Headers (or cookie)
Authorization: Bearer <current_or_recently_expired_token>

// Response
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 2592000
}
```

Accepts a JWT that is either still valid or has expired within the grace
window (`JWT_REFRESH_GRACE_SECONDS`, default 7 days). Re-validates the user
in the database and issues a freshly-signed token — no password/OTP required.
This supports sliding-session auth so a long-lived session cookie can keep
a user logged in across JWT rotations.

## JWT Implementation

### Token Structure

SonicJS AI uses JWTs with the following payload:

```typescript
interface JWTPayload {
  userId: string;      // User's unique ID
  email: string;       // User's email (normalized)
  role: string;        // User's role (admin, editor, viewer)
  exp: number;         // Expiration timestamp (Unix)
  iat: number;         // Issued at timestamp (Unix)
}
```

### Token Generation

```typescript
import { AuthManager, getJwtExpirySeconds } from '../middleware/auth'

// Generate a token with the environment-configured TTL
const ttl = getJwtExpirySeconds(env)
const token = await AuthManager.generateToken(
  userId,
  email,
  role,
  env.JWT_SECRET,
  ttl
)
```

### Configuring JWT Expiration

JWT TTL is controlled by the `JWT_EXPIRES_IN` environment variable. It accepts
a plain number of seconds or a duration string:

| Example value | Meaning      |
| ------------- | ------------ |
| `2592000`     | 30 days (default) |
| `30d`         | 30 days      |
| `12h`         | 12 hours     |
| `3600s`       | 1 hour       |

If `JWT_EXPIRES_IN` is not set, SonicJS defaults to **30 days**.

The refresh endpoint also honors `JWT_REFRESH_GRACE_SECONDS` (default 7 days),
which controls how long after expiration a token can still be used to obtain a
fresh one via `POST /auth/refresh`.

### Token Verification

The `JWT_SECRET` lives on the Cloudflare Workers binding (`c.env.JWT_SECRET`), so
you must thread the secret through when verifying tokens. The easiest way from a
Hono handler is `AuthManager.verifyAuthRequest(c)`, which extracts the token
from the `Authorization` header (or `auth_token` cookie) and pulls the secret
from `c.env` for you:

```typescript
// Inside a custom Hono route handler
const payload = await AuthManager.verifyAuthRequest(c)

if (!payload) {
  return c.json({ error: 'Invalid or expired token' }, 401)
}

console.log(payload.userId, payload.email, payload.role)
```

If you already have the raw token, call `verifyToken` directly and pass the
secret yourself:

```typescript
const payload = await AuthManager.verifyToken(token, c.env.JWT_SECRET)
```

> **Heads up:** `AuthManager.verifyToken(token)` (no secret argument) falls
> back to a development-only placeholder secret. In production this will
> silently fail to verify any real token. Always pass `c.env.JWT_SECRET`, or
> use `verifyAuthRequest(c)` / the `requireAuth()` middleware.

### Token Configuration

```typescript
// Default configuration in src/middleware/auth.ts
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production'

// Token expiration: 24 hours
const TOKEN_EXPIRY = 60 * 60 * 24
```

**Production Configuration:**

```bash
# Set JWT_SECRET in wrangler.toml or Cloudflare dashboard
[vars]
JWT_SECRET = "your-256-bit-production-secret"
```

## Token Caching with KV

SonicJS AI implements intelligent token verification caching using Cloudflare KV to reduce JWT verification overhead.

### How It Works

```typescript
// In requireAuth() middleware
export const requireAuth = () => {
  return async (c: Context, next: Next) => {
    // Get token from header or cookie
    let token = c.req.header('Authorization')?.replace('Bearer ', '')
    if (!token) {
      token = getCookie(c, 'auth_token')
    }

    // Try to get cached token verification from KV
    const kv = c.env?.KV
    let payload: JWTPayload | null = null

    if (kv) {
      const cacheKey = `auth:${token.substring(0, 20)}`
      const cached = await kv.get(cacheKey, 'json')
      if (cached) {
        payload = cached as JWTPayload
      }
    }

    // If not cached, verify token (passing the JWT_SECRET binding)
    if (!payload) {
      payload = await AuthManager.verifyToken(token, c.env?.JWT_SECRET)

      // Cache the verified payload for 5 minutes
      if (payload && kv) {
        const cacheKey = `auth:${token.substring(0, 20)}`
        await kv.put(cacheKey, JSON.stringify(payload), {
          expirationTtl: 300 // 5 minutes
        })
      }
    }

    if (!payload) {
      return c.json({ error: 'Invalid or expired token' }, 401)
    }

    // Add user info to context
    c.set('user', payload)
    await next()
  }
}
```

### Cache Strategy

- **Cache Key:** `auth:{first-20-chars-of-token}`
- **TTL:** 5 minutes (300 seconds)
- **Cache Miss:** Verifies JWT and caches result
- **Cache Hit:** Returns cached payload (faster)
- **Invalidation:** Automatic after 5 minutes

### Performance Benefits

- Reduces JWT signature verification overhead
- Faster response times for authenticated requests
- Scales better under high load
- Cloudflare KV provides global edge caching

## Password Security

### Hashing Algorithm

SonicJS AI uses SHA-256 with a salt for password hashing:

```typescript
export class AuthManager {
  static async hashPassword(password: string): Promise<string> {
    // In Cloudflare Workers, we use Web Crypto API
    const encoder = new TextEncoder()
    const data = encoder.encode(password + 'salt-change-in-production')
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  }

  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    const passwordHash = await this.hashPassword(password)
    return passwordHash === hash
  }
}
```

### Important Notes

1. **Change the salt in production** - Update `'salt-change-in-production'` to a unique, secure value
2. **SHA-256 vs bcrypt** - SHA-256 is used because bcrypt is not natively available in Cloudflare Workers
3. **Salt storage** - The salt is currently hardcoded; consider using environment variables
4. **Password requirements** - Minimum 8 characters (enforced in validation schemas)

### Password Validation

```typescript
// Registration schema
const registerSchema = z.object({
  email: z.string().email('Valid email is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  username: z.string().min(3, 'Username must be at least 3 characters'),
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required')
})
```

### Password History

Passwords are tracked in the `password_history` table for security:

```sql
CREATE TABLE password_history (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
```

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
    const user = c.get('user') as JWTPayload

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

### Login Page

**GET** `/auth/login`

Renders the login HTML form. Supports query parameters:
- `?error=<message>` - Display error message
- `?message=<message>` - Display info message

### Registration Page

**GET** `/auth/register`

Renders the registration HTML form.

### Login (API)

**POST** `/auth/login`

```typescript
// Request body
{
  "email": "user@example.com",
  "password": "password123"
}

// Success response (200)
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "username",
    "firstName": "John",
    "lastName": "Doe",
    "role": "viewer"
  },
  "token": "jwt-token"
}

// Error response (401)
{
  "error": "Invalid email or password"
}
```

### Login (Form)

**POST** `/auth/login/form`

Handles HTML form submissions. Returns HTMX-compatible HTML response.

### Register (API)

**POST** `/auth/register`

```typescript
// Request body
{
  "email": "user@example.com",
  "password": "password123",
  "username": "johndoe",
  "firstName": "John",
  "lastName": "Doe"
}

// Success response (201)
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe",
    "firstName": "John",
    "lastName": "Doe",
    "role": "viewer"
  },
  "token": "jwt-token"
}

// Error response (400)
{
  "error": "User with this email or username already exists"
}
```

### Register (Form)

**POST** `/auth/register/form`

Handles HTML form submissions. First user registered gets `admin` role.

### Logout

**GET** `/auth/logout` or **POST** `/auth/logout`

Clears the `auth_token` cookie and redirects to login page.

```typescript
// GET response
// Redirects to /auth/login?message=You have been logged out successfully

// POST response (200)
{
  "message": "Logged out successfully"
}
```

### Get Current User

**GET** `/auth/me`

Requires authentication.

```typescript
// Headers
Authorization: Bearer <token>

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

### Refresh Token

**POST** `/auth/refresh`

Requires authentication. Generates a new token with extended expiration.

```typescript
// Headers
Authorization: Bearer <current-token>

// Response (200)
{
  "token": "new-jwt-token"
}
```

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

### HTTP-Only Cookies

SonicJS AI uses secure, HTTP-only cookies for session management:

```typescript
setCookie(c, 'auth_token', token, {
  httpOnly: true,      // Cannot be accessed via JavaScript
  secure: true,        // HTTPS only in production
  sameSite: 'Strict',  // CSRF protection
  maxAge: 60 * 60 * 24 // 24 hours
})
```

### Session Tracking

Sessions are tracked in the `user_sessions` table:

```sql
CREATE TABLE user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
```

### Token Extraction

The `requireAuth()` middleware supports multiple token sources:

```typescript
// 1. Authorization header (Bearer token)
Authorization: Bearer <token>

// 2. HTTP-only cookie
Cookie: auth_token=<token>

// Priority: Header > Cookie
```

### Session Expiration

- **Token expiration:** 24 hours from issue time
- **Cookie expiration:** 24 hours (maxAge)
- **Cache expiration:** 5 minutes (KV TTL)

When a token expires:
1. JWT verification fails
2. User redirected to login (HTML requests)
3. 401 error returned (API requests)

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
7. Auto-login with JWT token
8. Redirect to admin dashboard

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

### Custom Routes Alongside SonicJS

When you mount your own Hono routes next to a SonicJS app, you can authenticate
requests with the same JWT that SonicJS issues. Three options, ordered by
preference:

**1. Use `requireAuth()` middleware** (recommended — matches what SonicJS uses
internally, including the KV verification cache):

```typescript
import { Hono } from 'hono'
import { requireAuth, createSonicJSApp } from '@sonicjs-cms/core'

const app = new Hono()
const adminRoutes = new Hono()

adminRoutes.use('*', requireAuth())
adminRoutes.get('/stats', (c) => {
  const user = c.get('user') // { userId, email, role, ... }
  return c.json({ user })
})

app.route('/api/admin', adminRoutes)
app.route('/', createSonicJSApp(config))
```

**2. Use `AuthManager.verifyAuthRequest(c)`** when you need custom error
handling but still want the helper to extract the token + secret for you:

```typescript
import { AuthManager } from '@sonicjs-cms/core'

adminRoutes.use('*', async (c, next) => {
  const payload = await AuthManager.verifyAuthRequest(c)
  if (!payload) return c.json({ error: 'Invalid token' }, 401)
  if (payload.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
  c.set('user', payload)
  await next()
})
```

**3. Call `AuthManager.verifyToken(token, secret)` directly** when you've
already extracted the token yourself. Always pass `c.env.JWT_SECRET`:

```typescript
const token = c.req.header('Authorization')?.replace('Bearer ', '')
const payload = await AuthManager.verifyToken(token, c.env.JWT_SECRET)
```

> **Don't call `AuthManager.verifyToken(token)` without a secret.** It falls
> back to a development-only placeholder, so any token signed with your real
> `JWT_SECRET` will silently fail verification.

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

### 1. Production JWT Secret

**Never use default JWT secret in production.**

```bash
# Generate a secure random secret
openssl rand -base64 32

# Add to wrangler.toml
[vars]
JWT_SECRET = "your-secure-random-256-bit-secret"
```

### 2. Change Password Salt

Update the salt in `src/middleware/auth.ts`:

```typescript
// BEFORE (insecure)
const data = encoder.encode(password + 'salt-change-in-production')

// AFTER (secure)
const SALT = c.env.PASSWORD_SALT || 'your-unique-production-salt'
const data = encoder.encode(password + SALT)
```

Better yet, use environment-specific salts:

```bash
# wrangler.toml
[vars]
PASSWORD_SALT = "your-unique-production-salt-value"
```

### 3. HTTPS Only

Always use HTTPS in production:

```typescript
setCookie(c, 'auth_token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production', // true in production
  sameSite: 'Strict',
  maxAge: 60 * 60 * 24
})
```

### 4. Rate Limiting

Implement rate limiting for auth endpoints:

```typescript
// Example with Cloudflare rate limiting
const RATE_LIMITS = {
  login: 5,        // 5 attempts
  register: 3,     // 3 attempts
  resetPassword: 2 // 2 attempts
}
```

### 5. Password Requirements

Enforce strong passwords:

```typescript
const strongPasswordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .regex(/[A-Z]/, 'Password must contain uppercase letter')
  .regex(/[a-z]/, 'Password must contain lowercase letter')
  .regex(/[0-9]/, 'Password must contain number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain special character')
```

### 6. Email Verification

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

### 7. Two-Factor Authentication (2FA)

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

### 9. Secure Headers

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

### 12. Input Validation

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

### Token Validation Errors

**Problem:** `Invalid or expired token`

**Solutions:**
1. Check JWT_SECRET matches between token generation and verification
2. Verify token hasn't expired (check `exp` claim)
3. Ensure token is properly formatted (Bearer <token>)
4. Check KV cache for stale data

```typescript
// Debug token
const parts = token.split('.')
const payload = JSON.parse(atob(parts[1]))
console.log('Token payload:', payload)
console.log('Expired?', payload.exp < Date.now() / 1000)
```

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

**Problem:** Auth cookie not being sent/received

**Solutions:**
1. Verify `secure` flag matches protocol (HTTP vs HTTPS)
2. Check `sameSite` setting
3. Ensure domain matches
4. Check browser console for cookie errors

```typescript
// Development (HTTP)
setCookie(c, 'auth_token', token, {
  httpOnly: true,
  secure: false,  // false for localhost HTTP
  sameSite: 'Lax', // Lax for development
  maxAge: 60 * 60 * 24
})

// Production (HTTPS)
setCookie(c, 'auth_token', token, {
  httpOnly: true,
  secure: true,   // true for HTTPS
  sameSite: 'Strict',
  maxAge: 60 * 60 * 24
})
```

### KV Cache Issues

**Problem:** Stale cached data

**Solutions:**
1. Wait for cache expiration (5 minutes)
2. Manually clear KV keys
3. Check KV namespace binding

```typescript
// Clear cached token verification
const cacheKey = `auth:${token.substring(0, 20)}`
await kv.delete(cacheKey)

// Clear user cache
await cache.delete(`user:${userId}`)
await cache.delete(`user:email:${email}`)
```

### Password Verification Failed

**Problem:** Valid password rejected

**Solutions:**
1. Check salt matches between hash and verify
2. Verify password_hash in database
3. Check for encoding issues
4. Ensure consistent salt usage

```typescript
// Test password hashing
const password = 'test123'
const hash1 = await AuthManager.hashPassword(password)
const hash2 = await AuthManager.hashPassword(password)
console.log('Hashes match?', hash1 === hash2) // Should be true

const valid = await AuthManager.verifyPassword(password, hash1)
console.log('Verification works?', valid) // Should be true
```

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
