# MCP Plugin Plan — Issue #784

**Status**: Draft  
**Branch**: `lane711/analyze-issue-784`  
**Issue**: https://github.com/SonicJs-Org/sonicjs/issues/784

---

## 1. Goal

MCP plugin exposes SonicJS content as callable tools. AI agents read/manage content via standard MCP clients (Claude Code, Cursor, VS Code, etc.).

Plugin is **opt-in** — users install via `plugins.register`. Not bundled in default bootstrap.

---

## 2. MCP Protocol Primer

MCP = JSON-RPC 2.0 over HTTP + SSE. Spec defines three primitives:

- **Tools** — callable functions (CRUD ops on content)
- **Resources** — readable URIs (collection schemas, document lists)
- **Prompts** — structured message templates (out of scope v1)

Transport: **Streamable HTTP** (POST to `/api/mcp`, SSE stream). Modern MCP transport — compatible with Cloudflare Workers via `ReadableStream`.

---

## 3. Architecture

### 3.1 Plugin Location

```
packages/core/src/plugins/core-plugins/mcp-plugin/
  index.ts                    — definePlugin entry point
  routes/
    mcp.ts                    — main Hono router (mounted at /api/mcp)
    transport.ts              — Streamable HTTP + SSE handler
  tools/
    index.ts                  — builds tool registry from CollectionRegistry
    documents.ts              — find/get/create/update/delete tool factories
    collections.ts            — list_collections tool
  resources/
    index.ts                  — resource registry
    schemas.ts                — collection schema resources
  auth/
    middleware.ts             — Bearer token → API key validation
    api-keys.ts               — CRUD for mcp_api_key document type
  services/
    tool-registry.ts          — builds + caches MCP tool list at boot
    schema-generator.ts       — Zod → JSON Schema for tool input/output
  admin/
    routes.ts                 — /admin/mcp/* (key management UI)
    templates.ts              — HTMX templates for key list + create form
  configSchema.ts             — Zod schema for plugin config
```

### 3.2 Document Types Introduced

```
mcp_api_key  — stores API keys (hashed) in documents table
  fields:
    name: string          — human label
    key_hash: string      — SHA-256 of raw key (raw never stored)
    key_prefix: string    — first 8 chars for UI display
    scopes: string[]      — ['read', 'write'] or per-type overrides
    allowed_types: string[] | null  — null = all types
    owner_user_id: string
    expires_at: number | null
    last_used_at: number | null
```

No new DB tables. Keys in `documents` with `type_id = 'mcp_api_key'`, `tenant_id = 'default'`. R12 compliant.

---

## 4. MCP Endpoint

**Mount**: `register(app) => app.route('/api/mcp', mcpRouter)`

```
POST /api/mcp          — JSON-RPC request (tools/call, tools/list, resources/list, resources/read)
GET  /api/mcp          — SSE stream (server-sent notifications, keep-alive)
```

All requests require `Authorization: Bearer <api-key>`.

### 4.1 JSON-RPC Methods Supported (v1)

| Method | Description |
|---|---|
| `initialize` | Handshake — server info + capabilities |
| `tools/list` | All tools visible to API key |
| `tools/call` | Execute tool |
| `resources/list` | Available resources |
| `resources/read` | Read resource (e.g. collection schema) |

---

## 5. Tools

### 5.1 Auto-Generated Per Document Type

Per active document type in plugin config, generate:

| Tool Name | Maps To |
|---|---|
| `list_{typeId}` | `DocumentRepository.list({ typeId, status })` |
| `get_{typeId}` | Raw SQL lookup by id/slug |
| `create_{typeId}` | `DocumentsService.create()` + optional auto-publish |
| `update_{typeId}` | `DocumentsService.saveDraft()` |
| `publish_{typeId}` | `DocumentsService.publish()` |
| `delete_{typeId}` | `DocumentsService` soft-delete (sets `deleted_at`) |

### 5.2 Static Tools (Always Present)

| Tool | Description |
|---|---|
| `list_collections` | All exposed type IDs + display names |
| `search_content` | Cross-type full-text search via `q_title` / `q_slug` |

### 5.3 Tool Input Schema Generation

Each tool `inputSchema` = JSON Schema from collection Zod schema via `zod-to-json-schema`. Virtual/system fields (`id`, `created_at`, `updated_at`, `version_number`) stripped from write schemas.

---

## 6. Resources

| URI Pattern | Content |
|---|---|
| `sonicjs://collections` | JSON list of all exposed types + their schemas |
| `sonicjs://collections/{typeId}/schema` | JSON Schema for one type |
| `sonicjs://collections/{typeId}/documents` | Paginated list (published, first 50) |

---

## 7. Auth

### 7.1 API Key Flow

1. Admin creates key in `/admin/mcp/keys` — selects name, scopes, allowed types, expiry
2. System generates `crypto.randomUUID()` raw key, shows it **once**
3. Store `SHA-256(rawKey)` as `key_hash` in documents table
4. On each request: hash bearer token, lookup matching `mcp_api_key` doc, check scopes + expiry
5. On match: update `last_used_at` (async, non-blocking)

### 7.2 Scope Enforcement

Scopes on key: `['read']`, `['write']`, or `['read', 'write']`

Write tools (`create_*`, `update_*`, `publish_*`, `delete_*`) require `write` scope.  
Read tools (`list_*`, `get_*`, `search_*`) require `read` scope.

Per-type: if `allowed_types` set, only those type IDs accessible.

### 7.3 ACL Passthrough

After API key auth, reads/writes still go through `DocumentRepository.isAllowed()` + `DocumentsService` — inheriting existing ACL. API key auth does **not** bypass document-level permissions.

Principal set for MCP requests:
```ts
const principalSet = [
  { type: 'user', id: apiKey.owner_user_id },
  { type: 'role', id: 'mcp' },  // new role, base grants apply
]
```

---

## 8. Plugin Configuration

```ts
import { mcpPlugin } from '@sonicjs/core/plugins/mcp'

export default createSonicJSApp({
  plugins: {
    register: [
      mcpPlugin({
        // Expose only these types (default: all active types)
        expose: ['posts', 'pages', 'products'],

        // Per-type write control (default: read+write for all exposed)
        types: {
          posts:    { read: true, write: true },
          pages:    { read: true, write: false },  // read-only
          products: { read: true, write: true },
        },

        // Strip these fields from all tool responses
        redactFields: ['internal_notes', 'cost_price'],

        // Max documents returned by list_* tools (default: 50)
        listLimit: 50,

        // Allow unauthenticated read access (default: false — insecure, dev only)
        allowPublicRead: false,
      })
    ]
  }
})
```

Config in plugin `configSchema` (Zod), persisted in plugin document `settings` field (existing plugin storage pattern).

---

## 9. Admin UI

Routes mounted at `/admin/mcp` via `register(app)`.

### Pages

| Route | Description |
|---|---|
| `GET /admin/mcp` | Dashboard — active keys, request count, enabled types |
| `GET /admin/mcp/keys` | Key list with prefix + scopes |
| `POST /admin/mcp/keys` | Create new key — shows raw key once |
| `DELETE /admin/mcp/keys/:id` | Revoke key |
| `GET /admin/mcp/docs` | Integration guide (how to connect Claude Code, Cursor) |

Design: glass-morphism/catalyst, HTMX, consistent with existing admin pages.

---

## 10. Cloudflare Workers Compatibility

| Concern | Solution |
|---|---|
| SSE | `ReadableStream` + `TransformStream` — native Workers API |
| Crypto (key hashing) | `crypto.subtle.digest('SHA-256', ...)` — native Workers API |
| Long-running connections | Keep-alive ping every 30s via SSE comment (`:\n\n`) |
| `zod-to-json-schema` | Tree-shakeable, no Node.js deps — Workers compatible |
| No `process.env` | Use `ctx.env` from `onBoot` context |

---

## 11. Implementation Plan

### Phase 1 — Core Protocol + Read Tools
- [ ] `configSchema.ts` — plugin config Zod schema
- [ ] `mcp_api_key` document type registration in `onBoot`
- [ ] Bearer token auth middleware
- [ ] Transport handler (POST JSON-RPC + GET SSE)
- [ ] `initialize` + `tools/list` methods
- [ ] `list_collections`, `list_{typeId}`, `get_{typeId}` tools
- [ ] `resources/list` + `resources/read` (schemas only)
- [ ] Unit tests for tool generation + auth middleware

### Phase 2 — Write Tools
- [ ] `create_{typeId}`, `update_{typeId}`, `publish_{typeId}`, `delete_{typeId}` tools
- [ ] Scope enforcement on write ops
- [ ] Input schema generation (Zod → JSON Schema)
- [ ] Integration tests (real SQLite harness)

### Phase 3 — Admin UI + API Keys
- [ ] Admin routes + HTMX templates
- [ ] Key create/list/revoke UI
- [ ] Plugin dashboard with request metrics (stored in `documents` as `mcp_request_log` type)
- [ ] Integration guide page (Claude Code `~/.claude/settings.json` snippet auto-generated)

### Phase 4 — Polish
- [ ] `search_content` cross-type tool
- [ ] `redactFields` config option
- [ ] E2E Playwright specs (numbered 68+, per R11)
- [ ] README + integration examples

---

## 12. Open Questions

1. **`mcp-remote` vs direct HTTP** — Some MCP clients need `mcp-remote` npm bridge for SSE. Add setup instructions or ship small proxy endpoint?
2. **Request logging** — Store per-request logs as documents (`mcp_request_log`)? Adds storage, enables usage analytics. Make opt-in via config.
3. **Webhooks / push notifications** — Out of scope v1. MCP 2025-11 spec supports server-initiated notifications. Note for v2.
4. **Rate limiting** — Cloudflare Rate Limiting on `/api/mcp`? Deployment concern, not plugin responsibility.
5. **Multi-tenant** — POC uses `tenant_id = 'default'`. Multi-tenant follows same pattern as rest of system.

---

## 13. Files Changed / Created

### New
```
packages/core/src/plugins/core-plugins/mcp-plugin/   (entire directory)
tests/e2e/68-mcp-plugin-read.spec.ts
tests/e2e/69-mcp-plugin-write.spec.ts
tests/e2e/70-mcp-api-key-management.spec.ts
```

### Modified
```
packages/core/src/plugins/core-plugins/index.ts      — export mcpPlugin
packages/core/src/index.ts                           — export mcpPlugin from public API
packages/core/src/services/document-types-seed.ts   — add mcp_api_key type seed (optional)
```

No migration files. No new DB tables.

---

## 14. Acceptance Criteria

- [ ] `POST /api/mcp` with valid bearer key returns valid MCP `initialize` response
- [ ] `tools/list` returns one tool per exposed collection × operation
- [ ] `tools/call list_posts` returns published posts via `DocumentRepository`
- [ ] `tools/call create_posts` creates document, respects ACL
- [ ] Invalid/expired key returns `401` with MCP error envelope
- [ ] Admin can create, view prefix, and revoke API keys
- [ ] Plugin disabled = no routes mounted (zero surface area)
- [ ] All existing tests pass (no regressions)
- [ ] E2E specs 68–70 pass in CI