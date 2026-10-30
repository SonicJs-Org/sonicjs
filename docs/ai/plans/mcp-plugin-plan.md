# MCP Plugin Plan — Issue #784 (revised)

**Status**: Ready to build
**Issue**: https://github.com/SonicJs-Org/sonicjs/issues/784

> **Revision note**: This plan was rewritten after a codebase audit. The original
> draft duplicated infrastructure that already exists. See §0 for what changed and
> why. Net effect: ~40% less code, zero new dependencies, zero new tables, zero
> new document types.

---

## 0. What changed from the original draft (and why)

| Original draft | Reality found in codebase | Decision |
|---|---|---|
| New `mcp_api_key` document type + hashing + mint-once flow (§7.1, §3.2) | `api-keys-plugin` already ships `api_key` doc type, `sk_<hex>` secret, SHA-256 hash, mint-once UI at `/admin/plugins/api-keys`, and `ApiKeyService.resolve()`. | **Reuse it.** Drop the entire `mcp_api_key` type, `auth/` dir, and key-CRUD UI. |
| Per-request Bearer→key middleware inside the plugin | `apiKeyAuthMiddleware()` is wired **globally** (`app.ts:487`, `app.use('*', …)`). It resolves `Authorization: Bearer sk_…` → `c.get('user') = {userId,email,role,isSuperAdmin}` before any route runs. | **Inherit it.** `/api/mcp` gets an authed principal for free. Plugin only checks `c.get('user')` presence. |
| `principalSet` uses invented `role: 'mcp'` (§7.3) | Base grants match `public` + real `role`. A fake `mcp` role matches no grants. | Use the **real user role**: `[{type:'user',id:userId},{type:'role',id:role}]`. Higher ACL fidelity. |
| `zod-to-json-schema` dependency (§10) | Collections are `FieldConfig[]` arrays (`types/collection-config.ts`), **not** Zod schemas. | Hand-write a small `fieldConfigToJsonSchema()` mapper. **No new dep** (Workers bundle stays lean). |
| MCP SDK + Streamable HTTP + SSE stream (§2, §4) | The official SDK assumes Node transports. SSE is only needed for **server-initiated** notifications (out of scope v1). | v1 = plain **POST → JSON** JSON-RPC 2.0, hand-rolled (~60 LOC). `GET /api/mcp` SSE deferred to v2. |
| Reads via `DocumentRepository.list({principalSet})` | `list()` takes **no** `principalSet`; ACL is a separate `isAllowed(principalSet, rootId, permission, typeSettings)` call. | Reads = `list()` then per-doc `isAllowed()` filter. Writes = `DocumentsService` + `isAllowed` gate (mirrors `admin-content.ts`). |
| E2E specs numbered 68–70 | Highest existing spec is `91-*`. R11 floor is stale. | Number new specs **92–94**. |
| Per-key `scopes: ['read','write']` | `api_key` has no scope field. | v1: **no per-key scopes.** ACL + document-level permissions are the real gate. Read/write split is enforced by tool config (`types[t].write`) + `isAllowed(...,'update'|'create')`. Per-key scopes = v2 (would need an `api_key` field add). |

**Unchanged from the draft**: opt-in plugin, auto-generated per-type tools, static
`list_collections` + `search_content`, resources for collection schemas, admin
dashboard + integration guide, R12 compliance (no legacy-table drops).

---

## 1. Goal

MCP plugin exposes SonicJS content as callable tools over the Model Context
Protocol. AI agents (Claude Code, Cursor, VS Code, …) read/manage content via
standard MCP clients.

**Opt-in** — registered like any core plugin (manifest `is_core: true`, **not**
seeded active). Activated by the operator; mounts zero surface area when inactive.

Authentication is delegated entirely to the existing **API Keys** plugin. To use
MCP, an operator mints a key at `/admin/plugins/api-keys` and presents it as
`Authorization: Bearer sk_…`.

---

## 2. MCP protocol (v1 subset)

MCP = JSON-RPC 2.0. v1 implements the request/response half over a single
`POST /api/mcp` endpoint returning `application/json`. No SSE stream in v1
(server-initiated notifications are out of scope).

Methods supported:

| Method | Description |
|---|---|
| `initialize` | Handshake — returns `serverInfo` + `capabilities: { tools:{}, resources:{} }` |
| `tools/list` | Tools visible to the caller (per plugin config) |
| `tools/call` | Execute one tool; returns `content: [{type:'text', text:…}]` |
| `resources/list` | Available resource URIs |
| `resources/read` | Read one resource (collection schema / document list) |

JSON-RPC error envelope on failure: `{ jsonrpc:'2.0', id, error:{ code, message } }`.
Codes: `-32700` parse, `-32600` invalid request, `-32601` method not found,
`-32602` invalid params, `-32603` internal, `-32001` unauthorized (custom).

---

## 3. Architecture

### 3.1 Plugin location + files

```
packages/core/src/plugins/core-plugins/mcp-plugin/
  index.ts                       definePlugin — register(app), configSchema, menu
  manifest.json                  auto-registry entry (is_core, opt-in)
  config.ts                      Zod config schema + defaults + resolve helper
  jsonrpc.ts                     JSON-RPC 2.0 parse + dispatch + error envelopes
  routes/
    mcp.ts                       POST /api/mcp — the 5 methods
  tools/
    registry.ts                  build tool list from CollectionRegistry ∩ config
    documents.ts                 list/get/create/update/publish/delete executors
    static.ts                    list_collections, search_content executors
  resources/
    schemas.ts                   sonicjs:// resource resolvers
  schema/
    field-to-jsonschema.ts       FieldConfig[] → JSON Schema (no dep)
  admin/
    routes.ts                    GET /admin/mcp dashboard + integration guide
    templates.ts                 catalyst/HTMX templates
  __tests__/
    tool-registry.test.ts        unit — tool generation from config
    jsonrpc.test.ts              unit — dispatch + error envelopes
    field-to-jsonschema.test.ts  unit — field mapper
    mcp.integration.test.ts      real-SQLite — call round-trips
```

### 3.2 Document types introduced

**None.** Auth reuses `api_key`. Content lives in existing collection-backed
`documents`. No new type registration, no new `q_*` columns.

### 3.3 Mount points

Both mounted synchronously in the plugin's `register(app)`:

```
POST /mcp            JSON-RPC endpoint (under global apiKeyAuthMiddleware)
GET  /admin/mcp      dashboard + integration guide (under admin auth)
```

Note: `/mcp` not `/api/mcp` — user plugins are registered after `app.route('/api', apiRoutes)`
in `app.ts`, so `/api/mcp` would be caught by the `/:collection` POST catch-all.

---

## 4. Auth (delegated)

No auth code in this plugin beyond a presence check.

1. Operator mints an `sk_…` key at `/admin/plugins/api-keys`.
2. Client sends `Authorization: Bearer sk_…` to `POST /api/mcp`.
3. Global `apiKeyAuthMiddleware` (`app.ts:487`) resolves it → `c.get('user')`.
4. In `routes/mcp.ts`:
   ```ts
   const user = c.get('user')
   if (!user) return jsonRpcError(id, -32001, 'Unauthorized: valid API key required')
   const principalSet = [
     { type: 'user', id: user.userId },
     { type: 'role', id: user.role },
   ]
   ```
5. Every read/write passes `principalSet` through `DocumentRepository.isAllowed()`.
   The MCP layer never bypasses document ACL.

Read vs write split (v1, no per-key scopes):
- Read tools (`list_*`, `get_*`, `list_collections`, `search_content`) require
  `isAllowed(principalSet, rootId, 'read', …)` per document.
- Write tools (`create_*`, `update_*`, `publish_*`, `delete_*`) are only generated
  for types with `config.types[t].write === true`, **and** gated at call time by
  `isAllowed(…, 'create'|'update'|'delete', …)`.

---

## 5. Tools

### 5.1 Auto-generated per exposed type

For each active collection in `CollectionRegistry.listActive()` that passes the
`config.expose` filter:

| Tool | Maps to | Scope |
|---|---|---|
| `list_{typeId}` | `DocumentRepository.list({ typeId, status, limit })` → `isAllowed` filter | read |
| `get_{typeId}` | `DocumentRepository.getById` / by slug (`q_slug`) → `isAllowed` | read |
| `create_{typeId}` | `DocumentsService.create()` (optional `publishOnCreate`) | write |
| `update_{typeId}` | `DocumentsService.saveDraft()` | write |
| `publish_{typeId}` | `DocumentsService.publish()` | write |
| `delete_{typeId}` | `DocumentsService` soft-delete (`deleted_at`) | write |

Write tools emitted only when `config.types[typeId].write === true` (default true
for exposed types unless overridden).

### 5.2 Static tools (always present when plugin active)

| Tool | Description |
|---|---|
| `list_collections` | Exposed type IDs + display names + record counts |
| `search_content` | Cross-type search over `q_title` / `q_slug` (LIKE), ACL-filtered |

### 5.3 Tool input schema generation

`inputSchema` (JSON Schema) built from the collection's `FieldConfig[]` via
`fieldConfigToJsonSchema()`. Mapping:

| FieldType | JSON Schema |
|---|---|
| `text`, `slug`, `richtext`, `textarea`, `email`, `url` | `{type:'string'}` |
| `number` | `{type:'number'}` |
| `boolean`, `checkbox` | `{type:'boolean'}` |
| `date`, `datetime` | `{type:'string', format:'date-time'}` |
| `select` | `{type:'string', enum:[…]}` |
| `array` | `{type:'array', items:…}` |
| `object` | `{type:'object'}` |
| `relation`, `media` | `{type:'string'}` (id reference) |

System/virtual fields stripped from **write** schemas: `id`, `created_at`,
`updated_at`, `version_number`, `root_id`. `required` derived from
`field.required === true`.

---

## 6. Resources

| URI | Content |
|---|---|
| `sonicjs://collections` | JSON list of exposed types + display names |
| `sonicjs://collections/{typeId}/schema` | JSON Schema for one type |
| `sonicjs://collections/{typeId}/documents` | First `listLimit` published docs (ACL-filtered) |

`resources/list` enumerates the first two per exposed type; `resources/read`
resolves by URI.

---

## 7. Plugin configuration

```ts
import { mcpPlugin } from '@sonicjs-cms/core'

registerPlugins([
  mcpPlugin({
    expose: ['posts', 'pages', 'products'],   // default: all active collections
    types: {
      posts:    { read: true, write: true },
      pages:    { read: true, write: false }, // read-only
      products: { read: true, write: true },
    },
    redactFields: ['internal_notes', 'cost_price'],  // stripped from all responses
    listLimit: 50,                                    // cap for list_*/resources
  }),
])
```

`config.ts` exposes a Zod schema (all fields optional, defaulted) and a
`resolveMcpConfig(raw, registry)` that expands `expose` defaults from the live
registry. Persisted via the standard plugin `settings` field (`configSchema`).

Defaults: `expose` = every active collection; `types[t]` = `{read:true,write:true}`;
`redactFields` = `[]`; `listLimit` = 50.

---

## 8. Admin UI (`/admin/mcp`)

No key management here — that lives at `/admin/plugins/api-keys`. This page is
read-only guidance + status.

| Section | Content |
|---|---|
| Status | Plugin active? Endpoint URL. Count of exposed collections + tools. |
| Exposed collections | Table: type, read/write flags, tool names. |
| Integration guide | Copy-paste client config (Claude Code / Cursor `mcp.json`) with the live endpoint URL pre-filled + a "mint a key" link to `/admin/plugins/api-keys`. |

Design: catalyst/glass-morphism + HTMX, consistent with existing admin pages.
Escape all rendered values with `escapeHtml` (R8).

---

## 9. Cloudflare Workers compatibility

| Concern | Solution |
|---|---|
| JSON-RPC parse | `await c.req.json()` — native |
| Crypto | none needed in-plugin (delegated to ApiKeyService) |
| JSON Schema gen | hand-rolled mapper, no deps |
| No SSE in v1 | plain JSON response; no long-lived connection |
| `process.env` | use `c.env` — never `process` |

---

## 10. Implementation plan

### Phase 1 — Protocol + read tools ✅ (shipped)
- [x] `config.ts` — Zod config schema, defaults, `resolveMcpConfig`
- [x] `schema/field-to-jsonschema.ts` — FieldConfig[] → JSON Schema
- [x] `jsonrpc.ts` — parse, dispatch, error envelopes
- [x] `tools/registry.ts` — build tool set from registry ∩ config (write/search phase-gated off)
- [x] `tools/documents.ts` — `list_*`, `get_*` executors (read + `isAllowed` filter)
- [x] `tools/static.ts` — `list_collections`
- [x] `resources/schemas.ts` — `resources/list` + `resources/read` (schemas)
- [x] `routes/mcp.ts` — POST handler: `initialize`, `tools/list`, `tools/call`, `resources/*`
- [x] `index.ts` + `manifest.json` — definePlugin, register (`/api/mcp` only; menu/admin → P3)
- [x] export from `core-plugins/index.ts` + public `src/index.ts`; regenerated `manifest-registry.ts`
- [x] unit tests: `tool-registry`, `jsonrpc`, `field-to-jsonschema`, `config` (37 tests, all pass)
- [ ] **P2 carryover**: real-SQLite integration test of the read path (R10 — unit/mock tests don't prove SQL). Bundled with the Phase 2 harness.

### Phase 2 — Write tools ✅ (shipped)
- [x] `tools/mutations.ts` — `create_*`, `update_*`, `publish_*`, `delete_*` (keyed by root id)
- [x] write-scope gating: config `types[t].write` (tool emission) + `isAllowed` per op (create=base-grant, update/publish/delete=concrete root)
- [x] PII branch: `settings.pii` → hard `erase`; else soft-delete live rows (published + current draft)
- [x] `PHASE_FLAGS.includeWrite` flipped on in `routes/mcp.ts` + write dispatch wired
- [x] `mcp.integration.test.ts` — real-SQLite route-level: create→list(draft/published)→publish→get→update→delete round-trip, ACL denial (viewer), auth gate, unknown-tool, resources/read (9 tests)
- Note: `data` on update merges (`{...prev, ...input.data}`) — partial payloads are safe. Input beyond title/slug/data is not accepted (system fields already stripped from the write schema).

### Phase 3 — Admin UI ✅ (shipped)
- [x] `admin/templates.ts` — `renderMcpDashboardPage`: status card (endpoint URL + counts), exposed collections table (typeId/displayName/read/write/tools), integration guide (Claude Code + Cursor mcp.json with auto-filled URL)
- [x] `admin/routes.ts` — `createMcpAdminRoutes(options)`: requireAuth + admin role guard, derives endpoint URL from request, resolves live config + builds tool list for counts
- [x] `index.ts` updated — mounts `/admin/mcp`, adds sidebar menu entry (order 87, terminal icon)
- [x] E2E spec `tests/e2e/93-mcp-admin.spec.ts` (7 cases: heading, endpoint URL, copy button, collections table, Claude Code snippet, Cursor snippet, api-keys link, unauthed redirect)

### Phase 4 — Polish
- [ ] `search_content` cross-type tool
- [ ] `redactFields` enforcement in all responses
- [ ] E2E specs `94-mcp-read.spec.ts`, `95-mcp-write.spec.ts` (write only — CI runs; admin spec shipped in P3 as `93-mcp-admin.spec.ts`)
- [ ] README + client integration examples

---

## 11. Files changed / created

### New
```
packages/core/src/plugins/core-plugins/mcp-plugin/**   (entire directory)
tests/e2e/93-mcp-admin.spec.ts
tests/e2e/94-mcp-read.spec.ts      (P4)
tests/e2e/95-mcp-write.spec.ts     (P4)
```

### Modified
```
packages/core/src/plugins/core-plugins/index.ts   — export mcpPlugin
packages/core/src/index.ts                         — re-export mcpPlugin from public API
```

**No migrations. No new DB tables. No new document types. No new dependencies.**

---

## 12. Acceptance criteria

- [ ] `POST /api/mcp` (`initialize`) with a valid `Bearer sk_…` returns MCP handshake
- [ ] Missing/invalid key → `-32001` unauthorized envelope
- [ ] `tools/list` returns one tool per exposed collection × operation + static tools
- [ ] `tools/call list_{type}` returns published docs, ACL-filtered via `isAllowed`
- [ ] `tools/call create_{type}` creates a document and respects ACL (denied → error)
- [ ] Read-only type (`write:false`) emits no write tools; forced call → method-not-found
- [ ] `resources/read sonicjs://collections/{type}/schema` returns valid JSON Schema
- [ ] `/admin/mcp` renders status + integration guide; links to api-keys for tokens
- [ ] Plugin inactive → no routes mounted (zero surface area)
- [ ] All existing tests pass (no regressions)
- [ ] E2E specs 92–94 present (validated by CI)

---

## 13. Open questions / deferred to v2

1. **SSE / server push** — `GET /api/mcp` streaming for notifications. Out of scope v1.
2. **Per-key scopes** — narrow a key to read-only or to specific types. Needs an
   `api_key` field addition; v1 relies on ACL + user role.
3. **`mcp-remote` bridge** — some clients need the npm SSE bridge. Document in the
   integration guide; revisit if direct HTTP proves insufficient.
4. **Request logging / usage metrics** — opt-in `documents`-backed log. v2.
5. **Rate limiting** — Cloudflare Rate Limiting on `/api/mcp` is a deployment
   concern, not plugin responsibility.
