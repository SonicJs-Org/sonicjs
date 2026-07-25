# SonicJS Developer SDK — Build Plan

> **Status**: Approved design, ready to build.
> **Audience**: Builder agents. This doc is self-contained — you should not need to re-explore the codebase to execute. File paths, code skeletons, endpoint mappings, and per-phase acceptance criteria are all inline.
> **Package**: `@sonicjs-cms/sdk` at `packages/sdk/`.

---

## 1. Context & goal

SonicJS is a Cloudflare-native headless CMS (`@sonicjs-cms/core`, published to npm). Today the only way to consume its HTTP API from an external app (Next.js, React, Cloudflare Workers, Node scripts) is hand-written `fetch` against `/api/*` and `/auth/*`: no typed client, no per-collection types, manual auth headers, manual keyset-cursor paging, manual `where[field][op]=value` filter encoding.

**Build a first-class SDK**: an isomorphic, zero-runtime-dependency TypeScript client wrapping the full public API, plus a codegen CLI that emits per-collection TypeScript types from a live instance.

### Locked product decisions
| # | Decision | Value |
|---|---|---|
| 1 | Scope | **Full client** — read + write CRUD + media + auth |
| 2 | Codegen | **Yes** — CLI generates per-collection TS types from collections |
| 3 | Runtime | **Isomorphic core only** — browser / Node / Workers, zero-dependency native `fetch` |
| 4 | Auth | **API keys + JWT session + public-anon reads** |

### Non-goals
- No React/Next.js hooks package (future, separate).
- No server-side/plugin authoring helpers (that's already `@sonicjs-cms/core`).
- No new DB tables, no core route changes. SDK is a **pure client** over existing endpoints.
- No zod in SDK runtime (validation is server-side).

---

## 2. Existing API surface (verified — build against this)

**Route mounting** (`packages/core/src/app.ts:590-594`):
```
/api/media       → apiMediaRoutes
/api/system      → apiSystemRoutes
/api/documents   → apiDocumentsRoutes
/api             → apiRoutes  (content, collections, /:collection shorthands)
/auth/*          → authRoutes (+ Better Auth handler at app.ts:642)
```

### Endpoint → SDK method map

| SDK method | HTTP | Path | Source file | Notes |
|---|---|---|---|---|
| `system.health()` | GET | `/api/system/health` | `routes/api-system.ts:18` | db/kv/r2 checks |
| `system.info()` | GET | `/api/system/info` | `routes/api-system.ts:102` | name/version/features |
| `system.stats()` | GET | `/api/system/stats` | `routes/api-system.ts:131` | counts |
| `collections.list()` | GET | `/api/collections` | `routes/api.ts:646` | `{data,meta}` from registry |
| `content.list(o)` | GET | `/api/content` | `routes/api.ts:717` | `{data,meta}`, **offset**, ms ts |
| `content.get(id,o)` | GET | `/api/content/:id` | `routes/api-content-crud.ts:85` | `{data}` |
| `content.checkSlug(...)` | GET | `/api/content/check-slug` | `routes/api-content-crud.ts:49` | `{available}` |
| `content.create(i)` | POST | `/api/content` | `routes/api-content-crud.ts:174` | 201 `{data}`, auth req |
| `content.update(id,i)` | PUT | `/api/content/:id` | `routes/api-content-crud.ts:273` | auth req |
| `content.delete(id)` | DELETE | `/api/content/:id` | `routes/api-content-crud.ts:359` | `{success}`, auth req |
| `collection(n).list(o)` | GET | `/api/:collection` | `routes/api.ts:1054` | scoped shorthand |
| `collection(n).get(id)` | GET | `/api/:collection/:id` | `routes/api.ts:1172` | |
| `collection(n).create(i)` | POST | `/api/:collection` | `routes/api.ts:1238` | auth req |
| `collection(n).update(id,i)` | PUT | `/api/:collection/:id` | `routes/api.ts:1284` | auth req |
| `collection(n).delete(id)` | DELETE | `/api/:collection/:id` | `routes/api.ts:1344` | auth req |
| `documents.list(o)` | GET | `/api/documents` | `routes/api-documents.ts:29` | **keyset**, seconds ts |
| `documents.getByRoot(id)` | GET | `/api/documents/root/:rootId` | `routes/api-documents.ts:126` | time-window enforced |
| `documents.get(id)` | GET | `/api/documents/:id` | `routes/api-documents.ts:164` | by revision id |
| `media.upload(f,o)` | POST | `/api/media/upload` | `routes/api-media.ts:48` | FormData, ≤50MB, auth req |
| `media.uploadMany(f,o)` | POST | `/api/media/upload-multiple` | `routes/api-media.ts:185` | ≤50 files, auth req |
| `media.bulkDelete(ids)` | POST | `/api/media/bulk-delete` | `routes/api-media.ts:358` | ≤50, auth req |
| `auth.register(i)` | POST | `/auth/register` | `routes/auth.ts:142` | 201 `{token,user}`, rate-limited 30/min |
| `auth.login(i)` | POST | `/auth/login` | `routes/auth.ts:281` | JSON session token (Better Auth `/auth/sign-in/email`) |
| `auth.logout()` | POST | `/auth/logout` | `routes/auth.ts` | |

### Auth headers (`plugins/core-plugins/api-keys-plugin/middleware/api-key-auth.ts:19`, `middleware/auth.ts:263`)
- API key: `x-api-key: sk_…` **or** `Authorization: Bearer sk_…` (prefix `sk_`).
- Session JWT: `Authorization: Bearer <jwt>` **or** cookie `auth_token=<jwt>`. Payload `{userId,email,role,exp,iat}`.
- Anon: no header → public reads only, role-gated visibility (published-only for anon/viewer/author).

### Response envelopes
- **List (content/collections)**: `{ data: T[], meta: { count, timestamp, filter?, cache? } }`. Offset pagination.
- **Single**: `{ data: T }`.
- **Documents list**: `{ data: DocRow[], pagination: { limit, nextCursor: {cursor_updated_at, cursor_id} | null } }`. Keyset on `(updated_at, id)`.
- **Error**: `{ error: string, details?: string | object }`. Non-2xx status.

### Filter DSL (`utils/query-filter.ts`)
Query params: `where[field][op]=value` or `where[field][]=v1&where[field][]=v2`; `sort` (field), `dir` (asc|desc), `limit`, `offset`, `status` (draft|published|archived), `include` (csv), `fields` (csv projection, e.g. `id,title,data.excerpt`), `resolve_variables` (bool). Operators: `equals, in, contains, exists, gt, gte, lt, lte`. JSON paths use `data.<path>`.

### Documents list params (`routes/api-documents.ts:29`)
`type` (required), `locale` (default `default`), `limit` (≤200), `cursor_updated_at` (int), `cursor_id` (string), `sort`, `dir`, `filter[field]=value` (scalar → `q_*` cols), `facet[field]=value`.

### Timestamp units (do not silently normalize)
- Content API (`/api/content*`): **milliseconds** (legacy contract).
- Documents API (`/api/documents*`): **seconds** (D29).
- Ship helpers `secondsToDate(n)` / `msToDate(n)`; document per-resource. No lossy auto-conversion.

### Types to reuse (type-only import from `@sonicjs-cms/core`)
`CollectionConfig`, `CollectionSchema`, `FieldConfig`, `FieldType` from `packages/core/src/types/collection-config.ts`. Import type-only so SDK ships **zero** runtime dep on core.

`FieldType` =
```
string | number | boolean | date | datetime | email | url | richtext | lexical |
markdown | json | array | object | reference | media | select | multiselect |
checkbox | radio | textarea | slug | color | file | user
```
`FieldConfig` (subset used by codegen): `{ type, required?, enum?, items?: FieldConfig, properties?: Record<string,FieldConfig>, collection? }`.
`CollectionConfig`: `{ name, displayName, schema: { type:'object', properties: Record<string,FieldConfig>, required?: string[] }, ... }`.

---

## 3. Monorepo conventions (match these)

- npm workspaces; root `package.json` glob `packages/*` **auto-includes** `packages/sdk` — no workspaces edit needed.
- Build tool: **tsup** dual ESM+CJS + `.d.ts`, tree-shaking, target ES2022. `"type":"module"`.
- Node ≥18, TypeScript ^5.9, module resolution `bundler`.
- Publish: `.github/workflows/publish.yml` on GitHub release (Node 20, `--provenance --access public`). **Add sdk to its publish step.**
- Versioning: custom `scripts/sync-versions.js` (no changesets). **Add sdk to its sync list.** Current core version `3.0.0-beta.24`.
- Root `tsconfig.json` has path aliases for workspace pkgs — **add `@sonicjs-cms/sdk`**.
- **Lock-file trap**: any `npm install` on macOS → immediately `rm -rf node_modules package-lock.json && npm install`, then commit. Never commit a lock produced by `npm install --workspace=...`.

---

## 4. Package layout

```
packages/sdk/
  package.json
  tsup.config.ts
  tsconfig.json
  README.md
  src/
    index.ts              # barrel: createClient, defineClient, SonicError, types
    client.ts             # SonicClient factory wiring resources
    http.ts               # HttpClient: fetch wrapper, auth, error mapping, retry-none
    config.ts             # ClientOptions, resolveAuthHeaders()
    errors.ts             # SonicError
    types.ts              # envelopes, ListOptions, DocumentRow, MediaAsset, AuthResult
    query.ts              # ListOptions → query string serializer
    pagination.ts         # keyset iterate() generator + offset page helper
    time.ts               # secondsToDate / msToDate
    resources/
      content.ts
      collections.ts
      documents.ts
      media.ts
      auth.ts
      system.ts
    codegen/
      cli.ts              # arg parse + orchestrate
      fetch-schema.ts     # live GET /api/collections | local config module
      field-map.ts        # FieldType → TS type string
      emit.ts             # render collections.d.ts
  __tests__/
    content.test.ts
    documents.test.ts
    media.test.ts
    auth.test.ts
    query.test.ts
    pagination.test.ts
    codegen.test.ts
```

---

## 5. File-by-file spec

### `package.json`
```jsonc
{
  "name": "@sonicjs-cms/sdk",
  "version": "3.0.0-beta.24",          // keep in lockstep via sync-versions.js
  "description": "Isomorphic TypeScript client + codegen for the SonicJS headless CMS API.",
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "bin": { "sonicjs-sdk": "./dist/cli.cjs" },
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js", "require": "./dist/index.cjs" },
    "./package.json": "./package.json"
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsup",
    "dev": "tsup --watch",
    "type-check": "tsc --noEmit",
    "test": "vitest run",
    "prepublishOnly": "npm run build",
    "prepare": "npm run build"
  },
  "engines": { "node": ">=18.0.0" },
  "devDependencies": {
    "@sonicjs-cms/core": "workspace:*",   // TYPE-ONLY import; not a runtime dep
    "tsup": "^8",
    "typescript": "^5.9.3",
    "vitest": "^3"
  }
  // NO dependencies / peerDependencies — zero runtime deps, native fetch.
}
```
> Confirm exact tsup/vitest versions against root `package.json` / `packages/core/package.json` before pinning.

### `tsup.config.ts`
```ts
import { defineConfig } from 'tsup'
export default defineConfig({
  entry: { index: 'src/index.ts', cli: 'src/codegen/cli.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  target: 'es2022',
  // @sonicjs-cms/core is type-only; ensure it is NOT bundled:
  external: ['@sonicjs-cms/core'],
})
```

### `tsconfig.json`
Extend root config; `noEmit` (tsup emits). `moduleResolution: bundler`, `strict: true`.

### `src/config.ts`
```ts
export interface ClientOptions {
  url: string                       // base URL of the CMS, no trailing slash required
  apiKey?: string                   // sk_… → x-api-key
  token?: string                    // JWT → Authorization: Bearer
  tenant?: string                   // optional; default 'default' server-side
  fetch?: typeof fetch              // override for Workers/tests
  headers?: Record<string, string>  // extra static headers
}

export interface RequestAuth { apiKey?: string; token?: string }

export function resolveAuthHeaders(
  opts: ClientOptions, override?: RequestAuth,
): Record<string, string> {
  const h: Record<string, string> = {}
  const apiKey = override?.apiKey ?? opts.apiKey
  const token = override?.token ?? opts.token
  if (apiKey) h['x-api-key'] = apiKey            // precedence: call override → apiKey → token → anon
  else if (token) h['Authorization'] = `Bearer ${token}`
  return h
}
```

### `src/errors.ts`
```ts
export class SonicError extends Error {
  readonly status: number
  readonly code: string
  readonly details?: unknown
  constructor(args: { status: number; code: string; message: string; details?: unknown }) {
    super(args.message)
    this.name = 'SonicError'
    this.status = args.status; this.code = args.code; this.details = args.details
  }
}
```

### `src/http.ts`
```ts
import { ClientOptions, RequestAuth, resolveAuthHeaders } from './config'
import { SonicError } from './errors'

export class HttpClient {
  constructor(private opts: ClientOptions) {}
  private base = () => this.opts.url.replace(/\/$/, '')
  private fetchImpl = () => this.opts.fetch ?? fetch

  async request<T>(method: string, path: string, init?: {
    query?: Record<string, unknown>; body?: unknown; form?: FormData; auth?: RequestAuth;
  }): Promise<T> {
    const url = this.base() + path + (init?.query ? '?' + serializeQuery(init.query) : '')
    const headers: Record<string,string> = {
      ...(this.opts.headers ?? {}),
      ...resolveAuthHeaders(this.opts, init?.auth),
    }
    let bodyInit: BodyInit | undefined
    if (init?.form) { bodyInit = init.form }                 // let fetch set multipart boundary
    else if (init?.body !== undefined) { headers['Content-Type'] = 'application/json'; bodyInit = JSON.stringify(init.body) }
    let res: Response
    try { res = await this.fetchImpl()(url, { method, headers, body: bodyInit }) }
    catch (e) { throw new SonicError({ status: 0, code: 'network', message: String((e as Error)?.message ?? e) }) }
    const text = await res.text()
    const json = text ? safeJson(text) : undefined
    if (!res.ok) throw new SonicError({ status: res.status, code: 'http_error', message: json?.error ?? res.statusText, details: json?.details ?? json })
    return json as T
  }
}
```
`serializeQuery` lives in `query.ts`. `safeJson` = try/catch JSON.parse → undefined.

### `src/query.ts`
Serialize `ListOptions` → query string. Handle:
- scalars: `limit, offset, status, sort, dir, include, fields, resolve_variables`.
- `where`: `{ field: { op: value } }` → `where[field][op]=value`; array value → repeated `where[field][]=v`.
- `filter` / `facet` (documents): `filter[field]=value`.
- `cursor`: `{updatedAt,id}` → `cursor_updated_at`, `cursor_id`.
Export `serializeQuery(obj: Record<string,unknown>): string` used by HttpClient too. URL-encode keys+values.

### `src/types.ts`
```ts
export interface ListMeta { count: number; timestamp: string; filter?: unknown; cache?: unknown }
export interface ListResponse<T> { data: T[]; meta: ListMeta }
export interface ItemResponse<T> { data: T }
export interface Keyset { updatedAt: number; id: string }
export interface DocumentsPage<T> { data: T[]; nextCursor: Keyset | null }

export interface ContentRecord {
  id: string; title: string; slug: string; status: 'draft'|'published'|'archived'
  collectionId: string; data: Record<string, unknown>
  created_at: number /* ms */; updated_at: number /* ms */
}
export interface DocumentRow {
  id: string; rootId: string; typeId: string; title: string | null; slug: string | null
  path: string | null; locale: string
  publishedAt: number /* seconds */; updatedAt: number /* seconds */; data: Record<string, unknown>
}
export interface MediaAsset {
  id: string; filename: string; originalName: string; mimeType: string; size: number
  publicUrl: string; thumbnailUrl: string | null; uploadedAt: string
}
export interface AuthResult { token: string; user: { id?: string; userId?: string; email: string; role: string } }

export interface ListOptions {
  limit?: number; offset?: number; status?: 'draft'|'published'|'archived'
  sort?: string; dir?: 'asc'|'desc'; fields?: string[]; include?: string[]
  where?: Record<string, Record<string, unknown> | unknown>
  resolveVariables?: boolean
}
export interface DocumentsListOptions {
  type: string; locale?: string; limit?: number; cursor?: Keyset | null
  sort?: string; dir?: 'asc'|'desc'
  filter?: Record<string, unknown>; facet?: Record<string, unknown>
}
```

### `src/resources/content.ts`
```ts
export class ContentResource {
  constructor(private http: HttpClient) {}
  list(o: ListOptions = {}, auth?: RequestAuth) {
    return this.http.request<ListResponse<ContentRecord>>('GET', '/api/content', { query: toContentQuery(o), auth })
  }
  get(id: string, o?: { fields?: string[]; resolveVariables?: boolean }, auth?: RequestAuth) {
    return this.http.request<ItemResponse<ContentRecord>>('GET', `/api/content/${enc(id)}`, { query: o, auth })
  }
  checkSlug(collectionId: string, slug: string, excludeId?: string) {
    return this.http.request<{ available: boolean; message?: string }>('GET', '/api/content/check-slug', { query: { collectionId, slug, excludeId } })
  }
  create(input: { collectionId: string; title: string; slug?: string; status?: string; data?: Record<string,unknown> }, auth?: RequestAuth) {
    return this.http.request<ItemResponse<ContentRecord>>('POST', '/api/content', { body: input, auth })
  }
  update(id: string, input: Partial<{ title: string; slug: string; status: string; data: Record<string,unknown> }>, auth?: RequestAuth) {
    return this.http.request<ItemResponse<ContentRecord>>('PUT', `/api/content/${enc(id)}`, { body: input, auth })
  }
  delete(id: string, auth?: RequestAuth) {
    return this.http.request<{ success: boolean }>('DELETE', `/api/content/${enc(id)}`, { auth })
  }
}
```
`enc` = `encodeURIComponent`. `toContentQuery` maps `ListOptions` → DSL via `query.ts` (`fields`→csv, `where`→bracket form, `resolveVariables`→`resolve_variables`).

### `src/resources/collections.ts`
- `list()` → GET `/api/collections` → `{data,meta}`.
- `collection(name)` returns a scoped object with `list/get/create/update/delete` hitting `/api/:collection[/:id]` (same shapes as content, collectionId implied by path). Support generic typing (see §6).

### `src/resources/documents.ts`
```ts
export class DocumentsResource {
  constructor(private http: HttpClient) {}
  async list(o: DocumentsListOptions, auth?: RequestAuth): Promise<DocumentsPage<DocumentRow>> {
    const raw = await this.http.request<{ data: DocumentRow[]; pagination: { limit: number; nextCursor: { cursor_updated_at: number; cursor_id: string } | null } }>(
      'GET', '/api/documents', { query: toDocQuery(o), auth })
    const nc = raw.pagination.nextCursor
    return { data: raw.data, nextCursor: nc ? { updatedAt: nc.cursor_updated_at, id: nc.cursor_id } : null }
  }
  async *iterate(o: DocumentsListOptions, auth?: RequestAuth): AsyncGenerator<DocumentRow> {
    let cursor = o.cursor ?? null
    do {
      const page = await this.list({ ...o, cursor }, auth)
      for (const row of page.data) yield row
      cursor = page.nextCursor
    } while (cursor)
  }
  getByRoot(rootId: string, auth?: RequestAuth) { return this.http.request<DocumentRow>('GET', `/api/documents/root/${enc(rootId)}`, { auth }) }
  get(id: string, auth?: RequestAuth) { return this.http.request<DocumentRow>('GET', `/api/documents/${enc(id)}`, { auth }) }
}
```

### `src/resources/media.ts`
```ts
export class MediaResource {
  constructor(private http: HttpClient) {}
  upload(file: File | Blob, o?: { folder?: string; filename?: string }, auth?: RequestAuth) {
    const fd = new FormData()
    fd.append('file', file, o?.filename)
    if (o?.folder) fd.append('folder', o.folder)
    return this.http.request<{ success: boolean; file: MediaAsset }>('POST', '/api/media/upload', { form: fd, auth })
  }
  uploadMany(files: (File|Blob)[], o?: { folder?: string }, auth?: RequestAuth) {
    const fd = new FormData()
    for (const f of files) fd.append('files', f)
    if (o?.folder) fd.append('folder', o.folder)
    return this.http.request<{ success: boolean; uploaded: MediaAsset[]; errors: unknown[]; summary: { total:number; successful:number; failed:number } }>('POST', '/api/media/upload-multiple', { form: fd, auth })
  }
  bulkDelete(fileIds: string[], auth?: RequestAuth) {
    return this.http.request<{ success: boolean; deleted: string[]; errors: unknown[] }>('POST', '/api/media/bulk-delete', { body: { fileIds }, auth })
  }
}
```
> Note: browser `File`/`Blob`/`FormData` are global in Workers + modern Node (18+). No polyfill.

### `src/resources/auth.ts`
```ts
export class AuthResource {
  constructor(private http: HttpClient, private setAuth: (a: { token?: string }) => void) {}
  async register(input: { email: string; password: string; firstName?: string; lastName?: string; [k:string]: unknown }) {
    const res = await this.http.request<AuthResult>('POST', '/auth/register', { body: input })
    if (res.token) this.setAuth({ token: res.token })
    return res
  }
  async login(input: { email: string; password: string }) {
    const res = await this.http.request<AuthResult>('POST', '/auth/login', { body: input })
    if (res.token) this.setAuth({ token: res.token })
    return res
  }
  logout() { this.setAuth({ token: undefined }); return this.http.request<unknown>('POST', '/auth/logout') }
}
```
Client exposes `setToken(t)` / `setApiKey(k)` that mutate stored `ClientOptions` so post-login calls auto-authenticate.

### `src/resources/system.ts`
`health()` → `/api/system/health`, `info()` → `/api/system/info`, `stats()` → `/api/system/stats`. Plain typed GETs.

### `src/client.ts` + `src/index.ts`
```ts
export function createClient<TCollections = DefaultCollections>(opts: ClientOptions) {
  const state: ClientOptions = { ...opts }
  const http = new HttpClient(state)
  const setAuth = (a: { token?: string; apiKey?: string }) => Object.assign(state, a)
  return {
    content: new ContentResource(http),
    collections: new CollectionsResource(http),
    collection: <K extends keyof TCollections>(name: K) => new ScopedCollection<TCollections[K]>(http, String(name)),
    documents: new DocumentsResource(http),
    media: new MediaResource(http),
    auth: new AuthResource(http, setAuth),
    system: new SystemResource(http),
    setToken: (t?: string) => setAuth({ token: t }),
    setApiKey: (k?: string) => setAuth({ apiKey: k }),
  }
}
export type SonicClient<T = DefaultCollections> = ReturnType<typeof createClient<T>>
// index.ts re-exports: createClient, SonicError, all public types, time helpers.
```
`defineClient` = thin typed alias so codegen output can `createClient<Collections>()`.

### `src/time.ts`
`secondsToDate(n) => new Date(n*1000)`; `msToDate(n) => new Date(n)`.

---

## 6. Codegen CLI

**Command**: `npx sonicjs-sdk codegen --url <cms> [--api-key sk_…] --out <file.d.ts> [--from-config <path>]`

**Flow**
1. **fetch-schema.ts**
   - Default (live): `GET {url}/api/collections` (optionally with `x-api-key`) → `{ data: CollectionConfig[] }`. Each has `name` + `schema.properties` + `schema.required`.
   - `--from-config <path>`: dynamic-import a module exporting collection configs (repo-local generation without a running server).
2. **field-map.ts** — `FieldConfig → TS type string`:
   | FieldType | TS |
   |---|---|
   | string, email, url, slug, color, richtext, markdown, lexical, textarea | `string` |
   | number | `number` |
   | boolean, checkbox | `boolean` |
   | date, datetime | `string \| number` |
   | json | `Record<string, unknown>` |
   | object | nested interface from `properties` |
   | array | `<mapped items>[]` (from `items`; fallback `unknown[]`) |
   | reference, media, file, user | `string` (id) |
   | select, radio | union from `enum` (`'a' \| 'b'`); fallback `string` |
   | multiselect | `(<union>)[]` |
   Required vs optional from `schema.required` → `?` on the property.
3. **emit.ts** — render:
   ```ts
   // AUTO-GENERATED by @sonicjs-cms/sdk codegen. Do not edit.
   export interface BlogPostsData { title: string; body: string; excerpt?: string; tags: string[] }
   export interface Collections {
     blog_posts: { data: BlogPostsData }
     // …one entry per collection, key = collection.name
   }
   ```
   PascalCase interface name from collection `name`. Write to `--out`.

**Usage after codegen**
```ts
import { createClient } from '@sonicjs-cms/sdk'
import type { Collections } from './sonicjs.d.ts'
const sonic = createClient<Collections>({ url, apiKey })
sonic.collection('blog_posts').list()   // data typed as BlogPostsData
```

---

## 7. Build phases (checklists for builder agents)

Each phase = one PR-sized unit. Mark boxes as you go.

### P0 — Scaffold + wiring
- [ ] Create `packages/sdk/` with `package.json`, `tsup.config.ts`, `tsconfig.json`, empty `src/index.ts`, `README.md` stub.
- [ ] Add `@sonicjs-cms/sdk` path alias to root `tsconfig.json`.
- [ ] Add sdk to `scripts/sync-versions.js` package list.
- [ ] Add sdk build+publish to `.github/workflows/publish.yml`.
- [ ] `rm -rf node_modules package-lock.json && npm install`; commit regenerated lock.
- **Accept**: `cd packages/sdk && npm run build` emits `dist/index.{js,cjs,d.ts}` + `dist/cli.{js,cjs}`.

### P1 — Transport core
- [ ] `config.ts`, `errors.ts`, `http.ts`, `query.ts` (serializer only), `types.ts`.
- **Accept**: unit test — mock `fetch`, assert URL/method/headers/JSON body; non-2xx → `SonicError` with status+details; network throw → code `network`.

### P2 — Read resources
- [ ] `content.list/get/checkSlug`, `collections.list`, `documents.list/iterate/getByRoot/get`, `system.*`.
- [ ] `pagination.ts` keyset generator.
- **Accept**: tests — content list serializes `where`/`fields`/`sort`; documents `iterate()` follows `nextCursor` across ≥2 pages then stops on `null`.

### P3 — Write resources
- [ ] `content.create/update/delete`, scoped `collection(n).*`, `media.upload/uploadMany/bulkDelete`.
- **Accept**: tests — create sends JSON body + auth header; media sends `FormData` (no manual Content-Type); bulkDelete body `{fileIds}`.

### P4 — Auth
- [ ] `auth.register/login/logout`; `setToken`/`setApiKey` mutate client state; auto-store token on login/register.
- **Accept**: test — after `login()`, subsequent call carries `Authorization: Bearer <token>`.

### P5 — Query + pagination polish
- [ ] Finalize `ListOptions` → DSL edge cases (array values → `where[f][]`, JSON paths, `resolve_variables`).
- **Accept**: `query.test.ts` snapshot of representative option sets.

### P6 — Codegen CLI
- [ ] `codegen/cli.ts` (arg parse), `fetch-schema.ts` (live + `--from-config`), `field-map.ts`, `emit.ts`.
- [ ] Generic `createClient<TCollections>()` + `ScopedCollection<T>` typing wired.
- **Accept**: `codegen.test.ts` — given a sample `CollectionConfig[]`, `emit` produces expected interfaces (snapshot); `field-map` covers every `FieldType`.

### P7 — Docs + examples + tests polish
- [ ] `README.md`: install, quickstart (anon read, API-key write, JWT login), codegen usage, timestamp-units note.
- [ ] `www` docs page for the SDK.
- [ ] Ensure full vitest suite green; `type-check` clean.

---

## 8. Testing

**Primary = vitest** (`packages/sdk/__tests__/`). SDK is a client library — Playwright E2E is not the right tool; the wrapped endpoints already have E2E coverage in the core app.
- Mock `fetch` via `ClientOptions.fetch` injection (no network). Assert request URL, method, headers, body per resource method.
- Cover: query-DSL serialization, keyset `iterate()` multi-page, error mapping (http + network), media FormData shape, auth token storage, codegen field-map (all `FieldType`) + emit snapshot.
- **Live codegen smoke** (manual/optional): `cd my-sonicjs-app && npm run setup:db && npm run dev` (Conductor dir-derived port, **not** 8787), then `node packages/sdk/dist/cli.cjs codegen --url http://localhost:<port> --out /tmp/sonicjs.d.ts` → assert interfaces match seeded collections.
- **If** any repo-level E2E is added for the demo app, number **68+** (R11) and tag `@api`.

## 9. Verification commands
```bash
cd packages/sdk && npm run type-check && npm run build   # dual ESM/CJS + d.ts, cli built
npm test -- sdk                                          # vitest green
npm publish --dry-run --workspace=@sonicjs-cms/sdk       # verify files/exports before release
```

## 10. Risks / notes
- Login endpoint confirmed (`POST /auth/login` JSON, `routes/auth.ts:281`). Better Auth `/auth/sign-in/*` available for a lower-level passthrough later if needed.
- Two content surfaces coexist: `/api/content*` (ms, offset, legacy-shaped, document-backed) vs `/api/documents*` (seconds, keyset, modern). SDK exposes both, clearly labeled — matches the CMS's document-model transition.
- Zero runtime deps: no zod, no core at runtime. `@sonicjs-cms/core` is a **dev** dependency, **type-only** import.
- `File`/`Blob`/`FormData` assumed global (browser, Workers, Node ≥18). Document Node-18 caveat if targeting older runtimes.
- Before pinning tsup/vitest versions, read `packages/core/package.json` for the exact versions in use.

---

## 11. Demo App — Employee Directory

**Purpose**: Public-facing showcase deployed to Cloudflare Pages. Proves SDK + SonicJS edge speed to developers. Live URL becomes the SDK README "see it in action" link.

**Reference**: `/Users/lane/Dev/refs/edgecache-demo` — existing React SPA (not modified, reference only).

### Location
```
demos/employee-directory/
  package.json               # standalone; not in packages/* workspace
  vite.config.ts
  tsconfig.json
  index.html
  public/
  src/
    main.tsx
    App.tsx                  # root: layout, state, fetch orchestration
    sonicjs.d.ts             # codegen output (committed; regenerate via P8 checklist)
    components/
      EmployeeGrid.tsx       # card grid (name, dept, region, title, avatar, email, phone)
      Filters.tsx            # department / gender / region filter panel
      Pagination.tsx         # prev/next + page counter
      SpeedBadge.tsx         # execution time ms + cache hit/miss pill
      CacheToggle.tsx        # edge-cache URL ↔ origin URL toggle
      CodeSnippet.tsx        # syntax-highlighted SDK usage example
    lib/
      client.ts              # createClient({ url, apiKey }) — SDK import
      types.ts               # EmployeeRecord matching collection schema
  .dev.vars                  # VITE_CMS_URL, VITE_API_KEY (local dev, gitignored)
  wrangler.toml              # Cloudflare Pages config (static build)
```

### Employee collection schema (seed in SonicJS instance)
Collection name: `employees`

| Field | FieldType | Notes |
|---|---|---|
| `first_name` | string | required |
| `last_name` | string | required |
| `department` | select | enum: Engineering, Product, Design, Marketing, Sales, HR, Finance, Legal, Ops |
| `job_title` | string | |
| `region` | select | enum: US-East, US-West, EU-West, EU-North, APAC, LATAM |
| `gender` | select | enum: Male, Female, Non-binary |
| `email` | email | |
| `phone` | string | |
| `avatar_seed` | string | seed for robohash avatar URL (`https://robohash.org/<seed>?set=set4`) |

### Feature parity with edgecache-demo

| Feature | Implementation |
|---|---|
| Paginated employee grid | `sonic.collection('employees').list({ limit: 18, offset: page*18, where: { department: { equals: filter } } })` |
| Department filter | `where[department][equals]=<value>` via SDK |
| Region filter | `where[region][in][]=<values>` via SDK |
| Gender filter | `where[gender][equals]=<value>` via SDK |
| Edge-cache toggle | Two `createClient()` instances — edge URL vs origin URL; swap on toggle |
| Execution time | Measure `Date.now()` before/after SDK call; display in `SpeedBadge` |
| Cache hit detection | Read `sonicjs-source` response header — needs SDK to expose raw response headers (see §11.1) |
| SDK code snippet panel | `CodeSnippet` shows live code used to fetch current page (updates with active filters) |

### §11.1 — SDK header access (minor extension needed)

`HttpClient.request<T>` currently returns parsed JSON. Cache-hit detection requires `sonicjs-source` header. Extend `HttpClient` to support a `raw` mode:

```ts
// New method alongside request():
async requestWithHeaders<T>(method: string, path: string, init?: RequestInit & { query?; body?; form?; auth? }): Promise<{ data: T; headers: Headers }> {
  // ... same as request() but return { data: json, headers: res.headers }
}
```

Expose on resource level as optional opt-in (only demo uses it; normal callers unaffected):
```ts
// ContentResource (and CollectionsResource):
listWithMeta(o, auth?) → Promise<{ data: ListResponse<T>; headers: Headers }>
```

Alternatively: expose `HttpClient` as `client._http` escape hatch and let demo call `requestWithHeaders` directly. Decision: builder's call — simpler escape hatch is fine for demo.

### Environment / deployment

| Var | Dev (`.dev.vars`) | Prod (Cloudflare Pages env) |
|---|---|---|
| `VITE_CMS_URL` | `http://localhost:<conductor-port>` | production SonicJS instance URL |
| `VITE_API_KEY` | local dev API key | production API key (secret) |
| `VITE_EDGE_URL` | edge-cached CDN URL (optional second endpoint) | deployed Cloudflare Pages URL |

**Build**: `vite build` → `dist/` → Cloudflare Pages static deployment.
**Seed**: `scripts/seed-employees.ts` — Node script using SDK to batch-insert employees into SonicJS. Include `--count` flag (default 500 for local, 2M+ for production seeding).

### §11.2 — Seed script

```
demos/employee-directory/scripts/seed-employees.ts
```

```ts
import { createClient } from '@sonicjs-cms/sdk'
const sonic = createClient({ url: process.env.CMS_URL!, apiKey: process.env.CMS_API_KEY! })

async function seed(count = 500) {
  const DEPTS = ['Engineering','Product','Design','Marketing','Sales','HR','Finance','Legal','Ops']
  const REGIONS = ['US-East','US-West','EU-West','EU-North','APAC','LATAM']
  const GENDERS = ['Male','Female','Non-binary']
  for (let i = 0; i < count; i++) {
    await sonic.collection('employees').create({
      data: {
        first_name: FIRST[i % FIRST.length],
        last_name: LAST[i % LAST.length],
        department: DEPTS[i % DEPTS.length],
        job_title: TITLES[i % TITLES.length],
        region: REGIONS[i % REGIONS.length],
        gender: GENDERS[i % GENDERS.length],
        email: `user${i}@example.com`,
        phone: `+1-555-${String(i).padStart(4,'0')}`,
        avatar_seed: `employee-${i}`,
      }
    })
    if (i % 100 === 0) console.log(`${i}/${count}`)
  }
}
seed(Number(process.argv[2] ?? 500))
```

---

### P8 — Demo App: Employee Directory

Add to `## 7. Build phases`:

- [ ] Scaffold `demos/employee-directory/` — `package.json` (deps: react, react-dom; devDeps: vite, @vitejs/plugin-react, typescript, `@sonicjs-cms/sdk`: `workspace:*`), `vite.config.ts`, `tsconfig.json`, `index.html`.
- [ ] Run codegen against local instance → commit `src/sonicjs.d.ts` (or check in generated types directly if no local instance available — build builder can stub it).
- [ ] `src/lib/client.ts` — `createClient<Collections>({ url: import.meta.env.VITE_CMS_URL, apiKey: import.meta.env.VITE_API_KEY })`.
- [ ] `EmployeeGrid`, `Filters`, `Pagination`, `SpeedBadge`, `CacheToggle` components — port logic from `edgecache-demo/src/components/persons.jsx` + `sidebar.jsx`, rewrite in TypeScript using SDK.
- [ ] `CodeSnippet` — live-generated SDK snippet showing current `collection('employees').list(...)` call with active filters.
- [ ] Extend `HttpClient` / resource for header access (§11.1) — expose `sonicjs-source` to `SpeedBadge`.
- [ ] `scripts/seed-employees.ts` — batch insert, `--count` arg.
- [ ] `wrangler.toml` for Cloudflare Pages static deploy.
- [ ] `.dev.vars.example` committed; `.dev.vars` gitignored.
- [ ] `README.md` in `demos/employee-directory/` — local dev + seed + deploy instructions.
- **Accept**: `vite build` clean; `sonicjs-source` header shown in SpeedBadge; filters chain through SDK `where` DSL; CodeSnippet updates live; deploys to Cloudflare Pages.
