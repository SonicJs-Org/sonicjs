# @sonicjs-cms/sdk

Isomorphic TypeScript client + codegen CLI for the [SonicJS](https://sonicjs.com) headless CMS API.

## Install

```bash
npm install @sonicjs-cms/sdk
```

## Quickstart

```ts
import { createClient } from '@sonicjs-cms/sdk'

// Anon (public reads)
const sonic = createClient({ url: 'https://cms.example.com' })

// API key
const sonic = createClient({ url: 'https://cms.example.com', apiKey: 'sk_…' })

// JWT login
const sonic = createClient({ url: 'https://cms.example.com' })
await sonic.auth.login({ email: 'admin@example.com', password: '…' })
// token auto-stored; subsequent calls include Authorization: Bearer <token>
```

## Usage

```ts
// List content
const { data, meta } = await sonic.content.list({ limit: 20, status: 'published' })

// Filtered list
const { data } = await sonic.content.list({
  where: { collectionId: { equals: 'blog_posts' } },
  sort: 'created_at',
  dir: 'desc',
})

// Scoped collection (type-safe with codegen)
const { data } = await sonic.collection('blog_posts').list({ limit: 10 })

// Documents (keyset pagination, modern surface)
const page = await sonic.documents.list({ type: 'blog_posts', limit: 50 })
console.log(page.nextCursor) // { updatedAt, id } | null

// Iterate all documents
for await (const doc of sonic.documents.iterate({ type: 'blog_posts' })) {
  console.log(doc.id)
}

// Media
const { file } = await sonic.media.upload(fileBlob, { folder: 'avatars' })

// System
const { status } = await sonic.system.health()
```

## Timestamp units

- **Content API** (`sonic.content.*`): timestamps in **milliseconds**. Use `msToDate(n)`.
- **Documents API** (`sonic.documents.*`): timestamps in **seconds**. Use `secondsToDate(n)`.

```ts
import { secondsToDate, msToDate } from '@sonicjs-cms/sdk'
```

## Codegen

Generate per-collection TypeScript types from a live instance:

```bash
npx sonicjs-sdk codegen --url https://cms.example.com --api-key sk_… --out src/sonicjs.d.ts
```

Then use them for typed collection access:

```ts
import { createClient } from '@sonicjs-cms/sdk'
import type { Collections } from './sonicjs.d.ts'

const sonic = createClient<Collections>({ url, apiKey })
const { data } = await sonic.collection('blog_posts').list()
// data[0].data is typed as BlogPostsData
```

### Offline codegen (from local config)

```bash
npx sonicjs-sdk codegen --from-config ./collections.config.ts --out src/sonicjs.d.ts
```

## Error handling

All non-2xx responses throw `SonicError`:

```ts
import { SonicError } from '@sonicjs-cms/sdk'

try {
  await sonic.content.create({ collectionId: 'posts', title: 'Hello' })
} catch (e) {
  if (e instanceof SonicError) {
    console.log(e.status, e.code, e.message, e.details)
  }
}
```

Network failures throw `SonicError` with `status: 0` and `code: 'network'`.
