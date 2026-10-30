/**
 * Seed script: default blog content
 *
 * Creates one published welcome blog post in the code-defined `blog_post`
 * content type. Idempotent: if the slug exists, the script skips it.
 *
 * Run from my-sonicjs-app/:
 *   npx tsx scripts/seed-documents.ts
 */

import { getPlatformProxy } from 'wrangler'
import { DocumentsService } from '../../packages/core/src/services/documents'
import { DocumentTypeRegistry } from '../../packages/core/src/services/document-type-registry'
import { bootstrapDocumentTypes } from '../../packages/core/src/services/document-types-seed'

const BLOG_POST_TYPE = 'blog_post'
const WELCOME_SLUG = 'welcome-to-sonicjs'

async function seed() {
  const { env, dispose } = await getPlatformProxy()
  const db = (env as any).DB as D1Database

  if (!db) {
    console.error('DB binding not found. Make sure wrangler.toml is configured.')
    process.exit(1)
  }

  try {
    console.log('Registering document types...')
    await bootstrapDocumentTypes(db)
    console.log('Document types ready')

    const registry = new DocumentTypeRegistry(db)
    const blogType = await registry.findById(BLOG_POST_TYPE)
    if (!blogType) {
      throw new Error(`${BLOG_POST_TYPE} type not found after registration`)
    }

    const existing = await db
      .prepare(
        `SELECT id FROM documents
         WHERE type_id = ? AND tenant_id = 'default' AND slug = ? AND is_current_draft = 1`
      )
      .bind(BLOG_POST_TYPE, WELCOME_SLUG)
      .first()

    if (existing) {
      console.log('Welcome blog post already exists')
      return
    }

    const documents = new DocumentsService(db, {
      queryableFields: blogType.queryableFields,
      typeSchemaVersion: blogType.schemaVersion,
      maxVersionsPerRoot: blogType.settings.maxVersionsPerRoot,
    })

    const doc = await documents.create(
      {
        typeId: BLOG_POST_TYPE,
        tenantId: 'default',
        locale: 'default',
        title: 'Welcome to SonicJS',
        slug: WELCOME_SLUG,
        data: {
          title: 'Welcome to SonicJS',
          slug: WELCOME_SLUG,
          excerpt: 'Start building with the Cloudflare-native SonicJS CMS.',
          content: '<p>Welcome to SonicJS. This first post confirms your default blog content is ready.</p>',
          author: 'SonicJS',
          status: 'published',
          difficulty: 'beginner',
          tags: 'welcome,sonicjs',
        },
        parentRootId: '',
        sortOrder: 0,
        visible: true,
        metadata: {},
        publishOnCreate: false,
      },
      'seed'
    )

    await documents.publish(doc.id, 'seed')

    console.log('Created welcome blog post')
    console.log(`  Type: ${BLOG_POST_TYPE}`)
    console.log(`  Slug: ${WELCOME_SLUG}`)
  } catch (error) {
    console.error('Error seeding documents:', error)
    await dispose()
    process.exit(1)
  }

  await dispose()
}

seed()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Seeding failed:', error)
    process.exit(1)
  })
