import type { CollectionConfig } from '@sonicjs-cms/core'

const pageBlocksCollection: CollectionConfig = {
  name: 'page_blocks',
  displayName: 'Page Blocks',
  description: 'Pages with flexible content blocks',
  managed: true,
  schema: {
    type: 'object',
    required: ['title', 'slug'],
    properties: {
      title: {
        type: 'string',
        title: 'Title',
        required: true,
        minLength: 3,
      },
      slug: {
        type: 'slug',
        title: 'Slug',
        required: true,
      },
      featuredPage: {
        type: 'reference',
        title: 'Featured Page',
        collection: ['page_blocks', 'pages', 'blog_posts'],
      },
      seo: {
        type: 'object',
        title: 'SEO',
        properties: {
          title: { type: 'string', title: 'SEO title' },
          description: { type: 'textarea', title: 'SEO description' },
        },
      },
      team: {
        type: 'object',
        title: 'Team',
        properties: {
          heading: { type: 'string', title: 'Heading' },
          members: {
            type: 'array',
            title: 'Members',
            itemTitle: 'Member',
            items: {
              type: 'object',
              properties: {
                name: { type: 'string', title: 'Name', required: true },
                role: { type: 'string', title: 'Role' },
                photo: { type: 'media', title: 'Photo' },
              },
            },
          },
        },
      },

      body: {
        type: 'array',
        title: 'Content Blocks',
        items: {
          type: 'object',
          discriminator: 'blockType',
          blocks: {
            text: {
              label: 'Text',
              properties: {
                heading: { type: 'string', title: 'Heading', required: true },
                body: { type: 'textarea', title: 'Body text', required: true },
              },
            },
            longText: {
              label: 'Long Text',
              properties: {
                body: { type: 'textarea', required: true },
              },
            },
            imageText: {
              label: 'Image + Text',
              properties: {
                title: { type: 'string', title: 'Title', required: true },
                body: { type: 'textarea', title: 'Body text', required: true },
                image: { type: 'media', title: 'Image', required: true },
              },
            },
            callToAction: {
              label: 'Call To Action',
              properties: {
                title: { type: 'string', title: 'Heading', required: true },
                body: { type: 'textarea', title: 'Body text', required: true },
                buttonLabel: { type: 'string', title: 'Button label', required: true },
                buttonUrl: { type: 'url', title: 'Button link', required: true },
              },
            },
          },
        },
      },
    },
  },
}

export default pageBlocksCollection
