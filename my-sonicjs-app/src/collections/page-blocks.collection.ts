import type { CollectionConfig } from '@sonicjs-cms/core'

const heroBlock = {
  label: 'Hero',
  properties: {
    heading: { type: 'string', title: 'Heading', required: true },
    height: {
      type: 'radio',
      title: 'Height',
      enum: ['small', 'medium', 'full'],
      enumLabels: ['Small', 'Medium', 'Full'],
      default: 'medium',
      inline: true,
    },
    subheading: { type: 'textarea', title: 'Subheading', maxLength: 600 },
    image: { type: 'media', title: 'Background/Image' },
    imageAlt: { type: 'string', title: 'Image Alt' },

    ctaPrimary: {
      title: 'Primary CTA',
      type: 'object',
      properties: {
        label: { type: 'string', title: 'Label' },
        link: {
          title: 'Link',
          type: 'object',
          properties: {
            mode: {
              type: 'select',
              title: 'Link type',
              enum: ['none', 'internal', 'external'],
              enumLabels: ['None', 'Internal', 'External'],
              default: 'none',
            },
            reference: { type: 'reference', title: 'Internal reference', collection: 'pages' },
            url: { type: 'url', title: 'External URL' },
          },
        },
        style: {
          type: 'select',
          title: 'Button style',
          enum: ['primary', 'secondary'],
          enumLabels: ['Primary', 'Secondary'],
          default: 'primary',
        },
      },
    },
    ctaSecondary: {
      title: 'Secondary CTA',
      type: 'object',
      properties: {
        label: { type: 'string', title: 'Label' },
        link: {
          title: 'Link',
          type: 'object',
          properties: {
            mode: {
              type: 'select',
              title: 'Type',
              enum: ['none', 'internal', 'external'],
              enumLabels: ['None', 'Internal', 'External'],
              default: 'none',
            },
            reference: { type: 'reference', title: 'Internal reference', collection: 'pages' },
            url: { type: 'url', title: 'External URL' },
          },
        },
        style: {
          type: 'select',
          title: 'Button style',
          enum: ['primary', 'secondary'],
          enumLabels: ['Primary', 'Secondary'],
          default: 'primary',
        },
      },
    },
  },
}

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
        objectLayout: 'flat',
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
            items: {
              type: 'object',
              properties: {
                name: { type: 'string', title: 'Name', required: true },
                role: { type: 'string', title: 'Role' },
                photo: { type: 'media', title: 'Photo' },
                children: {
                  type: 'array',
                  title: 'Children',
                  items: {
                    type: 'object',
                    properties: {
                      name: { type: 'string', title: 'Name', required: true },
                    },
                  },
                },
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
            hero: heroBlock,
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
