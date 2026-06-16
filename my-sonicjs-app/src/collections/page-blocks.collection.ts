import type { CollectionConfig } from "@sonicjs-cms/core";

export default {
  name: "page_blocks",
  displayName: "Page Blocks",
  slug: "page-blocks",
  description: "Page layouts built from block components",
  icon: "🧱",

  schema: {
    type: "object",
    properties: {
      title: {
        type: "string",
        title: "Title",
        required: true,
        maxLength: 200,
      },
      slug: {
        type: "slug",
        title: "URL Slug",
        required: true,
        maxLength: 200,
      },
      seo: {
        type: "object",
        title: "SEO",
        objectLayout: "flat",
        properties: {
          title: { type: "string", title: "SEO Title", maxLength: 60 },
          description: { type: "textarea", title: "Description", maxLength: 160 },
          keywords: { type: "string", title: "Keywords" },
        },
      },
      body: {
        type: "array",
        title: "Body Blocks",
        items: {
          type: "object",
          blocks: {
            hero: {
              label: "Hero",
              description: "Full-width hero section",
              properties: {
                heading: { type: "string", title: "Heading" },
                subheading: { type: "string", title: "Subheading" },
                ctaPrimary: {
                  type: "object",
                  title: "Primary CTA",
                  objectLayout: "nested",
                  collapsed: true,
                  properties: {
                    label: { type: "string", title: "Label" },
                    mode: {
                      type: "select",
                      title: "Mode",
                      enum: ["internal", "external"],
                      enumLabels: ["Internal", "External"],
                      default: "internal",
                    },
                    url: { type: "string", title: "URL" },
                    style: {
                      type: "select",
                      title: "Style",
                      enum: ["primary", "secondary", "outline"],
                      enumLabels: ["Primary", "Secondary", "Outline"],
                      default: "primary",
                    },
                  },
                },
                ctaSecondary: {
                  type: "object",
                  title: "Secondary CTA",
                  objectLayout: "nested",
                  collapsed: true,
                  properties: {
                    label: { type: "string", title: "Label" },
                    mode: {
                      type: "select",
                      title: "Mode",
                      enum: ["internal", "external"],
                      enumLabels: ["Internal", "External"],
                      default: "internal",
                    },
                    url: { type: "string", title: "URL" },
                    style: {
                      type: "select",
                      title: "Style",
                      enum: ["primary", "secondary", "outline"],
                      enumLabels: ["Primary", "Secondary", "Outline"],
                      default: "secondary",
                    },
                  },
                },
                backgroundImage: { type: "media", title: "Background Image" },
              },
            },
            text: {
              label: "Text",
              description: "Rich text content section",
              properties: {
                heading: { type: "string", title: "Heading" },
                body: { type: "textarea", title: "Body" },
              },
            },
          },
        },
      },
    },
    required: ["title", "slug"],
  },

  listFields: ["title", "slug"],
  searchFields: ["title"],
  defaultSort: "createdAt",
  defaultSortOrder: "desc",

  managed: true,
  isActive: true,
} satisfies CollectionConfig;
