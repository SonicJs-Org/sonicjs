import type { CollectionConfig } from "@sonicjs-cms/core";

export default {
  name: "e2e_test",
  displayName: "E2E Test",
  slug: "e2e-test",
  description: "Comprehensive field-type coverage for E2E testing — not for production use",
  icon: "🧪",

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
      description: {
        type: "textarea",
        title: "Description",
        maxLength: 500,
      },
      count: {
        type: "number",
        title: "Count",
      },
      isActive: {
        type: "boolean",
        title: "Is Active",
      },
      publishDate: {
        type: "date",
        title: "Publish Date",
      },
      publishDatetime: {
        type: "datetime",
        title: "Publish Datetime",
      },
      author: {
        type: "user",
        title: "Author",
      },
      featuredImage: {
        type: "media",
        title: "Featured Image",
      },
      category: {
        type: "select",
        title: "Category",
        enum: ["news", "tutorial", "showcase"],
        enumLabels: ["News", "Tutorial", "Showcase"],
        default: "news",
      },
      displayMode: {
        type: "radio",
        title: "Display Mode",
        enum: ["list", "grid", "card"],
        enumLabels: ["List", "Grid", "Card"],
        default: "list",
      },
      metadata: {
        type: "json",
        title: "Metadata",
        helpText: "JSON object for arbitrary structured data",
      },
      richContent: {
        type: "lexical",
        title: "Rich Content",
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
            callToAction: {
              label: "Call to Action",
              description: "CTA section with button",
              properties: {
                title: { type: "string", title: "Title" },
                body: { type: "textarea", title: "Body" },
                buttonLabel: { type: "string", title: "Button Label" },
                buttonUrl: { type: "string", title: "Button URL" },
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

  access: {
    public: ['read'],
  },
} satisfies CollectionConfig;
