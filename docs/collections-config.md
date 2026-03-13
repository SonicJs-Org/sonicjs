# Collections Configuration Guide

Comprehensive guide to defining, managing, and using collections in SonicJS.

## Table of Contents

1. [Collection System Architecture](#collection-system-architecture)
2. [Field Types Reference](#field-types-reference)
3. [CollectionConfig Interface](#collectionconfig-interface)
4. [Collection Configuration](#collection-configuration)
5. [Collection Sync Process](#collection-sync-process)
6. [Creating Custom Collections](#creating-custom-collections)
7. [Validation and Schema Enforcement](#validation-and-schema-enforcement)
8. [Field Type Examples](#field-type-examples)
9. [Advanced Features](#advanced-features)
10. [Using Collections in Routes](#using-collections-in-routes)
11. [Best Practices](#best-practices)

## Collection System Architecture

SonicJS provides a powerful, type-safe collection system that allows you to define content schemas in code. The architecture consists of several key components:

### Core Components

```
src/types/collection-config.ts       # TypeScript type definitions
src/services/collection-loader.ts    # Loads collection configs from disk
src/services/collection-sync.ts      # Syncs configs to database
src/collections/*.collection.ts      # Your collection definitions
```

### How It Works

1. **Config Loading**: On startup, the system scans `src/collections/` for `*.collection.ts` files
2. **Validation**: Each configuration is validated against the `CollectionConfig` interface
3. **Sync to Database**: Valid configs are synced to the `collections` table
4. **Schema Enforcement**: Content created in these collections is validated against their schemas
5. **API Generation**: Collections automatically become available via REST API endpoints

### Two Types of Collections

**Config-Managed Collections:**
- Defined in TypeScript files (`src/collections/*.collection.ts`)
- Version controlled with your codebase
- Automatically synced on app startup
- Locked from editing in the admin UI (marked with "Config" badge)
- Type-safe with IDE autocomplete

**UI-Created Collections:**
- Created and edited through the admin interface
- Stored directly in the database
- Not version controlled
- Fully editable in the UI
- Great for rapid prototyping

Both types work seamlessly together and use the same underlying storage and API systems.

## Field Types Reference

SonicJS supports 30+ field types for building rich content schemas:

### Text Fields
| Type | Description | Use Case |
|------|-------------|----------|
| `string` | Single-line text input | Titles, names, short text |
| `textarea` | Multi-line plain text | Descriptions, notes, long text |
| `email` | Email with validation | Contact emails, author info |
| `url` | URL with validation | Links, external resources |
| `slug` | URL-friendly identifier | Page URLs, SEO paths |
| `color` | Color picker | Theme colors, UI customization |

### Numbers and Dates
| Type | Description | Use Case |
|------|-------------|----------|
| `number` | Numeric input | Prices, quantities, ratings |
| `date` | Date picker (no time) | Birthdays, deadlines |
| `datetime` | Date and time picker | Publish dates, events |

### Rich Content
| Type | Description | Use Case |
|------|-------------|----------|
| `richtext` | WYSIWYG HTML editor | Blog posts, articles, formatted content |
| `markdown` | Markdown editor | Documentation, technical content |
| `json` | JSON editor | Structured data, API responses |

`markdown` is the canonical field type for the EasyMDE-backed markdown editor. Legacy aliases `mdxeditor` and `easymde` are still accepted for compatibility.

### Selections
| Type | Description | Use Case |
|------|-------------|----------|
| `select` | Dropdown (single choice) | Categories, status fields |
| `multiselect` | Dropdown (multiple choices) | Tags, multiple categories |
| `radio` | Radio buttons | Status, visibility options |
| `checkbox` | Boolean checkbox | Feature toggles, flags |

### Media and Files
| Type | Description | Use Case |
|------|-------------|----------|
| `media` | Image/media picker | Featured images, avatars |
| `file` | File upload | PDFs, documents, downloads |

### Relationships
| Type | Description | Use Case |
|------|-------------|----------|
| `reference` | Reference to another collection | Authors, related posts, categories |

### Structured Data
| Type | Description | Use Case |
|------|-------------|----------|
| `object` | Nested object with properties | SEO settings, address, metadata |
| `array` | Array of items | Image galleries, FAQs, specs |

## CollectionConfig Interface

The complete TypeScript interface for collection configurations:

```typescript
interface CollectionConfig {
  /**
   * Unique machine name (lowercase, underscores only)
   * Examples: 'blog_posts', 'products', 'team_members'
   */
  name: string

  /**
   * Human-readable display name
   * Examples: 'Blog Posts', 'Products', 'Team Members'
   */
  displayName: string

  /**
   * Optional description of the collection
   */
  description?: string

  /**
   * JSON schema definition for content structure
   */
  schema: CollectionSchema

  /**
   * If true, collection is managed by config and locked in UI
   * Default: true
   */
  managed?: boolean

  /**
   * If true, collection is active and available
   * Default: true
   */
  isActive?: boolean

  /**
   * Optional icon name for admin UI
   */
  icon?: string

  /**
   * Optional color (hex code) for admin UI
   */
  color?: string

  /**
   * Default field to sort by
   */
  defaultSort?: string

  /**
   * Default sort order
   */
  defaultSortOrder?: 'asc' | 'desc'

  /**
   * Fields to show in list view
   */
  listFields?: string[]

  /**
   * Fields to include in search
   */
  searchFields?: string[]

  /**
   * Additional custom metadata
   */
  metadata?: Record<string, any>
}
```

### CollectionSchema Interface

```typescript
interface CollectionSchema {
  type: 'object'
  properties: Record<string, FieldConfig>
  required?: string[]
}
```

### FieldConfig Interface

```typescript
interface FieldConfig {
  type: FieldType
  title?: string              // Display label
  description?: string        // Help text below label
  required?: boolean          // Make field required
  default?: any              // Default value
  placeholder?: string        // Input placeholder
  helpText?: string          // Inline help tooltip

  // Validation
  min?: number               // Min number value
  max?: number               // Max number value
  minLength?: number         // Min string length
  maxLength?: number         // Max string length
  pattern?: string           // Regex pattern

  // Select/Radio/Multiselect
  enum?: string[]           // Available options
  enumLabels?: string[]     // Display labels for options

  // Reference fields
  collection?: string       // Target collection name

  // Array fields
  items?: FieldConfig       // Type of array items

  // Object fields
  properties?: Record<string, FieldConfig>

  // UI hints
  format?: string
  widget?: string

  // Conditional display
  dependsOn?: string        // Field this depends on
  showWhen?: any           // Value to trigger showing
}
```

## Collection Configuration

### Basic Example

Here's a minimal collection configuration:

```typescript
// src/collections/events.collection.ts
import { CollectionConfig } from '../types/collection-config'

const eventsCollection: CollectionConfig = {
  name: 'events',
  displayName: 'Events',
  description: 'Community events and meetups',

  schema: {
    type: 'object',
    properties: {
      title: {
        type: 'string',
        title: 'Event Title',
        required: true,
        minLength: 3,
        maxLength: 200
      },
      date: {
        type: 'datetime',
        title: 'Event Date',
        required: true
      },
      location: {
        type: 'string',
        title: 'Location'
      }
    },
    required: ['title', 'date']
  },

  managed: true,
  isActive: true
}

export default eventsCollection
```

### Real-World Examples

#### Blog Posts Collection

Complete example from `src/collections/blog-posts.collection.ts`:

```typescript
import { CollectionConfig } from '../types/collection-config'

const blogPostsCollection: CollectionConfig = {
  name: 'blog_posts',
  displayName: 'Blog Posts',
  description: 'Articles and blog content for the website',
  icon: 'document-text',
  color: '#3B82F6',

  schema: {
    type: 'object',
    properties: {
      title: {
        type: 'string',
        title: 'Title',
        description: 'The title of the blog post',
        required: true,
        minLength: 3,
        maxLength: 200,
        placeholder: 'Enter blog post title...'
      },
      slug: {
        type: 'slug',
        title: 'URL Slug',
        description: 'Auto-generated URL-friendly slug',
        helpText: 'Leave blank to auto-generate from title'
      },
      excerpt: {
        type: 'textarea',
        title: 'Excerpt',
        description: 'Short summary of the post',
        maxLength: 300,
        placeholder: 'Brief description for previews and SEO...'
      },
      content: {
        type: 'richtext',
        title: 'Content',
        description: 'Main blog post content',
        required: true
      },
      featuredImage: {
        type: 'media',
        title: 'Featured Image',
        description: 'Main image for the blog post',
        helpText: 'Recommended size: 1200x630px'
      },
      author: {
        type: 'reference',
        title: 'Author',
        description: 'Post author',
        collection: 'users',
        required: true
      },
      category: {
        type: 'select',
        title: 'Category',
        description: 'Blog post category',
        enum: ['technology', 'design', 'business', 'development', 'marketing', 'other'],
        enumLabels: ['Technology', 'Design', 'Business', 'Development', 'Marketing', 'Other'],
        default: 'other'
      },
      tags: {
        type: 'multiselect',
        title: 'Tags',
        description: 'Keywords and topics',
        enum: ['javascript', 'typescript', 'cloudflare', 'cms', 'api', 'tutorial', 'guide', 'news'],
        enumLabels: ['JavaScript', 'TypeScript', 'Cloudflare', 'CMS', 'API', 'Tutorial', 'Guide', 'News']
      },
      publishDate: {
        type: 'datetime',
        title: 'Publish Date',
        description: 'When to publish this post',
        default: new Date().toISOString()
      },
      status: {
        type: 'select',
        title: 'Status',
        description: 'Publication status',
        enum: ['draft', 'published', 'archived'],
        enumLabels: ['Draft', 'Published', 'Archived'],
        default: 'draft',
        required: true
      },
      featured: {
        type: 'checkbox',
        title: 'Featured Post',
        description: 'Show this post in featured sections',
        default: false
      },
      allowComments: {
        type: 'checkbox',
        title: 'Allow Comments',
        description: 'Enable commenting on this post',
        default: true
      },
      seo: {
        type: 'object',
        title: 'SEO Settings',
        description: 'Search engine optimization settings',
        properties: {
          metaTitle: {
            type: 'string',
            title: 'Meta Title',
            maxLength: 60,
            helpText: 'Leave blank to use post title'
          },
          metaDescription: {
            type: 'textarea',
            title: 'Meta Description',
            maxLength: 160,
            helpText: 'Leave blank to use excerpt'
          },
          ogImage: {
            type: 'media',
            title: 'Social Share Image',
            helpText: 'Image for social media sharing (defaults to featured image)'
          }
        }
      }
    },
    required: ['title', 'content', 'status']
  },

  managed: true,
  isActive: true,
  defaultSort: 'publishDate',
  defaultSortOrder: 'desc',
  listFields: ['title', 'author', 'category', 'status', 'publishDate'],
  searchFields: ['title', 'excerpt', 'content']
}

export default blogPostsCollection
```

#### Products Collection

E-commerce example from `src/collections/products.collection.ts`:

```typescript
import { CollectionConfig } from '../types/collection-config'

const productsCollection: CollectionConfig = {
  name: 'products',
  displayName: 'Products',
  description: 'Product catalog and inventory',
  icon: 'shopping-bag',
  color: '#8B5CF6',

  schema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        title: 'Product Name',
        required: true,
        minLength: 3,
        maxLength: 200
      },
      slug: {
        type: 'slug',
        title: 'URL Slug',
        required: true
      },
      description: {
        type: 'richtext',
        title: 'Description',
        required: true
      },
      shortDescription: {
        type: 'textarea',
        title: 'Short Description',
        maxLength: 200,
        helpText: 'Brief description for product cards and previews'
      },
      sku: {
        type: 'string',
        title: 'SKU',
        description: 'Stock Keeping Unit',
        required: true,
        pattern: '^[A-Z0-9-]+$',
        helpText: 'Unique product identifier (e.g., PROD-001)'
      },
      price: {
        type: 'number',
        title: 'Price',
        description: 'Product price in USD',
        required: true,
        min: 0
      },
      compareAtPrice: {
        type: 'number',
        title: 'Compare at Price',
        description: 'Original price (for showing discounts)',
        min: 0,
        helpText: 'Leave blank if not on sale'
      },
      inventory: {
        type: 'object',
        title: 'Inventory',
        properties: {
          trackInventory: {
            type: 'checkbox',
            title: 'Track Inventory',
            default: true
          },
          stock: {
            type: 'number',
            title: 'Stock Quantity',
            min: 0,
            default: 0
          },
          lowStockThreshold: {
            type: 'number',
            title: 'Low Stock Alert',
            description: 'Alert when stock falls below this number',
            min: 0,
            default: 10
          }
        }
      },
      images: {
        type: 'array',
        title: 'Product Images',
        description: 'Upload product photos',
        items: {
          type: 'media',
          title: 'Image'
        }
      },
      category: {
        type: 'select',
        title: 'Category',
        enum: ['electronics', 'clothing', 'books', 'home', 'sports', 'toys', 'other'],
        enumLabels: ['Electronics', 'Clothing', 'Books', 'Home & Garden', 'Sports', 'Toys', 'Other'],
        required: true
      },
      tags: {
        type: 'multiselect',
        title: 'Tags',
        enum: ['new', 'featured', 'sale', 'bestseller', 'limited'],
        enumLabels: ['New Arrival', 'Featured', 'On Sale', 'Bestseller', 'Limited Edition']
      },
      specifications: {
        type: 'array',
        title: 'Specifications',
        description: 'Product specifications and features',
        items: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              title: 'Specification Name',
              placeholder: 'e.g., Dimensions, Weight, Material'
            },
            value: {
              type: 'string',
              title: 'Value',
              placeholder: 'e.g., 10x5x3 inches'
            }
          }
        }
      },
      status: {
        type: 'select',
        title: 'Status',
        enum: ['draft', 'active', 'archived', 'out-of-stock'],
        enumLabels: ['Draft', 'Active', 'Archived', 'Out of Stock'],
        default: 'draft',
        required: true
      },
      featured: {
        type: 'checkbox',
        title: 'Featured Product',
        default: false
      },
      seo: {
        type: 'object',
        title: 'SEO Settings',
        properties: {
          metaTitle: {
            type: 'string',
            title: 'Meta Title',
            maxLength: 60
          },
          metaDescription: {
            type: 'textarea',
            title: 'Meta Description',
            maxLength: 160
          }
        }
      }
    },
    required: ['name', 'slug', 'sku', 'price', 'category', 'status']
  },

  managed: true,
  isActive: true,
  defaultSort: 'name',
  defaultSortOrder: 'asc',
  listFields: ['name', 'sku', 'price', 'category', 'status'],
  searchFields: ['name', 'description', 'sku']
}

export default productsCollection
```

#### Pages Collection

Static pages example from `src/collections/pages.collection.ts`:

```typescript
import { CollectionConfig } from '../types/collection-config'

const pagesCollection: CollectionConfig = {
  name: 'pages',
  displayName: 'Pages',
  description: 'Static content pages like About, Contact, etc.',
  icon: 'document',
  color: '#10B981',

  schema: {
    type: 'object',
    properties: {
      title: {
        type: 'string',
        title: 'Page Title',
        description: 'The title of the page',
        required: true,
        minLength: 3,
        maxLength: 200
      },
      slug: {
        type: 'slug',
        title: 'URL Slug',
        description: 'URL-friendly page identifier',
        required: true,
        helpText: 'e.g., "about-us", "contact", "privacy-policy"'
      },
      content: {
        type: 'richtext',
        title: 'Page Content',
        description: 'Main page content',
        required: true
      },
      layout: {
        type: 'select',
        title: 'Page Layout',
        description: 'Choose the layout template',
        enum: ['default', 'full-width', 'sidebar-left', 'sidebar-right', 'landing'],
        enumLabels: ['Default', 'Full Width', 'Left Sidebar', 'Right Sidebar', 'Landing Page'],
        default: 'default'
      },
      showInMenu: {
        type: 'checkbox',
        title: 'Show in Navigation',
        description: 'Display this page in the main navigation menu',
        default: false
      },
      menuOrder: {
        type: 'number',
        title: 'Menu Order',
        description: 'Order in navigation menu (lower numbers appear first)',
        min: 0,
        default: 0,
        dependsOn: 'showInMenu',
        showWhen: true
      },
      parentPage: {
        type: 'reference',
        title: 'Parent Page',
        description: 'Create a page hierarchy',
        collection: 'pages',
        helpText: 'Optional - leave blank for top-level pages'
      },
      status: {
        type: 'select',
        title: 'Status',
        description: 'Publication status',
        enum: ['draft', 'published', 'archived'],
        enumLabels: ['Draft', 'Published', 'Archived'],
        default: 'draft',
        required: true
      },
      seo: {
        type: 'object',
        title: 'SEO Settings',
        properties: {
          metaTitle: {
            type: 'string',
            title: 'Meta Title',
            maxLength: 60
          },
          metaDescription: {
            type: 'textarea',
            title: 'Meta Description',
            maxLength: 160
          },
          ogImage: {
            type: 'media',
            title: 'Social Share Image'
          },
          noIndex: {
            type: 'checkbox',
            title: 'No Index',
            description: 'Prevent search engines from indexing this page',
            default: false
          }
        }
      }
    },
    required: ['title', 'slug', 'content', 'status']
  },

  managed: true,
  isActive: true,
  defaultSort: 'menuOrder',
  defaultSortOrder: 'asc',
  listFields: ['title', 'slug', 'status', 'showInMenu'],
  searchFields: ['title', 'content']
}

export default pagesCollection
```

## Collection Sync Process

The collection sync process runs automatically on application startup and can also be triggered manually.

### Automatic Sync on Startup

From `src/services/collection-sync.ts`:

```typescript
/**
 * Sync all collection configurations to the database
 */
export async function syncCollections(db: D1Database): Promise<CollectionSyncResult[]> {
  console.log('🔄 Starting collection sync...')

  const results: CollectionSyncResult[] = []
  const configs = await loadCollectionConfigs()

  if (configs.length === 0) {
    console.log('⚠️  No collection configurations found')
    return results
  }

  for (const config of configs) {
    const result = await syncCollection(db, config)
    results.push(result)
  }

  const created = results.filter(r => r.status === 'created').length
  const updated = results.filter(r => r.status === 'updated').length
  const unchanged = results.filter(r => r.status === 'unchanged').length
  const errors = results.filter(r => r.status === 'error').length

  console.log(`✅ Collection sync complete: ${created} created, ${updated} updated, ${unchanged} unchanged, ${errors} errors`)

  return results
}
```

### Sync Workflow

1. **Load Configurations**: System scans `src/collections/*.collection.ts`
2. **Validation**: Each config is validated for:
   - Required fields (name, displayName, schema)
   - Naming conventions (lowercase, underscores)
   - Schema structure
   - Field type validity
   - Reference and select field requirements
3. **Database Check**: Checks if collection already exists
4. **Create or Update**:
   - New collections are inserted with `managed = 1`
   - Existing collections are updated if schema/settings changed
   - Unchanged collections are skipped
5. **Cleanup**: Removed configs are marked `is_active = 0` (not deleted)

### Sync Result Types

```typescript
interface CollectionSyncResult {
  name: string
  status: 'created' | 'updated' | 'unchanged' | 'error'
  message?: string
  error?: string
}
```

### Console Output Example

```
🔄 Starting collection sync...
  ✓ Loaded collection config: blog_posts
  ✓ Loaded collection config: pages
  ✓ Loaded collection config: products
Loaded 3 collection configuration(s)
  ✓ Created collection: blog_posts
  ✓ Updated collection: pages
✅ Collection sync complete: 1 created, 1 updated, 1 unchanged, 0 errors
```

## Creating Custom Collections

### Step-by-Step Guide

#### Step 1: Create the Collection File

Create a new file in `src/collections/` following the naming convention `{name}.collection.ts`:

```bash
touch src/collections/team-members.collection.ts
```

#### Step 2: Define the Collection

```typescript
// src/collections/team-members.collection.ts
import { CollectionConfig } from '../types/collection-config'

const teamMembersCollection: CollectionConfig = {
  name: 'team_members',
  displayName: 'Team Members',
  description: 'Company team members and staff',
  icon: 'users',
  color: '#F59E0B',

  schema: {
    type: 'object',
    properties: {
      fullName: {
        type: 'string',
        title: 'Full Name',
        required: true,
        minLength: 2,
        maxLength: 100
      },
      role: {
        type: 'string',
        title: 'Job Title',
        required: true,
        placeholder: 'e.g., Senior Developer, Product Manager'
      },
      bio: {
        type: 'textarea',
        title: 'Biography',
        maxLength: 500,
        placeholder: 'Brief professional biography...'
      },
      photo: {
        type: 'media',
        title: 'Profile Photo',
        helpText: 'Recommended: square image, at least 400x400px'
      },
      email: {
        type: 'email',
        title: 'Work Email',
        required: true
      },
      socialLinks: {
        type: 'object',
        title: 'Social Media',
        properties: {
          linkedin: {
            type: 'url',
            title: 'LinkedIn Profile'
          },
          twitter: {
            type: 'url',
            title: 'Twitter/X Handle'
          },
          github: {
            type: 'url',
            title: 'GitHub Profile'
          }
        }
      },
      department: {
        type: 'select',
        title: 'Department',
        enum: ['engineering', 'product', 'design', 'marketing', 'sales', 'operations'],
        enumLabels: ['Engineering', 'Product', 'Design', 'Marketing', 'Sales', 'Operations'],
        required: true
      },
      startDate: {
        type: 'date',
        title: 'Start Date',
        description: 'When they joined the company'
      },
      featured: {
        type: 'checkbox',
        title: 'Featured Team Member',
        description: 'Show on homepage',
        default: false
      },
      displayOrder: {
        type: 'number',
        title: 'Display Order',
        min: 0,
        default: 0,
        helpText: 'Lower numbers appear first'
      }
    },
    required: ['fullName', 'role', 'email', 'department']
  },

  managed: true,
  isActive: true,
  defaultSort: 'displayOrder',
  defaultSortOrder: 'asc',
  listFields: ['fullName', 'role', 'department', 'email'],
  searchFields: ['fullName', 'role', 'bio']
}

export default teamMembersCollection
```

#### Step 3: Test the Configuration

Start your dev server:

```bash
npm run dev
```

Look for the sync output:

```
🔄 Starting collection sync...
  ✓ Loaded collection config: team_members
  ✓ Created collection: team_members
✅ Collection sync complete: 1 created, 0 updated, 0 unchanged, 0 errors
```

#### Step 4: Verify in Admin UI

1. Navigate to `/admin/collections`
2. Find your collection with the "Config" badge
3. Try creating content items

## Validation and Schema Enforcement

### Collection-Level Validation

From `src/services/collection-loader.ts`:

```typescript
export function validateCollectionConfig(config: CollectionConfig): {
  valid: boolean
  errors: string[]
} {
  const errors: string[] = []

  // Required fields
  if (!config.name) {
    errors.push('Collection name is required')
  } else if (!/^[a-z0-9_]+$/.test(config.name)) {
    errors.push('Collection name must contain only lowercase letters, numbers, and underscores')
  }

  if (!config.displayName) {
    errors.push('Display name is required')
  }

  if (!config.schema) {
    errors.push('Schema is required')
  } else {
    // Validate schema structure
    if (config.schema.type !== 'object') {
      errors.push('Schema type must be "object"')
    }

    if (!config.schema.properties || typeof config.schema.properties !== 'object') {
      errors.push('Schema must have properties')
    }

    // Validate field types
    for (const [fieldName, fieldConfig] of Object.entries(config.schema.properties || {})) {
      if (!fieldConfig.type) {
        errors.push(`Field "${fieldName}" is missing type`)
      }

      // Validate reference fields
      if (fieldConfig.type === 'reference' && !fieldConfig.collection) {
        errors.push(`Reference field "${fieldName}" is missing collection property`)
      }

      // Validate select fields
      if (['select', 'multiselect', 'radio'].includes(fieldConfig.type) && !fieldConfig.enum) {
        errors.push(`Select field "${fieldName}" is missing enum options`)
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  }
}
```

### Naming Convention Rules

**Collection Names:**
- Must be lowercase
- Can contain letters, numbers, and underscores
- Should be descriptive and plural
- Pattern: `/^[a-z0-9_]+$/`

**Examples:**
```typescript
// ✅ Valid names
'blog_posts'
'team_members'
'product_categories'
'faqs'

// ❌ Invalid names
'BlogPosts'      // No camelCase
'blog-posts'     // No hyphens
'blog posts'     // No spaces
'BP'             // Too short/unclear
```

### Field-Level Validation

Each field type has specific validation requirements:

**Reference Fields:**
```typescript
{
  type: 'reference',
  collection: 'users'  // Required!
}
```

**Select/Multiselect/Radio:**
```typescript
{
  type: 'select',
  enum: ['option1', 'option2'],      // Required!
  enumLabels: ['Option 1', 'Option 2']  // Optional
}
```

**String Fields with Patterns:**
```typescript
{
  type: 'string',
  pattern: '^[A-Z0-9-]+$',  // Regex validation
  minLength: 3,
  maxLength: 50
}
```

**Number Fields:**
```typescript
{
  type: 'number',
  min: 0,
  max: 100
}
```

## Field Type Examples

### String Field

```typescript
title: {
  type: 'string',
  title: 'Title',
  description: 'The page title',
  required: true,
  minLength: 3,
  maxLength: 200,
  placeholder: 'Enter title...',
  helpText: 'Keep it concise and descriptive'
}
```

### Number Field

```typescript
price: {
  type: 'number',
  title: 'Price (USD)',
  description: 'Product price in dollars',
  required: true,
  min: 0,
  max: 999999.99,
  default: 0,
  placeholder: '0.00'
}
```

### Boolean/Checkbox Field

```typescript
published: {
  type: 'checkbox',
  title: 'Published',
  description: 'Make this content publicly visible',
  default: false,
  helpText: 'You can always unpublish later'
}
```

### Date Field

```typescript
eventDate: {
  type: 'date',
  title: 'Event Date',
  description: 'When the event takes place',
  required: true
}
```

### DateTime Field

```typescript
publishDate: {
  type: 'datetime',
  title: 'Publish Date',
  description: 'When to publish this content',
  default: new Date().toISOString(),
  helpText: 'Schedule for future publication'
}
```

### RichText Field

```typescript
content: {
  type: 'richtext',
  title: 'Content',
  description: 'Main article content',
  required: true,
  placeholder: 'Start writing...'
}
```

### Markdown Field

```typescript
documentation: {
  type: 'markdown',
  title: 'Documentation',
  description: 'Technical documentation in Markdown',
  placeholder: '# Heading\n\nYour content here...'
}
```

### JSON Field

```typescript
metadata: {
  type: 'json',
  title: 'Custom Metadata',
  description: 'Additional structured data',
  placeholder: '{\n  "key": "value"\n}'
}
```

### Array Field (Simple)

```typescript
tags: {
  type: 'array',
  title: 'Tags',
  description: 'Content tags',
  items: {
    type: 'string',
    placeholder: 'Enter tag...'
  }
}
```

### Array Field (Complex)

```typescript
faqs: {
  type: 'array',
  title: 'FAQs',
  description: 'Frequently asked questions',
  items: {
    type: 'object',
    properties: {
      question: {
        type: 'string',
        title: 'Question',
        required: true
      },
      answer: {
        type: 'textarea',
        title: 'Answer',
        required: true
      },
      category: {
        type: 'select',
        title: 'Category',
        enum: ['general', 'technical', 'billing'],
        enumLabels: ['General', 'Technical', 'Billing']
      }
    }
  }
}
```

### Blocks Field (Repeater)

Blocks are modeled as an `array` whose `items` define a discriminator and a map of block definitions. Each block is stored as an object with the discriminator key plus its fields.

```typescript
contentBlocks: {
  type: 'array',
  title: 'Content Blocks',
  items: {
    type: 'object',
    discriminator: 'blockType',
    blocks: {
      textAndImage: {
        label: 'Text + Image',
        properties: {
          heading: { type: 'string', required: true },
          body: { type: 'richtext', required: true },
          image: { type: 'media' }
        }
      },
      team: {
        label: 'Team',
        properties: {
          title: { type: 'string' },
          members: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                name: { type: 'string', required: true },
                role: { type: 'string' },
                photo: { type: 'media' }
              }
            }
          }
        }
      }
    }
  }
}
```

Note: blocks are currently available for code-based collections; the collection builder UI does not yet expose block definitions.

### Object Field

```typescript
seo: {
  type: 'object',
  title: 'SEO Settings',
  description: 'Search engine optimization',
  properties: {
    metaTitle: {
      type: 'string',
      title: 'Meta Title',
      maxLength: 60,
      helpText: 'Optimal length: 50-60 characters'
    },
    metaDescription: {
      type: 'textarea',
      title: 'Meta Description',
      maxLength: 160,
      helpText: 'Optimal length: 150-160 characters'
    },
    keywords: {
      type: 'array',
      title: 'Keywords',
      items: {
        type: 'string'
      }
    },
    ogImage: {
      type: 'media',
      title: 'Open Graph Image',
      helpText: 'Recommended: 1200x630px'
    },
    noIndex: {
      type: 'checkbox',
      title: 'No Index',
      default: false
    }
  }
}
```

### Reference Field

```typescript
author: {
  type: 'reference',
  title: 'Author',
  description: 'Content author',
  collection: 'users',  // Must reference existing collection
  required: true
}
```

### Media Field

```typescript
featuredImage: {
  type: 'media',
  title: 'Featured Image',
  description: 'Main content image',
  helpText: 'Recommended size: 1200x630px (Open Graph standard)'
}
```

### Select Field

```typescript
status: {
  type: 'select',
  title: 'Status',
  description: 'Publication status',
  enum: ['draft', 'review', 'published', 'archived'],
  enumLabels: ['Draft', 'In Review', 'Published', 'Archived'],
  default: 'draft',
  required: true
}
```

### Multiselect Field

```typescript
categories: {
  type: 'multiselect',
  title: 'Categories',
  description: 'Select multiple categories',
  enum: ['tech', 'design', 'business', 'marketing', 'development'],
  enumLabels: ['Technology', 'Design', 'Business', 'Marketing', 'Development']
}
```

### Textarea Field

```typescript
excerpt: {
  type: 'textarea',
  title: 'Excerpt',
  description: 'Brief summary',
  maxLength: 300,
  placeholder: 'Enter a brief summary...',
  helpText: 'Used for previews and SEO'
}
```

### Slug Field

```typescript
slug: {
  type: 'slug',
  title: 'URL Slug',
  description: 'URL-friendly identifier',
  required: true,
  pattern: '^[a-z0-9-]+$',
  helpText: 'Auto-generated from title if left blank'
}
```

### Color Field

```typescript
themeColor: {
  type: 'color',
  title: 'Theme Color',
  description: 'Primary color for this content',
  default: '#3B82F6'
}
```

### Email Field

```typescript
contactEmail: {
  type: 'email',
  title: 'Contact Email',
  description: 'Primary contact email',
  required: true,
  placeholder: 'email@example.com'
}
```

### URL Field

```typescript
website: {
  type: 'url',
  title: 'Website',
  description: 'Company website URL',
  placeholder: 'https://example.com',
  pattern: '^https?://.+'
}
```

### File Field

```typescript
downloadableFile: {
  type: 'file',
  title: 'Downloadable File',
  description: 'PDF, document, or other file',
  helpText: 'Max size: 10MB'
}
```

### Radio Field

```typescript
visibility: {
  type: 'radio',
  title: 'Visibility',
  description: 'Who can see this content',
  enum: ['public', 'private', 'unlisted'],
  enumLabels: ['Public', 'Private', 'Unlisted'],
  default: 'public',
  required: true
}
```

## Advanced Features

### Managed Collections

Managed collections are locked from UI editing and version-controlled:

```typescript
const collection: CollectionConfig = {
  name: 'my_collection',
  displayName: 'My Collection',
  managed: true,  // Locks this collection in the UI
  // ...
}
```

**Benefits:**
- Schema changes tracked in Git
- Deployment via code push
- Protected from accidental modifications
- Supports code review workflows

### Relationships

Reference fields create relationships between collections:

```typescript
// Author relationship
author: {
  type: 'reference',
  title: 'Author',
  collection: 'users',
  required: true
}

// Self-referencing (parent-child)
parentPage: {
  type: 'reference',
  title: 'Parent Page',
  collection: 'pages',  // Same collection
  helpText: 'Leave blank for top-level pages'
}

// Multiple references
relatedPosts: {
  type: 'array',
  title: 'Related Posts',
  items: {
    type: 'reference',
    collection: 'blog_posts'
  }
}
```

### Conditional Fields

Show fields based on other field values:

```typescript
showInMenu: {
  type: 'checkbox',
  title: 'Show in Navigation',
  default: false
},
menuOrder: {
  type: 'number',
  title: 'Menu Order',
  min: 0,
  dependsOn: 'showInMenu',  // Only show when...
  showWhen: true             // ...showInMenu is true
}
```

### Validation Rules

**String Validation:**
```typescript
{
  type: 'string',
  minLength: 3,
  maxLength: 100,
  pattern: '^[A-Za-z0-9 ]+$'  // Alphanumeric and spaces only
}
```

**Number Validation:**
```typescript
{
  type: 'number',
  min: 0,
  max: 100,
  // Additional custom validation would be in content creation logic
}
```

**Required Fields:**
```typescript
{
  type: 'string',
  required: true
}

// Or in schema root:
schema: {
  type: 'object',
  properties: { /* ... */ },
  required: ['field1', 'field2']
}
```

### Default Values

Set sensible defaults for better UX:

```typescript
status: {
  type: 'select',
  enum: ['draft', 'published'],
  default: 'draft'  // New content starts as draft
}

allowComments: {
  type: 'checkbox',
  default: true  // Comments enabled by default
}

publishDate: {
  type: 'datetime',
  default: new Date().toISOString()  // Current timestamp
}
```

### Display Configuration

Control how collections appear in the admin UI:

```typescript
const collection: CollectionConfig = {
  // ...
  icon: 'document-text',           // Icon from icon library
  color: '#3B82F6',                // Hex color code
  defaultSort: 'publishDate',      // Default sort field
  defaultSortOrder: 'desc',        // 'asc' or 'desc'
  listFields: ['title', 'author', 'status'],  // Columns to show
  searchFields: ['title', 'content']          // Fields to search
}
```

## Using Collections in Routes

### Querying Collections

From `src/routes/api.ts`, here's how to query collections:

```typescript
// Get all collections
apiRoutes.get('/collections', async (c) => {
  const db = c.env.DB

  const stmt = db.prepare('SELECT * FROM collections WHERE is_active = 1')
  const { results } = await stmt.all()

  // Parse schema JSON
  const collections = results.map((row: any) => ({
    ...row,
    schema: row.schema ? JSON.parse(row.schema) : {}
  }))

  return c.json({
    data: collections,
    meta: {
      count: collections.length,
      timestamp: new Date().toISOString()
    }
  })
})
```

### Querying Content by Collection

```typescript
// Get content for a specific collection
apiRoutes.get('/collections/:collection/content', async (c) => {
  const collection = c.req.param('collection')
  const db = c.env.DB
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100)

  // First check if collection exists
  const collectionStmt = db.prepare(
    'SELECT * FROM collections WHERE name = ? AND is_active = 1'
  )
  const collectionResult = await collectionStmt.bind(collection).first()

  if (!collectionResult) {
    return c.json({ error: 'Collection not found' }, 404)
  }

  // Get content for this collection
  const contentStmt = db.prepare(`
    SELECT * FROM content
    WHERE collection_id = ?
    ORDER BY created_at DESC
    LIMIT ${limit}
  `)
  const { results } = await contentStmt.bind(collectionResult.id).all()

  // Transform results
  const items = results.map((row: any) => ({
    id: row.id,
    title: row.title,
    slug: row.slug,
    status: row.status,
    collectionId: row.collection_id,
    data: row.data ? JSON.parse(row.data) : {},
    created_at: row.created_at,
    updated_at: row.updated_at
  }))

  return c.json({
    data: items,
    meta: {
      collection: {
        ...collectionResult,
        schema: JSON.parse(collectionResult.schema)
      },
      count: items.length,
      timestamp: new Date().toISOString()
    }
  })
})
```

### Custom Route Example

```typescript
// Custom route for featured blog posts
blogRoutes.get('/featured', async (c) => {
  const db = c.env.DB

  // Get blog_posts collection
  const collectionStmt = db.prepare(
    'SELECT id FROM collections WHERE name = ? AND is_active = 1'
  )
  const collection = await collectionStmt.bind('blog_posts').first()

  if (!collection) {
    return c.json({ error: 'Blog posts collection not found' }, 404)
  }

  // Get featured posts
  const stmt = db.prepare(`
    SELECT * FROM content
    WHERE collection_id = ?
    AND status = 'published'
    AND json_extract(data, '$.featured') = true
    ORDER BY json_extract(data, '$.publishDate') DESC
    LIMIT 10
  `)

  const { results } = await stmt.bind(collection.id).all()

  const posts = results.map((row: any) => ({
    ...row,
    data: JSON.parse(row.data)
  }))

  return c.json({ data: posts })
})
```

### Creating Content Programmatically

```typescript
// Create a new blog post
const createBlogPost = async (db: D1Database, postData: any) => {
  // Get collection
  const collectionStmt = db.prepare(
    'SELECT * FROM collections WHERE name = ? AND is_active = 1'
  )
  const collection = await collectionStmt.bind('blog_posts').first()

  if (!collection) {
    throw new Error('Blog posts collection not found')
  }

  // Validate against schema (implement validation logic)
  const schema = JSON.parse((collection as any).schema)
  // ... validation logic here ...

  // Insert content
  const contentId = `cnt-${crypto.randomUUID()}`
  const now = Date.now()

  const insertStmt = db.prepare(`
    INSERT INTO content (
      id, collection_id, title, slug, status, data, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `)

  await insertStmt.bind(
    contentId,
    collection.id,
    postData.title,
    postData.slug || generateSlug(postData.title),
    postData.status || 'draft',
    JSON.stringify(postData),
    now,
    now
  ).run()

  return contentId
}
```

## Best Practices

### 1. Naming Conventions

**Collections:**
```typescript
// ✅ Good
'blog_posts'
'team_members'
'product_categories'
'customer_reviews'

// ❌ Bad
'BlogPosts'        // Use snake_case, not PascalCase
'blog-posts'       // Use underscores, not hyphens
'posts'            // Too generic
'bp'               // Not descriptive
```

**Fields:**
```typescript
// ✅ Good - Clear, descriptive
fullName: { type: 'string' }
publishedAt: { type: 'datetime' }
isActive: { type: 'checkbox' }

// ❌ Bad - Unclear or inconsistent
name: { type: 'string' }         // Too vague
pub_date: { type: 'datetime' }   // Inconsistent style
active: { type: 'checkbox' }     // Missing verb prefix
```

### 2. Schema Design

**Keep schemas focused:**
```typescript
// ✅ Good - Focused product schema
properties: {
  name: { type: 'string' },
  sku: { type: 'string' },
  price: { type: 'number' },
  inventory: { type: 'object' }
}

// ❌ Bad - Too many unrelated fields
properties: {
  productName: { type: 'string' },
  customerName: { type: 'string' },  // Belongs in orders
  warehouseLocation: { type: 'string' },  // Belongs in inventory
  // ...
}
```

**Use objects for related data:**
```typescript
// ✅ Good - Grouped related fields
seo: {
  type: 'object',
  properties: {
    metaTitle: { type: 'string' },
    metaDescription: { type: 'textarea' },
    ogImage: { type: 'media' }
  }
}

// ❌ Bad - Flat structure
seoMetaTitle: { type: 'string' },
seoMetaDescription: { type: 'textarea' },
seoOgImage: { type: 'media' }
```

### 3. Validation

**Always validate critical fields:**
```typescript
// ✅ Good - Comprehensive validation
email: {
  type: 'email',  // Built-in email validation
  required: true,
  minLength: 5,
  maxLength: 100
}

sku: {
  type: 'string',
  required: true,
  pattern: '^[A-Z0-9-]+$',  // Alphanumeric and hyphens
  minLength: 3,
  maxLength: 20
}

price: {
  type: 'number',
  required: true,
  min: 0,
  max: 999999.99
}

// ❌ Bad - No validation
email: { type: 'string' }
sku: { type: 'string' }
price: { type: 'number' }
```

### 4. Provide Help Text

**Guide users with clear instructions:**
```typescript
// ✅ Good - Helpful descriptions
slug: {
  type: 'slug',
  title: 'URL Slug',
  description: 'URL-friendly page identifier',
  helpText: 'Leave blank to auto-generate from title',
  placeholder: 'my-page-url'
}

featuredImage: {
  type: 'media',
  title: 'Featured Image',
  description: 'Main image for social sharing',
  helpText: 'Recommended size: 1200x630px (Open Graph standard)'
}

// ❌ Bad - No guidance
slug: { type: 'slug' }
featuredImage: { type: 'media' }
```

### 5. Set Sensible Defaults

**Make content creation easier:**
```typescript
// ✅ Good - Safe, user-friendly defaults
status: {
  type: 'select',
  enum: ['draft', 'published', 'archived'],
  default: 'draft'  // Start as draft
}

publishDate: {
  type: 'datetime',
  default: new Date().toISOString()  // Current time
}

allowComments: {
  type: 'checkbox',
  default: true  // Enable by default
}

// ❌ Bad - No defaults, potential issues
status: {
  type: 'select',
  enum: ['draft', 'published', 'archived']
  // No default - might be null
}
```

### 6. Use Appropriate Field Types

**Choose the right field type:**
```typescript
// ✅ Good - Appropriate types
email: { type: 'email' }           // Email validation
price: { type: 'number' }          // Numeric operations
publishDate: { type: 'datetime' }  // Date operations
content: { type: 'richtext' }      // Formatted text

// ❌ Bad - Wrong types
email: { type: 'string' }          // Missing validation
price: { type: 'string' }          // Can't do math
publishDate: { type: 'string' }    // Can't sort chronologically
content: { type: 'string' }        // No formatting options
```

### 7. Organize Complex Schemas

**Break down into logical sections:**
```typescript
schema: {
  type: 'object',
  properties: {
    // Basic Information
    title: { type: 'string' },
    slug: { type: 'slug' },
    excerpt: { type: 'textarea' },

    // Content
    content: { type: 'richtext' },
    featuredImage: { type: 'media' },

    // Taxonomy
    category: { type: 'select' },
    tags: { type: 'multiselect' },

    // Publishing
    status: { type: 'select' },
    publishDate: { type: 'datetime' },
    author: { type: 'reference' },

    // SEO
    seo: {
      type: 'object',
      properties: { /* ... */ }
    }
  }
}
```

### 8. Document Your Collections

**Add descriptive comments:**
```typescript
/**
 * Products Collection
 *
 * E-commerce product catalog with inventory tracking.
 *
 * Features:
 * - SKU validation (uppercase alphanumeric)
 * - Price in USD (0-999,999.99)
 * - Image gallery support
 * - Nested inventory object
 * - SEO optimization fields
 *
 * Related collections: categories, brands
 */
const productsCollection: CollectionConfig = {
  name: 'products',
  // ...
}
```

### 9. Test Your Schemas

**Validate before deploying:**
```typescript
// Run the app and check console for errors
npm run dev

// Look for validation errors:
// ✅ "✓ Loaded collection config: products"
// ❌ "Validation failed: Reference field 'author' is missing collection property"
```

### 10. Version Control

**Track schema changes:**
```bash
# Commit schema changes with clear messages
git add src/collections/products.collection.ts
git commit -m "feat: add inventory tracking to products collection"

# Review schema changes in PRs
git diff src/collections/
```

### 11. Migration Strategy

**When updating existing collections:**

1. **Additive changes** (safe):
   ```typescript
   // Adding optional fields is safe
   newField: {
     type: 'string',
     required: false  // Won't break existing content
   }
   ```

2. **Breaking changes** (careful):
   ```typescript
   // Adding required fields needs data migration
   requiredField: {
     type: 'string',
     required: true,
     default: 'default-value'  // Provide default for existing content
   }
   ```

3. **Removing fields**:
   ```typescript
   // Mark as deprecated first, remove later
   oldField: {
     type: 'string',
     description: 'DEPRECATED: Use newField instead'
   }
   ```

### 12. Performance Considerations

**Optimize for queries:**
```typescript
// ✅ Good - Searchable fields defined
searchFields: ['title', 'excerpt', 'sku']

// ✅ Good - Logical default sort
defaultSort: 'publishDate',
defaultSortOrder: 'desc'

// ✅ Good - Limit list fields
listFields: ['title', 'status', 'publishDate']  // Only 3-5 fields
```

---

## Related Documentation

- [Collection Config Types](/Users/lane/Dev/refs/sonicjs-ai/src/types/collection-config.ts) - TypeScript type definitions
- [Collection Loader](/Users/lane/Dev/refs/sonicjs-ai/src/services/collection-loader.ts) - Loading and validation logic
- [Collection Sync](/Users/lane/Dev/refs/sonicjs-ai/src/services/collection-sync.ts) - Database synchronization
- [Example Collections](/Users/lane/Dev/refs/sonicjs-ai/src/collections/) - Real-world examples

## Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/lane711/sonicjs
- Documentation: https://sonicjs.com/docs
