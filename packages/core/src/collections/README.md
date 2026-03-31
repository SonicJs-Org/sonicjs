# Collections

This directory contains collection configuration files that define the structure and behavior of content types in SonicJS.

## Overview

Collections are defined as TypeScript files that export a `CollectionConfig` object. These configurations are used instead of database-stored collection definitions, providing:

- **Version control**: Collection schemas are tracked in git
- **Type safety**: TypeScript ensures configuration correctness
- **Portability**: Collections can be easily shared across projects
- **Testing**: Collections can be unit tested

## Collection Files

### test-items.collection.ts

A simple test collection used for development and testing purposes. This collection demonstrates:

- Basic field types (string, number, checkbox, select, textarea)
- Field validation (required, min/max, maxLength)
- Default values
- List view configuration
- Search configuration
- Metadata

**Schema:**
- `title` (string, required): Main title for the item
- `description` (textarea): Brief description
- `status` (select, required): One of 'active', 'inactive', or 'archived'
- `priority` (number): Priority from 1 to 10
- `isPublic` (checkbox): Public visibility flag
- `tags` (string): Comma-separated tags

## Creating a New Collection

1. Create a new file with the naming pattern: `{name}.collection.ts`
2. Import the `CollectionConfig` type:
   ```typescript
   import type { CollectionConfig } from '../types/collection-config'
   ```
3. Export a default object satisfying the `CollectionConfig` interface:
   ```typescript
   export default {
     name: 'my_collection',
     displayName: 'My Collection',
     description: 'Description of my collection',
     schema: {
       type: 'object',
       properties: {
         // Define your fields here
       },
       required: ['field1', 'field2']
     }
   } satisfies CollectionConfig
   ```

## Required Fields

Every collection must have:

- `name`: Unique machine name (lowercase, underscores only)
- `displayName`: Human-readable name
- `schema`: JSON schema definition with:
  - `type`: Must be 'object'
  - `properties`: Object defining all fields

## Optional Configuration

- `description`: Collection description
- `icon`: Emoji or icon name for UI
- `color`: Hex color code
- `managed`: If true, collection is managed by config (default: true)
- `isActive`: If collection is active (default: true)
- `listFields`: Fields to show in list view
- `searchFields`: Fields to include in search
- `defaultSort`: Default sort field
- `defaultSortOrder`: 'asc' or 'desc'
- `metadata`: Additional metadata object

## Field Types

Supported field types include:

- **Text**: `string`, `email`, `url`, `textarea`, `markdown`, `richtext`
- **Numeric**: `number`
- **Boolean**: `boolean`, `checkbox`
- **Date**: `date`, `datetime`
- **Selection**: `select`, `multiselect`, `radio`
- **Relationships**: `reference`, `media`
- **Structured**: `json`, `array`, `object`
- **Special**: `slug`, `color`, `file`

## Field Configuration

Each field can have:

- `type`: Field type (required)
- `title`: Display label
- `description`: Field description
- `required`: Whether field is required
- `default`: Default value
- `placeholder`: Placeholder text
- `helpText`: Help text shown in UI

### Validation Options:

- `min`, `max`: Numeric range
- `minLength`, `maxLength`: String length
- `pattern`: Regular expression pattern

### Select/Radio/Multiselect:

- `enum`: Array of valid values
- `enumLabels`: Array of display labels

### Reference Fields:

- `collection`: Name of referenced collection

### Array/Object Fields:

- `items`: Schema for array items
- `itemTitle`: Optional singular item label used in array item cards/buttons (for example, `"Member"`)
- `properties`: Schema for object properties
- `objectLayout`: Object field layout mode: `'nested'` (default) or `'flat'`
- `collapsed`: For nested object layout, initial state (default: `true`; set `false` to start open)
- Note: `collapsed` is ignored when `objectLayout` is `'flat'`

## Testing Collections

Create test files in `src/__tests__/collections/` to verify:

1. Configuration structure
2. Field definitions
3. Validation rules
4. Type consistency
5. Integration with collection loader

See `test-items.test.ts` for a comprehensive example.

## Collection Loader

Collections are automatically loaded by the collection loader service when the application starts. The loader:

1. Scans for `*.collection.ts` files
2. Validates each configuration
3. Returns an array of `CollectionConfig` objects

## Best Practices

1. Use descriptive field names and titles
2. Provide helpful placeholder and help text
3. Set appropriate validation constraints
4. Define required fields explicitly
5. Test your collections thoroughly
6. Document complex field relationships
7. Use consistent naming conventions
8. Keep schemas focused and simple

## Examples

See the `test-items.collection.ts` file for a working example that demonstrates all major features.
