/**
 * Extended Dynamic Field Template Tests
 *
 * Tests for additional field types and edge cases in renderDynamicField
 */

import { describe, it, expect } from 'vitest';
import {
  renderDynamicField,
  renderFieldGroup,
  FieldDefinition,
  FieldRenderOptions,
} from '../../templates/components/dynamic-field.template';

// Helper to create a test field definition
function createTestField(overrides: Partial<FieldDefinition>): FieldDefinition {
  return {
    id: 'test-field-id',
    field_name: 'test_field',
    field_type: 'text',
    field_label: 'Test Field',
    field_options: {},
    field_order: 1,
    is_required: false,
    is_searchable: false,
    ...overrides,
  };
}

describe('renderDynamicField - Text Fields', () => {
  it('should render text field with value', () => {
    const field = createTestField({ field_type: 'text' });
    const html = renderDynamicField(field, { value: 'Test Value' });

    expect(html).toContain('type="text"');
    expect(html).toContain('value="Test Value"');
    expect(html).toContain('id="field-test_field"');
    expect(html).toContain('name="test_field"');
  });

  it('should render text field with placeholder', () => {
    const field = createTestField({
      field_type: 'text',
      field_options: { placeholder: 'Enter text here...' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('placeholder="Enter text here..."');
  });

  it('should render text field with maxLength', () => {
    const field = createTestField({
      field_type: 'text',
      field_options: { maxLength: 100 },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('maxlength="100"');
  });

  it('should render text field with pattern', () => {
    const field = createTestField({
      field_type: 'text',
      field_options: { pattern: '^[a-zA-Z0-9_-]+$' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('data-pattern="^[a-zA-Z0-9_-]+$"');
    expect(html).toContain('Use letters, numbers, underscores, and hyphens only');
  });

  it('should render text field with slug-specific pattern', () => {
    const field = createTestField({
      field_name: 'slug',
      field_type: 'text',
      field_options: { pattern: '^[a-z0-9-]+$' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('data-pattern="^[a-z0-9-]+$"');
    expect(html).toContain('Generate from title');
  });

  it('should render text field with custom pattern help text', () => {
    const field = createTestField({
      field_type: 'text',
      field_options: { pattern: '^[0-9]{3}-[0-9]{4}$' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('Must match required format');
  });

  it('should render required text field with asterisk', () => {
    const field = createTestField({
      field_type: 'text',
      is_required: true,
    });
    const html = renderDynamicField(field);

    expect(html).toContain('required');
    expect(html).toContain('*</span>');
    expect(html).toContain('text-pink-600');
  });

  it('should render disabled text field', () => {
    const field = createTestField({ field_type: 'text' });
    const html = renderDynamicField(field, { disabled: true });

    expect(html).toContain('disabled');
  });

  it('should render text field with errors', () => {
    const field = createTestField({ field_type: 'text' });
    const html = renderDynamicField(field, { errors: ['Field is invalid', 'Too short'] });

    expect(html).toContain('Field is invalid');
    expect(html).toContain('Too short');
    expect(html).toContain('text-pink-600');
    expect(html).toContain('ring-pink-600');
  });

  it('should render text field with help text', () => {
    const field = createTestField({
      field_type: 'text',
      field_options: { helpText: 'This is help text' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('This is help text');
  });
});

describe('renderDynamicField - Textarea Fields', () => {
  it('should render textarea with default rows', () => {
    const field = createTestField({ field_type: 'textarea' });
    const html = renderDynamicField(field, { value: 'Multi-line content' });

    expect(html).toContain('<textarea');
    expect(html).toContain('rows="6"');
    expect(html).toContain('Multi-line content');
  });

  it('should render textarea with custom rows', () => {
    const field = createTestField({
      field_type: 'textarea',
      field_options: { rows: 10 },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('rows="10"');
  });

  it('should render textarea with placeholder', () => {
    const field = createTestField({
      field_type: 'textarea',
      field_options: { placeholder: 'Enter description...' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('placeholder="Enter description..."');
  });
});

describe('renderDynamicField - Number Fields', () => {
  it('should render number field', () => {
    const field = createTestField({ field_type: 'number' });
    const html = renderDynamicField(field, { value: 42 });

    expect(html).toContain('type="number"');
    expect(html).toContain('value="42"');
  });

  it('should render number field with min/max', () => {
    const field = createTestField({
      field_type: 'number',
      field_options: { min: 1, max: 100 },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('min="1"');
    expect(html).toContain('max="100"');
  });

  it('should render number field with step', () => {
    const field = createTestField({
      field_type: 'number',
      field_options: { step: 0.5 },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('step="0.5"');
  });
});

describe('renderDynamicField - Boolean Fields', () => {
  it('should render unchecked checkbox', () => {
    const field = createTestField({ field_type: 'boolean' });
    const html = renderDynamicField(field, { value: false });

    expect(html).toContain('type="checkbox"');
    expect(html).not.toContain('checked');
  });

  it('should render checked checkbox for true value', () => {
    const field = createTestField({ field_type: 'boolean' });
    const html = renderDynamicField(field, { value: true });

    expect(html).toContain('checked');
  });

  it('should render checked checkbox for "true" string', () => {
    const field = createTestField({ field_type: 'boolean' });
    const html = renderDynamicField(field, { value: 'true' });

    expect(html).toContain('checked');
  });

  it('should render checked checkbox for "1" string', () => {
    const field = createTestField({ field_type: 'boolean' });
    const html = renderDynamicField(field, { value: '1' });

    expect(html).toContain('checked');
  });

  it('should render custom checkbox label', () => {
    const field = createTestField({
      field_type: 'boolean',
      field_options: { checkboxLabel: 'Enable feature' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('Enable feature');
  });

  it('should include hidden submitted field', () => {
    const field = createTestField({ field_type: 'boolean' });
    const html = renderDynamicField(field);

    expect(html).toContain('name="test_field_submitted"');
    expect(html).toContain('value="1"');
  });
});

describe('renderDynamicField - Date/DateTime Fields', () => {
  it('should render date field', () => {
    const field = createTestField({ field_type: 'date' });
    const html = renderDynamicField(field, { value: '2024-01-15' });

    expect(html).toContain('type="date"');
    expect(html).toContain('value="2024-01-15"');
  });

  it('should render date field with min/max', () => {
    const field = createTestField({
      field_type: 'date',
      field_options: { min: '2024-01-01', max: '2024-12-31' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('min="2024-01-01"');
    expect(html).toContain('max="2024-12-31"');
  });

  it('should render datetime field', () => {
    const field = createTestField({ field_type: 'datetime' });
    const html = renderDynamicField(field, { value: '2024-01-15T10:30' });

    expect(html).toContain('type="datetime-local"');
    expect(html).toContain('value="2024-01-15T10:30"');
  });

  it('should render datetime field with min/max', () => {
    const field = createTestField({
      field_type: 'datetime',
      field_options: { min: '2024-01-01T00:00', max: '2024-12-31T23:59' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('min="2024-01-01T00:00"');
    expect(html).toContain('max="2024-12-31T23:59"');
  });
});

describe('renderDynamicField - Slug Fields', () => {
  it('should render slug field with validation', () => {
    const field = createTestField({
      field_type: 'slug',
      field_options: { collectionId: 'posts' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('slug-field-container');
    expect(html).toContain('data-pattern="^[a-z0-9-]+$"');
    expect(html).toContain('data-collection-id="posts"');
  });

  it('should render slug field with custom pattern', () => {
    const field = createTestField({
      field_type: 'slug',
      field_options: { pattern: '^[a-z0-9_-]+$' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('data-pattern="^[a-z0-9_-]+$"');
  });

  it('should render slug field in edit mode', () => {
    const field = createTestField({
      field_type: 'slug',
      field_options: { collectionId: 'posts', contentId: 'content-123' },
    });
    const html = renderDynamicField(field, { value: 'existing-slug' });

    expect(html).toContain('value="existing-slug"');
    expect(html).toContain('data-is-edit-mode="true"');
  });

  it('should render slug field with regenerate button', () => {
    const field = createTestField({ field_type: 'slug' });
    const html = renderDynamicField(field);

    expect(html).toContain('Regenerate from title');
  });

  it('should render slug field with content ID from options', () => {
    const field = createTestField({
      field_type: 'slug',
      field_options: { contentId: 'option-content-id' },
    });
    const html = renderDynamicField(field, { contentId: 'override-content-id' });

    expect(html).toContain('data-content-id="override-content-id"');
  });
});

describe('renderDynamicField - Select Fields', () => {
  it('should render select with string options', () => {
    const field = createTestField({
      field_type: 'select',
      field_options: { options: ['draft', 'published', 'archived'] },
    });
    const html = renderDynamicField(field, { value: 'published' });

    expect(html).toContain('<select');
    expect(html).toContain('<option value="draft"');
    expect(html).toContain('<option value="published" selected');
    expect(html).toContain('<option value="archived"');
  });

  it('should render select with object options', () => {
    const field = createTestField({
      field_type: 'select',
      field_options: {
        options: [
          { value: 'draft', label: 'Draft Status' },
          { value: 'published', label: 'Published' },
        ],
      },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('Draft Status');
    expect(html).toContain('Published');
  });

  it('should render select without default option when required', () => {
    const field = createTestField({
      field_type: 'select',
      is_required: true,
      field_options: { options: ['a', 'b'] },
    });
    const html = renderDynamicField(field);

    expect(html).not.toContain('Choose an option...');
  });

  it('should render select with default option when not required', () => {
    const field = createTestField({
      field_type: 'select',
      is_required: false,
      field_options: { options: ['a', 'b'] },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('Choose an option...');
  });

  it('should render multiselect', () => {
    const field = createTestField({
      field_type: 'select',
      field_options: { options: ['a', 'b', 'c'], multiple: true },
    });
    const html = renderDynamicField(field, { value: ['a', 'c'] });

    expect(html).toContain('multiple');
    expect(html).toContain('name="test_field[]"');
    expect(html).toMatch(/<option value="a"[^>]*selected/);
    expect(html).toMatch(/<option value="c"[^>]*selected/);
    expect(html).not.toMatch(/<option value="b"[^>]*selected/);
  });

  it('should render select with custom option input', () => {
    const field = createTestField({
      field_type: 'select',
      field_options: { options: ['a', 'b'], allowCustom: true },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('Add custom option...');
    expect(html).toContain('addCustomOption');
  });
});

describe('renderDynamicField - Reference Fields', () => {
  it('should render reference field with collection', () => {
    const field = createTestField({
      field_type: 'reference',
      field_options: { collection: 'users' },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('reference-field-container');
    expect(html).toContain('data-reference-collection="users"');
    expect(html).toContain('Select reference');
    expect(html).toContain('No reference selected.');
  });

  it('should render reference field with multiple collections', () => {
    const field = createTestField({
      field_type: 'reference',
      field_options: { collection: ['posts', 'pages'] },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('data-reference-collections="posts,pages"');
  });

  it('should render reference field with existing value', () => {
    const field = createTestField({
      field_type: 'reference',
      field_options: { collection: 'users' },
    });
    const html = renderDynamicField(field, { value: 'user-123' });

    expect(html).toContain('value="user-123"');
    expect(html).toContain('Loading selection...');
    // Remove button should be enabled
    expect(html).toContain('data-reference-clear');
    expect(html).not.toContain('data-reference-clear"\n            disabled');
  });

  it('should render reference field without collection (disabled)', () => {
    const field = createTestField({
      field_type: 'reference',
      field_options: {},
    });
    const html = renderDynamicField(field);

    expect(html).toContain('Reference collection not configured.');
    expect(html).toContain('disabled');
  });
});

describe('renderDynamicField - Rich Text Fields', () => {
  it('should render richtext textarea', () => {
    const field = createTestField({
      field_type: 'richtext',
      field_options: { height: 400 },
    });
    const html = renderDynamicField(field, {
      value: '<p>Content</p>',
      pluginStatuses: { tinymceEnabled: true },
    });

    expect(html).toContain('richtext-container');
    expect(html).toContain('data-height="400"');
    expect(html).toContain('data-editor-family="richtext"');
    expect(html).toContain('data-editor-provider="tinymce"');
    // Content gets HTML-escaped in the textarea
    expect(html).toContain('&lt;p&gt;Content&lt;/p&gt;');
  });

  it('should render richtext with toolbar option', () => {
    const field = createTestField({
      field_type: 'richtext',
      field_options: { toolbar: 'minimal' },
    });
    const html = renderDynamicField(field, {
      pluginStatuses: { tinymceEnabled: true },
    });

    expect(html).toContain('data-toolbar="minimal"');
  });
});

describe('renderDynamicField - Quill Editor Fields', () => {
  it('should render quill editor container', () => {
    const field = createTestField({
      field_type: 'quill',
      field_options: { theme: 'snow', height: 300 },
    });
    const html = renderDynamicField(field, {
      value: '<p>Content</p>',
      pluginStatuses: { quillEnabled: true },
    });

    expect(html).toContain('quill-editor-container');
    expect(html).toContain('data-theme="snow"');
    expect(html).toContain('data-height="300"');
    expect(html).toContain('id="field-test_field-editor"');
    expect(html).toContain('<p>Content</p>');
  });

  it('should fallback to textarea when quill plugin is disabled', () => {
    const field = createTestField({
      field_type: 'quill',
    });
    const html = renderDynamicField(field, {
      pluginStatuses: { quillEnabled: false },
    });

    expect(html).toContain('<textarea');
    expect(html).toContain('Quill Editor plugin is inactive');
    expect(html).not.toContain('quill-editor-container');
  });

  it('should fallback to textarea when mdxeditor plugin is disabled', () => {
    const field = createTestField({
      field_type: 'mdxeditor',
    });
    const html = renderDynamicField(field, {
      pluginStatuses: { mdxeditorEnabled: false },
    });

    expect(html).toContain('<textarea');
    expect(html).toContain('Markdown editor plugin is inactive');
  });

  it('should fallback to textarea when markdown plugin is disabled', () => {
    const field = createTestField({
      field_type: 'markdown',
    });
    const html = renderDynamicField(field, {
      pluginStatuses: { mdxeditorEnabled: false },
    });

    expect(html).toContain('<textarea');
    expect(html).toContain('Markdown editor plugin is inactive');
  });

  it('should fallback to textarea when easymde alias is disabled', () => {
    const field = createTestField({
      field_type: 'easymde',
    });
    const html = renderDynamicField(field, {
      pluginStatuses: { mdxeditorEnabled: false },
    });

    expect(html).toContain('<textarea');
    expect(html).toContain('Markdown editor plugin is inactive');
  });

  it('should fallback to textarea when tinymce plugin is disabled', () => {
    const field = createTestField({
      field_type: 'tinymce',
    });
    const html = renderDynamicField(field, {
      pluginStatuses: { tinymceEnabled: false },
    });

    expect(html).toContain('<textarea');
    expect(html).toContain('TinyMCE plugin is inactive');
  });

  it('should fallback to textarea when canonical richtext plugin is disabled', () => {
    const field = createTestField({
      field_type: 'richtext',
    });
    const html = renderDynamicField(field, {
      pluginStatuses: { tinymceEnabled: false },
    });

    expect(html).toContain('<textarea');
    expect(html).toContain('TinyMCE plugin is inactive');
    expect(html).not.toContain('data-editor-provider="tinymce"');
  });
});

describe('renderDynamicField - Unknown Field Type', () => {
  it('should render unknown field type as text input', () => {
    const field = createTestField({ field_type: 'unknown_type' as any });
    const html = renderDynamicField(field, { value: 'Test' });

    expect(html).toContain('type="text"');
    expect(html).toContain('value="Test"');
  });
});

describe('renderDynamicField - Object Fields', () => {
  it('should render structured object field', () => {
    const field = createTestField({
      field_type: 'object',
      field_options: {
        properties: {
          title: { type: 'text', title: 'Title' },
          description: { type: 'textarea', title: 'Description' },
        },
      },
    });
    const html = renderDynamicField(field, {
      value: { title: 'Test', description: 'Desc' },
    });

    expect(html).toContain('data-structured-object');
    expect(html).toContain('data-field-name="test_field"');
    expect(html).toContain('Title');
    expect(html).toContain('Description');
  });

  it('should handle empty object properties', () => {
    const field = createTestField({
      field_type: 'object',
      field_options: { properties: {} },
    });
    const html = renderDynamicField(field);

    expect(html).toContain('data-structured-object');
  });
});

describe('renderDynamicField - Array Fields', () => {
  it('should render structured array field', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: {
        items: { type: 'text', title: 'Item' },
        itemLabel: 'Custom Items',
      },
    });
    const html = renderDynamicField(field, { value: ['item1', 'item2'] });

    expect(html).toContain('data-structured-array');
    expect(html).toContain('Custom Items');
    expect(html).toContain('Add item');
    expect(html).toContain('structured-array-item');
  });

  it('should render empty array state', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: { items: { type: 'text' } },
    });
    const html = renderDynamicField(field, { value: [] });

    expect(html).toContain('No items yet');
    expect(html).toContain('data-structured-empty');
  });

  it('should render array with object items', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: {
        items: {
          type: 'object',
          properties: {
            name: { type: 'text', title: 'Name' },
            url: { type: 'text', title: 'URL' },
          },
        },
      },
    });
    const html = renderDynamicField(field, {
      value: [{ name: 'Link 1', url: 'https://example.com' }],
    });

    expect(html).toContain('data-structured-array');
    expect(html).toContain('Name');
    expect(html).toContain('URL');
  });
});

describe('renderFieldGroup', () => {
  it('should render field group with title', () => {
    const fields = [
      '<input type="text" name="field1">',
      '<input type="text" name="field2">',
    ];
    const html = renderFieldGroup('Basic Info', fields);

    expect(html).toContain('Basic Info');
    expect(html).toContain('field-group');
    expect(html).toContain('name="field1"');
    expect(html).toContain('name="field2"');
  });

  it('should render collapsible field group', () => {
    const fields = ['<input type="text" name="field1">'];
    const html = renderFieldGroup('Advanced', fields, true);

    expect(html).toContain('cursor-pointer');
    expect(html).toContain('toggleFieldGroup');
    expect(html).toContain('id="advanced-icon"');
    expect(html).toContain('collapsible');
  });

  it('should render non-collapsible field group', () => {
    const fields = ['<input type="text" name="field1">'];
    const html = renderFieldGroup('Basic', fields, false);

    expect(html).not.toContain('cursor-pointer');
    expect(html).not.toContain('toggleFieldGroup');
    expect(html).not.toContain('collapsible');
  });

  it('should generate group ID from title', () => {
    const html = renderFieldGroup('SEO Settings', []);

    expect(html).toContain('id="seo-settings-content"');
    // Icon only appears when collapsible
    expect(html).toContain('seo-settings-content');
  });

  it('should generate group ID from title in collapsible mode', () => {
    const html = renderFieldGroup('SEO Settings', [], true);

    expect(html).toContain('id="seo-settings-content"');
    expect(html).toContain('id="seo-settings-icon"');
  });
});

describe('renderDynamicField - Blocks Fields', () => {
  it('should render blocks field with block types', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: {
        items: {
          discriminator: 'blockType',
          blocks: {
            hero: {
              label: 'Hero Section',
              description: 'A hero banner',
              properties: {
                title: { type: 'text', title: 'Title' },
                subtitle: { type: 'text', title: 'Subtitle' },
              },
            },
            text: {
              label: 'Text Block',
              properties: {
                content: { type: 'textarea', title: 'Content' },
              },
            },
          },
        },
      },
    });
    const html = renderDynamicField(field, {
      value: [{ blockType: 'hero', title: 'Welcome', subtitle: 'Hello' }],
    });

    expect(html).toContain('blocks-field');
    expect(html).toContain('Hero Section');
    expect(html).toContain('Text Block');
    expect(html).toContain('Choose a block...');
    expect(html).toContain('Add Block');
    expect(html).toContain('data-block-type="hero"');
  });

  it('should render unknown block type with warning', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: {
        items: {
          discriminator: 'blockType',
          blocks: {
            text: { label: 'Text', properties: { content: { type: 'text' } } },
          },
        },
      },
    });
    const html = renderDynamicField(field, {
      value: [{ blockType: 'unknown', data: 'test' }],
    });

    expect(html).toContain('Unknown block type');
    expect(html).toContain('unknown');
    expect(html).toContain('preserved as-is');
  });

  it('should render empty blocks state', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: {
        items: {
          blocks: {
            text: { label: 'Text', properties: {} },
          },
        },
      },
    });
    const html = renderDynamicField(field, { value: [] });

    expect(html).toContain('No blocks yet');
    expect(html).toContain('data-blocks-empty');
  });

  it('should render block with delete and move buttons', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: {
        items: {
          blocks: {
            text: { label: 'Text', properties: { content: { type: 'text' } } },
          },
        },
      },
    });
    const html = renderDynamicField(field, {
      value: [{ blockType: 'text', content: 'Test' }],
    });

    expect(html).toContain('data-action="remove-block"');
    expect(html).toContain('data-action="move-up"');
    expect(html).toContain('data-action="move-down"');
    expect(html).toContain('data-action="drag-handle"');
    expect(html).toContain('Delete block');
  });

  it('should handle nested blocks warning', () => {
    const field = createTestField({
      field_type: 'array',
      field_options: {
        items: {
          blocks: {
            nested: {
              label: 'Nested',
              properties: {
                children: {
                  type: 'array',
                  items: {
                    blocks: { inner: { label: 'Inner', properties: {} } },
                  },
                },
              },
            },
          },
        },
      },
    });
    const html = renderDynamicField(field, {
      value: [{ blockType: 'nested', children: [] }],
    });

    expect(html).toContain('Nested blocks are not supported yet');
  });
});

describe('renderDynamicField - MDXEditor Fields', () => {
  it('should render mdxeditor container when enabled', () => {
    const field = createTestField({
      field_type: 'mdxeditor',
      field_options: { height: 400 },
    });
    const html = renderDynamicField(field, {
      value: '# Markdown',
      pluginStatuses: { mdxeditorEnabled: true },
    });

    expect(html).toContain('richtext-container');
    expect(html).toContain('data-height="400"');
    expect(html).toContain('data-editor-family="markdown"');
    expect(html).toContain('data-editor-provider="easymde"');
    expect(html).toContain('# Markdown');
  });

  it('should render markdown container when enabled', () => {
    const field = createTestField({
      field_type: 'markdown',
      field_options: { height: 320, toolbar: 'minimal' },
    });
    const html = renderDynamicField(field, {
      value: '# Canonical Markdown',
      pluginStatuses: { mdxeditorEnabled: true },
    });

    expect(html).toContain('richtext-container');
    expect(html).toContain('data-height="320"');
    expect(html).toContain('data-toolbar="minimal"');
    expect(html).toContain('data-editor-family="markdown"');
    expect(html).toContain('data-editor-provider="easymde"');
    expect(html).toContain('# Canonical Markdown');
  });

  it('should render easymde alias container when enabled', () => {
    const field = createTestField({
      field_type: 'easymde',
      field_options: { height: 360 },
    });
    const html = renderDynamicField(field, {
      value: '## EasyMDE Alias',
      pluginStatuses: { mdxeditorEnabled: true },
    });

    expect(html).toContain('richtext-container');
    expect(html).toContain('data-height="360"');
    expect(html).toContain('data-editor-family="markdown"');
    expect(html).toContain('data-editor-provider="easymde"');
    expect(html).toContain('## EasyMDE Alias');
  });
});

describe('renderDynamicField - HTML Escaping', () => {
  it('should escape HTML in text values', () => {
    const field = createTestField({ field_type: 'text' });
    const html = renderDynamicField(field, { value: '<script>alert("xss")</script>' });

    expect(html).not.toContain('<script>alert');
    expect(html).toContain('&lt;script&gt;');
  });

  it('should escape HTML in field labels', () => {
    const field = createTestField({
      field_type: 'text',
      field_label: 'Field <b>Label</b>',
    });
    const html = renderDynamicField(field);

    expect(html).toContain('Field &lt;b&gt;Label&lt;/b&gt;');
  });

  it('should escape HTML in error messages', () => {
    const field = createTestField({ field_type: 'text' });
    const html = renderDynamicField(field, {
      errors: ['Error with <script>'],
    });

    expect(html).toContain('Error with &lt;script&gt;');
  });
});
