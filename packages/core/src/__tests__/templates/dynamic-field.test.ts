import { describe, it, expect } from 'vitest';
import {
  renderDynamicField,
  FieldDefinition,
} from '../../templates/components/dynamic-field.template';

/**
 * TDZ Bug Fix Tests (GitHub Issue #555, PR #556)
 *
 * Bug: The `select` case in renderDynamicField declares `const options = opts.options || []`
 * which shadows the function parameter `options: FieldRenderOptions`. Because const declarations
 * in switch cases are scoped to the entire switch block, this creates a TDZ (Temporal Dead Zone)
 * error when other cases (object, array) try to access the `options` parameter.
 *
 * These tests verify that object and array fields can be rendered without TDZ errors.
 */
describe('renderDynamicField - TDZ Bug Fix (Issue #555)', () => {
  it('should render object field without TDZ error', () => {
    const objectField: FieldDefinition = {
      id: 'seo-field',
      field_name: 'seo',
      field_type: 'object',
      field_label: 'SEO',
      field_options: {
        properties: {
          title: { type: 'string', title: 'SEO Title' },
          description: { type: 'textarea', title: 'SEO Description' },
        },
      },
      field_order: 1,
      is_required: false,
      is_searchable: false,
    };

    // This should not throw "ReferenceError: Cannot access 'options' before initialization"
    const html = renderDynamicField(objectField, {
      value: { title: 'Test Title', description: 'Test Description' },
    });

    expect(html).toContain('data-structured-object');
    expect(html).toContain('data-field-name="seo"');
    expect(html).toContain('SEO Title');
    expect(html).toContain('SEO Description');
  });

  it('should render array field without TDZ error', () => {
    const arrayField: FieldDefinition = {
      id: 'tags-field',
      field_name: 'tags',
      field_type: 'array',
      field_label: 'Tags',
      field_options: {
        items: {
          type: 'string',
          title: 'Tag',
        },
      },
      field_order: 1,
      is_required: false,
      is_searchable: false,
    };

    // This should not throw "ReferenceError: Cannot access 'options' before initialization"
    const html = renderDynamicField(arrayField, {
      value: ['tag1', 'tag2'],
    });

    expect(html).toContain('data-structured-array');
    expect(html).toContain('data-field-name="tags"');
  });

  it('should render blocks array field without TDZ error', () => {
    const blocksField: FieldDefinition = {
      id: 'body-field',
      field_name: 'body',
      field_type: 'array',
      field_label: 'Content Blocks',
      field_options: {
        items: {
          type: 'object',
          discriminator: 'blockType',
          blocks: {
            text: {
              label: 'Text',
              properties: {
                heading: { type: 'string', title: 'Heading' },
                body: { type: 'textarea', title: 'Body' },
              },
            },
          },
        },
      },
      field_order: 1,
      is_required: false,
      is_searchable: false,
    };

    // This should not throw "ReferenceError: Cannot access 'options' before initialization"
    const html = renderDynamicField(blocksField, {
      value: [{ blockType: 'text', heading: 'Hello', body: 'World' }],
    });

    expect(html).toContain('blocks-field');
    expect(html).toContain('data-field-name="body"');
  });

  it('should render select field correctly (has the options variable)', () => {
    const selectField: FieldDefinition = {
      id: 'status-field',
      field_name: 'status',
      field_type: 'select',
      field_label: 'Status',
      field_options: {
        options: [
          { value: 'draft', label: 'Draft' },
          { value: 'published', label: 'Published' },
        ],
      },
      field_order: 1,
      is_required: false,
      is_searchable: false,
    };

    const html = renderDynamicField(selectField, { value: 'draft' });

    expect(html).toContain('<select');
    expect(html).toContain('value="draft"');
    expect(html).toContain('Draft');
    expect(html).toContain('Published');
  });

  it('should render object and select fields in the same test run without TDZ issues', () => {
    // This test verifies that both field types can be rendered together
    // without the const options declaration in select case causing TDZ issues

    const objectField: FieldDefinition = {
      id: 'seo-field',
      field_name: 'seo',
      field_type: 'object',
      field_label: 'SEO',
      field_options: {
        properties: {
          title: { type: 'string', title: 'Title' },
        },
      },
      field_order: 1,
      is_required: false,
      is_searchable: false,
    };

    const selectField: FieldDefinition = {
      id: 'category-field',
      field_name: 'category',
      field_type: 'select',
      field_label: 'Category',
      field_options: {
        options: ['tech', 'business'],
      },
      field_order: 2,
      is_required: false,
      is_searchable: false,
    };

    // Both should render without errors
    const objectHtml = renderDynamicField(objectField, { value: { title: 'Test' } });
    const selectHtml = renderDynamicField(selectField, { value: 'tech' });

    expect(objectHtml).toContain('data-structured-object');
    expect(selectHtml).toContain('<select');
  });
});

describe('renderDynamicField - Select enum fallback (Issue #763)', () => {
  it('should render select options from enum when opts.options is not set', () => {
    const selectField: FieldDefinition = {
      id: 'plan-field',
      field_name: 'plan',
      field_type: 'select',
      field_label: 'Plan',
      field_options: {
        enum: ['free', 'monthly', 'annual', 'lifetime'],
        enumLabels: ['Free', 'Monthly', 'Annual', 'Lifetime'],
      },
      field_order: 1,
      is_required: true,
      is_searchable: false,
    };

    const html = renderDynamicField(selectField, { value: 'free' });

    expect(html).toContain('<select');
    expect(html).toContain('value="free"');
    expect(html).toContain('Free');
    expect(html).toContain('Monthly');
    expect(html).toContain('Annual');
    expect(html).toContain('Lifetime');
    expect(html).toContain('selected');
  });

  it('should render select options from enum without enumLabels', () => {
    const selectField: FieldDefinition = {
      id: 'plan-field',
      field_name: 'plan',
      field_type: 'select',
      field_label: 'Plan',
      field_options: {
        enum: ['free', 'monthly'],
      },
      field_order: 1,
      is_required: false,
      is_searchable: false,
    };

    const html = renderDynamicField(selectField, { value: '' });

    expect(html).toContain('<select');
    expect(html).toContain('value="free"');
    expect(html).toContain('value="monthly"');
  });

  it('should prefer opts.options over opts.enum when both are present', () => {
    const selectField: FieldDefinition = {
      id: 'plan-field',
      field_name: 'plan',
      field_type: 'select',
      field_label: 'Plan',
      field_options: {
        options: [
          { value: 'a', label: 'Option A' },
          { value: 'b', label: 'Option B' },
        ],
        enum: ['x', 'y'],
      },
      field_order: 1,
      is_required: false,
      is_searchable: false,
    };

    const html = renderDynamicField(selectField, { value: 'a' });

    expect(html).toContain('Option A');
    expect(html).toContain('Option B');
    expect(html).not.toContain('value="x"');
  });
});

describe('renderDynamicField - Media', () => {
  const baseField: FieldDefinition = {
    id: 'test-field',
    field_name: 'media_field',
    field_type: 'media',
    field_label: 'Media Field',
    field_options: {},
    field_order: 1,
    is_required: false,
    is_searchable: false,
  };

  it('should render single media field correctly', () => {
    const html = renderDynamicField(baseField, { value: 'https://example.com/image.jpg' });

    expect(html).toContain('id="field-media_field"');
    expect(html).toContain('value="https://example.com/image.jpg"');
    expect(html).toContain('data-multiple="false"');
    expect(html).toContain('<img src="https://example.com/image.jpg"');
    expect(html).toContain('Select Media');
    expect(html).not.toContain('Select Media (Multiple)');
  });

  it('should render multiple media field correctly', () => {
    const multipleField = { ...baseField, field_options: { multiple: true } };
    const values = ['https://example.com/img1.jpg', 'https://example.com/img2.jpg'];
    const html = renderDynamicField(multipleField, { value: values });

    expect(html).toContain('data-multiple="true"');
    expect(html).toContain('value="https://example.com/img1.jpg,https://example.com/img2.jpg"');
    expect(html).toContain('Select Media (Multiple)');
    expect(html).toContain('media-preview-grid');
    expect(html).toContain('grid-cols-4');
    // Should render two items
    expect(html.match(/media-preview-item/g)?.length).toBe(2);
  });

  it('should render video preview for video files', () => {
    const html = renderDynamicField(baseField, { value: 'https://example.com/video.mp4' });

    expect(html).toContain('<video src="https://example.com/video.mp4"');
    expect(html).toContain('muted');
    expect(html).not.toContain('<img src="https://example.com/video.mp4"');
  });

  it('should render mixed image and video previews in multiple mode', () => {
    const multipleField = { ...baseField, field_options: { multiple: true } };
    const values = ['https://example.com/image.jpg', 'https://example.com/video.mp4'];
    const html = renderDynamicField(multipleField, { value: values });

    expect(html).toContain('<img src="https://example.com/image.jpg"');
    expect(html).toContain('<video src="https://example.com/video.mp4"');
  });

  it('should handle empty values in multiple mode', () => {
    const multipleField = { ...baseField, field_options: { multiple: true } };
    const html = renderDynamicField(multipleField, { value: [] });

    expect(html).toContain('value=""');
    expect(html).toContain('hidden'); // Preview grid should be hidden
  });
});
