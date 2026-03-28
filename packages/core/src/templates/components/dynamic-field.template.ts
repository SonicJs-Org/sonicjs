import { getDragSortableScript } from './drag-sortable.template'

/**
 * Returns shared readFieldValue function used by both blocks and structured fields.
 * Uses a window flag to ensure it's only initialized once.
 */
function getReadFieldValueScript(): string {
  return `
    <script>
      if (!window.__sonicReadFieldValueInit) {
        window.__sonicReadFieldValueInit = true;

        window.sonicReadFieldValue = function(fieldWrapper) {
          const fieldType = fieldWrapper.dataset.fieldType;
          const select = fieldWrapper.querySelector('select');
          const textarea = fieldWrapper.querySelector('textarea');
          const inputs = Array.from(fieldWrapper.querySelectorAll('input'));
          const checkbox = inputs.find((input) => input.type === 'checkbox');
          const checkedRadio = inputs.find((input) => input.type === 'radio' && input.checked);
          const nonHiddenInput = inputs.find((input) => input.type !== 'hidden' && input.type !== 'checkbox');
          const hiddenInput = inputs.find((input) => input.type === 'hidden');

          if (fieldType === 'object' || fieldType === 'array') {
            if (!hiddenInput) {
              return fieldType === 'array' ? [] : {};
            }
            const rawValue = hiddenInput.value || '';
            if (!rawValue.trim()) {
              return fieldType === 'array' ? [] : {};
            }
            try {
              return JSON.parse(rawValue);
            } catch {
              return fieldType === 'array' ? [] : {};
            }
          }

          if (fieldType === 'boolean' && checkbox) {
            return checkbox.checked;
          }

          if (fieldType === 'radio') {
            return checkedRadio ? checkedRadio.value : '';
          }

          if (select) {
            if (select.multiple) {
              return Array.from(select.selectedOptions).map((option) => option.value);
            }
            return select.value;
          }

          if (fieldType === 'quill' || fieldType === 'media') {
            return hiddenInput ? hiddenInput.value : '';
          }

          const textSource = textarea || nonHiddenInput || hiddenInput;
          if (!textSource) {
            return '';
          }

          if (fieldType === 'number') {
            return textSource.value === '' ? null : Number(textSource.value);
          }

          return textSource.value;
        };
      }
    </script>
  `
}

export interface FieldDefinition {
  id: string
  field_name: string
  field_type: string
  field_label: string
  field_options: any // JSON options
  field_order: number
  is_required: boolean
  is_searchable: boolean
}

export interface FieldRenderOptions {
  value?: any
  errors?: string[]
  disabled?: boolean
  className?: string
  pluginStatuses?: {
    quillEnabled?: boolean
    mdxeditorEnabled?: boolean
    tinymceEnabled?: boolean
  }
  collectionId?: string
  contentId?: string
}

export function renderDynamicField(field: FieldDefinition, options: FieldRenderOptions = {}): string {
  const { value = '', errors = [], disabled = false, className = '', pluginStatuses = {}, collectionId = '', contentId = '' } = options
  const opts = field.field_options || {}
  const required = field.is_required ? 'required' : ''
  const baseClasses = `w-full rounded-lg px-3 py-2 text-sm text-zinc-950 dark:text-white bg-white dark:bg-zinc-800 shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow ${className}`
  const errorClasses = errors.length > 0 ? 'ring-pink-600 dark:ring-pink-500 focus:ring-pink-600 dark:focus:ring-pink-500' : ''

  const fieldId = `field-${field.field_name}`
  const fieldName = field.field_name

  // Check if this is a plugin-based field type and if the plugin is inactive
  // If so, fall back to textarea with a warning
  let fallbackToTextarea = false
  let fallbackWarning = ''

  if (field.field_type === 'quill' && !pluginStatuses.quillEnabled) {
    fallbackToTextarea = true
    fallbackWarning = '⚠️ Quill Editor plugin is inactive. Using textarea fallback.'
  } else if ((field.field_type === 'mdxeditor' || field.field_type === 'easymde' || field.field_type === 'markdown') && !pluginStatuses.mdxeditorEnabled) {
    fallbackToTextarea = true
    fallbackWarning = '⚠️ EasyMDE plugin is inactive. Using textarea fallback.'
  } else if (field.field_type === 'tinymce' && !pluginStatuses.tinymceEnabled) {
    fallbackToTextarea = true
    fallbackWarning = '⚠️ TinyMCE plugin is inactive. Using textarea fallback.'
  }

  // If falling back to textarea, render it with a warning
  if (fallbackToTextarea) {
    return `
      <div>
        ${fallbackWarning ? `<div class="mb-2 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 text-amber-900 dark:text-amber-200 text-xs rounded-lg border border-amber-200 dark:border-amber-800">${fallbackWarning}</div>` : ''}
        <textarea
          id="${fieldId}"
          name="${fieldName}"
          rows="${opts.rows || opts.height ? Math.floor(opts.height / 25) : 10}"
          placeholder="${opts.placeholder || ''}"
          maxlength="${opts.maxLength || ''}"
          class="${baseClasses} ${errorClasses} resize-y"
          ${required}
          ${disabled ? 'disabled' : ''}
        >${escapeHtml(value)}</textarea>
      </div>
    `
  }

  let fieldHTML = ''

  switch (field.field_type) {
    case 'text':
      let patternHelp = ''
      let autoSlugScript = ''
      
      if (opts.pattern) {
        if (opts.pattern === '^[a-z0-9-]+$' || opts.pattern === '^[a-zA-Z0-9_-]+$') {
          patternHelp = '<p class="mt-2 text-xs text-zinc-500 dark:text-zinc-400">Use letters, numbers, underscores, and hyphens only</p>'

          // Add auto-slug generation for slug fields
          if (fieldName === 'slug') {
            patternHelp += '<button type="button" class="mt-1 text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300" onclick="generateSlugFromTitle(\'${fieldId}\')">Generate from title</button>'
            autoSlugScript = `
              <script>
                function generateSlugFromTitle(slugFieldId) {
                  const titleField = document.querySelector('input[name="title"]');
                  const slugField = document.getElementById(slugFieldId);
                  if (titleField && slugField) {
                    const slug = titleField.value
                      .toLowerCase()
                      .replace(/[^a-z0-9\\s_-]/g, '')
                      .replace(/\\s+/g, '-')
                      .replace(/[-_]+/g, '-')
                      .replace(/^[-_]|[-_]$/g, '');
                    slugField.value = slug;
                  }
                }
                
                // Auto-generate slug when title changes
                document.addEventListener('DOMContentLoaded', function() {
                  const titleField = document.querySelector('input[name="title"]');
                  const slugField = document.getElementById('${fieldId}');
                  if (titleField && slugField && !slugField.value) {
                    titleField.addEventListener('input', function() {
                      if (!slugField.value) {
                        generateSlugFromTitle('${fieldId}');
                      }
                    });
                  }
                });
              </script>
            `
          }
        } else {
          patternHelp = '<p class="mt-2 text-xs text-zinc-500 dark:text-zinc-400">Must match required format</p>'
        }
      }
      
      fieldHTML = `
        <input 
          type="text" 
          id="${fieldId}"
          name="${fieldName}"
          value="${escapeHtml(value)}"
          placeholder="${opts.placeholder || ''}"
          maxlength="${opts.maxLength || ''}"
          ${opts.pattern ? `data-pattern="${opts.pattern}"` : ''}
          class="${baseClasses} ${errorClasses}"
          ${required}
          ${disabled ? 'disabled' : ''}
        >
        ${patternHelp}
        ${autoSlugScript}
        ${opts.pattern ? `
        <script>
          (function() {
            const field = document.getElementById('${fieldId}');
            const pattern = new RegExp('${opts.pattern}');
            
            field.addEventListener('input', function() {
              if (this.value && !pattern.test(this.value)) {
                if ('${opts.pattern}' === '^[a-zA-Z0-9_-]+$' || '${opts.pattern}' === '^[a-z0-9-]+$') {
                  this.setCustomValidity('Please use only letters, numbers, underscores, and hyphens.');
                } else {
                  this.setCustomValidity('Please enter a valid format.');
                }
              } else {
                this.setCustomValidity('');
              }
            });
            
            field.addEventListener('blur', function() {
              this.reportValidity();
            });
          })();
        </script>
        ` : ''}
      `
      break

    case 'textarea':
      fieldHTML = `
        <textarea
          id="${fieldId}"
          name="${fieldName}"
          rows="${opts.rows || 6}"
          placeholder="${opts.placeholder || ''}"
          maxlength="${opts.maxLength || ''}"
          class="${baseClasses} ${errorClasses} resize-y"
          ${required}
          ${disabled ? 'disabled' : ''}
        >${escapeHtml(value)}</textarea>
      `
      break

    case 'richtext':
      fieldHTML = `
        <div class="richtext-container" data-height="${opts.height || 300}" data-toolbar="${opts.toolbar || 'full'}">
          <textarea
            id="${fieldId}"
            name="${fieldName}"
            class="${baseClasses} ${errorClasses} min-h-[${opts.height || 300}px]"
            ${required}
            ${disabled ? 'disabled' : ''}
          >${escapeHtml(value)}</textarea>
        </div>
      `
      break

    case 'quill':
      // Quill WYSIWYG Editor
      fieldHTML = `
        <div class="quill-editor-container" data-field-id="${fieldId}">
          <!-- Quill Editor Container -->
          <div
            id="${fieldId}-editor"
            class="quill-editor bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100"
            data-theme="${opts.theme || 'snow'}"
            data-toolbar="${opts.toolbar || 'full'}"
            data-placeholder="${opts.placeholder || 'Enter content...'}"
            data-height="${opts.height || 300}"
          >${value}</div>

          <!-- Hidden input to store the actual content for form submission -->
          <input
            type="hidden"
            id="${fieldId}"
            name="${fieldName}"
            value="${escapeHtml(value)}"
          >
        </div>
      `
      break

    case 'mdxeditor':
    case 'tinymce':
    case 'easymde':
    case 'markdown':
      // Markdown/TinyMCE/MDX rich text editors render the same container as richtext.
      // The editor plugin initialization scripts will handle the editor setup.
      fieldHTML = `
        <div class="richtext-container" data-height="${opts.height || 300}" data-toolbar="${opts.toolbar || 'full'}">
          <textarea
            id="${fieldId}"
            name="${fieldName}"
            class="${baseClasses} ${errorClasses} min-h-[${opts.height || 300}px]"
            ${required}
            ${disabled ? 'disabled' : ''}
          >${escapeHtml(value)}</textarea>
        </div>
      `
      break

    case 'number':
      fieldHTML = `
        <input 
          type="number" 
          id="${fieldId}"
          name="${fieldName}"
          value="${value}"
          min="${opts.min || ''}"
          max="${opts.max || ''}"
          step="${opts.step || ''}"
          placeholder="${opts.placeholder || ''}"
          class="${baseClasses} ${errorClasses}"
          ${required}
          ${disabled ? 'disabled' : ''}
        >
      `
      break
      
    case 'boolean':
      const checked = value === true || value === 'true' || value === '1' ? 'checked' : ''
      fieldHTML = `
        <div class="flex items-center space-x-3">
          <input 
            type="checkbox" 
            id="${fieldId}"
            name="${fieldName}"
            value="true"
            class="w-5 h-5 text-blue-600 bg-white/10 border-white/20 rounded focus:ring-blue-500 focus:ring-2"
            ${checked}
            ${disabled ? 'disabled' : ''}
          >
          <label for="${fieldId}" class="text-sm text-gray-300">
            ${opts.checkboxLabel || field.field_label}
          </label>
        </div>
        <input type="hidden" name="${fieldName}_submitted" value="1">
      `
      break
      
    case 'date':
      fieldHTML = `
        <input
          type="date"
          id="${fieldId}"
          name="${fieldName}"
          value="${value}"
          min="${opts.min || ''}"
          max="${opts.max || ''}"
          class="${baseClasses} ${errorClasses}"
          ${required}
          ${disabled ? 'disabled' : ''}
        >
      `
      break

    case 'datetime':
      fieldHTML = `
        <input
          type="datetime-local"
          id="${fieldId}"
          name="${fieldName}"
          value="${value}"
          min="${opts.min || ''}"
          max="${opts.max || ''}"
          class="${baseClasses} ${errorClasses}"
          ${required}
          ${disabled ? 'disabled' : ''}
        >
      `
      break

    case 'slug':
      // Slug fields with auto-generation and duplicate detection
      const slugPattern = opts.pattern || '^[a-z0-9-]+$'
      const collectionIdValue = collectionId || opts.collectionId || ''
      const contentIdValue = contentId || opts.contentId || ''
      const isEditMode = !!value
      
      fieldHTML = `
        <div class="slug-field-container">
          <input
            type="text"
            id="${fieldId}"
            name="${fieldName}"
            value="${escapeHtml(value)}"
            placeholder="${opts.placeholder || 'url-friendly-slug'}"
            maxlength="${opts.maxLength || 100}"
            data-pattern="${slugPattern}"
            data-collection-id="${collectionIdValue}"
            data-content-id="${contentIdValue}"
            data-is-edit-mode="${isEditMode}"
            class="${baseClasses} ${errorClasses}"
            ${required}
            ${disabled ? 'disabled' : ''}
          >
          <div id="${fieldId}-status" class="slug-status mt-1 text-sm min-h-[20px]"></div>
          <button 
            type="button" 
            class="regenerate-slug-btn mt-2 text-sm text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300 flex items-center gap-1 transition-colors"
            onclick="window.regenerateSlugFromTitle_${fieldId.replace(/-/g, '_')}()"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
            </svg>
            Regenerate from title
          </button>
          <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">Use lowercase letters, numbers, and hyphens only</p>
        </div>
        
        <script>
          (function() {
            const slugField = document.getElementById('${fieldId}');
            const statusDiv = document.getElementById('${fieldId}-status');
            const isEditMode = slugField.dataset.isEditMode === 'true';
            const pattern = new RegExp('${slugPattern}');
            const collectionId = slugField.dataset.collectionId;
            const contentId = slugField.dataset.contentId;
            
            let checkTimeout;
            let lastCheckedSlug = '';
            let manuallyEdited = false;
            
            // Shared slug generation function
            function generateSlug(text) {
              if (!text) return '';
              
              return text
                .toLowerCase()
                .normalize('NFD')
                .replace(/[\\u0300-\\u036f]/g, '')
                .replace(/[^a-z0-9\\s_-]/g, '')
                .replace(/\\s+/g, '-')
                .replace(/[-_]+/g, '-')
                .replace(/^[-_]+|[-_]+$/g, '')
                .substring(0, 100);
            }
            
            // Check if slug is available
            async function checkSlugAvailability(slug) {
              if (!slug || !collectionId) return;
              
              // Don't check if it's the same as last time
              if (slug === lastCheckedSlug) return;
              lastCheckedSlug = slug;
              
              try {
                // Show checking status
                statusDiv.innerHTML = '<span class="text-gray-400">⏳ Checking availability...</span>';
                
                // Build URL
                let url = \`/api/content/check-slug?collectionId=\${encodeURIComponent(collectionId)}&slug=\${encodeURIComponent(slug)}\`;
                if (contentId) {
                  url += \`&excludeId=\${encodeURIComponent(contentId)}\`;
                }
                
                const response = await fetch(url);
                const data = await response.json();
                
                if (data.available) {
                  statusDiv.innerHTML = '<span class="text-green-500 dark:text-green-400">✓ Available</span>';
                  slugField.setCustomValidity('');
                } else {
                  statusDiv.innerHTML = \`<span class="text-red-500 dark:text-red-400">✗ \${data.message || 'Already in use'}</span>\`;
                  slugField.setCustomValidity(data.message || 'This slug is already in use');
                }
              } catch (error) {
                console.error('Error checking slug:', error);
                statusDiv.innerHTML = '<span class="text-yellow-500 dark:text-yellow-400">⚠ Could not verify</span>';
              }
            }
            
            // Format validation and duplicate checking
            slugField.addEventListener('input', function() {
              const value = this.value;
              
              // Mark as manually edited if user types directly
              if (document.activeElement === this) {
                manuallyEdited = true;
              }
              
              // Clear status if empty
              if (!value) {
                statusDiv.innerHTML = '';
                this.setCustomValidity('');
                return;
              }
              
              // Pattern validation
              if (!pattern.test(value)) {
                this.setCustomValidity('Please use only lowercase letters, numbers, and hyphens.');
                statusDiv.innerHTML = '<span class="text-red-500 dark:text-red-400">✗ Invalid format</span>';
                return;
              }
              
              // Debounce the availability check
              clearTimeout(checkTimeout);
              checkTimeout = setTimeout(() => {
                checkSlugAvailability(value);
              }, 500); // Wait 500ms after user stops typing
            });
            
            // Initial check if field has value
            if (slugField.value) {
              checkSlugAvailability(slugField.value);
            }
            
            // Auto-generate only in create mode
            // Wait for all fields to be rendered before attaching listeners
            if (!isEditMode) {
              // Use setTimeout to ensure all fields in the form are rendered
              setTimeout(() => {
                const titleField = document.querySelector('input[name="title"]');
                if (titleField) {
                  titleField.addEventListener('input', function() {
                    if (!manuallyEdited) {
                      const slug = generateSlug(this.value);
                      slugField.value = slug;
                      
                      // Trigger validation and duplicate check
                      slugField.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                  });
                }
              }, 0);
            }
            
            // Global function for regenerate button
            window.regenerateSlugFromTitle_${fieldId.replace(/-/g, '_')} = function() {
              const titleField = document.querySelector('input[name="title"]');
              if (titleField && slugField) {
                const slug = generateSlug(titleField.value);
                slugField.value = slug;
                manuallyEdited = false;
                
                // Trigger validation and duplicate check
                slugField.dispatchEvent(new Event('input', { bubbles: true }));
              }
            };
          })();
        </script>
      `
      break

    case 'select':
      const selectOptions = opts.options || []
      const multiple = opts.multiple ? 'multiple' : ''
      const selectedValues = Array.isArray(value) ? value : [value]

      fieldHTML = `
        <select
          id="${fieldId}"
          name="${fieldName}${opts.multiple ? '[]' : ''}"
          class="${baseClasses} ${errorClasses}"
          ${multiple}
          ${required}
          ${disabled ? 'disabled' : ''}
        >
          ${!required && !opts.multiple ? '<option value="">Choose an option...</option>' : ''}
          ${selectOptions.map((option: any) => {
            const optionValue = typeof option === 'string' ? option : option.value
            const optionLabel = typeof option === 'string' ? option : option.label
            const selected = selectedValues.includes(optionValue) ? 'selected' : ''
            return `<option value="${escapeHtml(optionValue)}" ${selected}>${escapeHtml(optionLabel)}</option>`
          }).join('')}
        </select>
        ${opts.allowCustom ? `
          <div class="mt-2">
            <input 
              type="text" 
              placeholder="Add custom option..."
              class="${baseClasses.replace('border-white/10', 'border-white/5')} text-sm"
              onkeypress="if(event.key==='Enter'){addCustomOption(this, '${fieldId}');event.preventDefault();}"
            >
          </div>
        ` : ''}
      `
      break

    case 'radio':
      const radioOptions =
        opts.options ||
        (Array.isArray(opts.enum)
          ? opts.enum.map((optionValue: string, index: number) => ({
              value: optionValue,
              label: opts.enumLabels?.[index] || optionValue,
            }))
          : [])
      const selectedRadioValue =
        value !== undefined && value !== null
          ? String(value)
          : opts.default
            ? String(opts.default)
            : ''

      const isInline = opts.inline === true
      fieldHTML = `
        <div class="${isInline ? 'flex flex-wrap gap-4' : 'space-y-3'}">
          ${radioOptions
            .map((option: any, index: number) => {
              const optionValue = typeof option === 'string' ? option : option.value
              const optionLabel = typeof option === 'string' ? option : option.label
              const inputId = `${fieldId}-option-${index}`
              const checked = selectedRadioValue === String(optionValue) ? 'checked' : ''
              return `
                <label for="${inputId}" class="flex items-center gap-3 text-sm text-zinc-700 dark:text-zinc-300">
                  <input
                    type="radio"
                    id="${inputId}"
                    name="${fieldName}"
                    value="${escapeHtml(optionValue)}"
                    class="h-4 w-4 text-zinc-900 focus:ring-zinc-400 dark:text-white dark:focus:ring-white"
                    ${checked}
                    ${required}
                    ${disabled ? 'disabled' : ''}
                  >
                  <span>${escapeHtml(optionLabel)}</span>
                </label>
              `
            })
            .join('')}
        </div>
      `
      break

    case 'reference':
      let referenceCollections: string[] = []
      if (Array.isArray(opts.collection)) {
        referenceCollections = opts.collection.filter(Boolean)
      } else if (typeof opts.collection === 'string' && opts.collection) {
        referenceCollections = [opts.collection]
      }
      const referenceCollectionsAttr = referenceCollections.join(',')
      const hasReferenceCollection = referenceCollections.length > 0
      const hasReferenceValue = Boolean(value)
      fieldHTML = `
        <div class="reference-field-container" data-reference-field data-field-name="${escapeHtml(fieldName)}" data-reference-collection="${escapeHtml(referenceCollections[0] || '')}" data-reference-collections="${escapeHtml(referenceCollectionsAttr)}" data-reference-enabled="${hasReferenceCollection ? 'true' : 'false'}">
          <input type="hidden" id="${fieldId}" name="${fieldName}" value="${escapeHtml(value)}">
          <div class="flex flex-wrap items-start gap-2">
            <div
              class="min-w-[220px] flex-1 rounded-lg border border-zinc-200 bg-white/60 px-3 py-2 text-sm text-zinc-600 dark:border-white/10 dark:bg-white/5 dark:text-zinc-300 ${hasReferenceCollection ? 'cursor-pointer hover:border-zinc-300 dark:hover:border-white/20' : 'cursor-not-allowed opacity-80'}"
              data-reference-display
              data-reference-trigger
              role="button"
              tabindex="${hasReferenceCollection ? '0' : '-1'}"
              aria-disabled="${hasReferenceCollection ? 'false' : 'true'}"
            >
              ${hasReferenceCollection ? (hasReferenceValue ? 'Loading selection...' : 'No reference selected.') : 'Reference collection not configured.'}
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onclick="openReferenceSelector('${fieldId}')"
                class="inline-flex items-center justify-center rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white/10 dark:hover:bg-white/20"
                ${hasReferenceCollection ? '' : 'disabled'}
              >
                Select reference
              </button>
              <button
                type="button"
                onclick="clearReferenceField('${fieldId}')"
                class="inline-flex items-center justify-center rounded-lg border border-zinc-200 px-3 py-2 text-sm font-semibold text-zinc-700 hover:bg-zinc-100 dark:border-white/10 dark:text-zinc-200 dark:hover:bg-white/10"
                data-reference-clear
                ${hasReferenceValue ? '' : 'disabled'}
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      `
      break

    case 'media':
      // Check if multiple selection is enabled
      const isMultiple = opts.multiple === true
      const mediaValues = isMultiple && value ? (Array.isArray(value) ? value : String(value).split(',').filter(Boolean)) : []
      const singleValue = !isMultiple ? value : ''

      // Helper to detect if URL is a video
      const isVideoUrl = (url: string) => {
        const videoExtensions = ['.mp4', '.webm', '.ogg', '.mov', '.avi']
        return videoExtensions.some(ext => url.toLowerCase().endsWith(ext))
      }

      // Helper to render media element
      const renderMediaPreview = (url: string, alt: string, classes: string) => {
        if (isVideoUrl(url)) {
          return `<video src="${url}" class="${classes}" muted></video>`
        }
        return `<img src="${url}" alt="${alt}" class="${classes}">`
      }

      fieldHTML = `
        <div class="media-field-container">
          <input type="hidden" id="${fieldId}" name="${fieldName}" value="${isMultiple ? mediaValues.join(',') : singleValue}" data-multiple="${isMultiple}">

          ${isMultiple ? `
            <div class="media-preview-grid grid grid-cols-4 gap-2 mb-2 ${mediaValues.length === 0 ? 'hidden' : ''}" id="${fieldId}-preview">
              ${mediaValues.map((url: string, idx: number) => `
                <div class="relative media-preview-item" data-url="${url}">
                  ${renderMediaPreview(url, `Media ${idx + 1}`, 'w-full h-24 object-cover rounded-lg border border-white/20')}
                  <button
                    type="button"
                    onclick="removeMediaFromMultiple('${fieldId}', '${url}')"
                    class="absolute top-1 right-1 bg-red-600 text-white rounded-full p-1 hover:bg-red-700"
                    ${disabled ? 'disabled' : ''}
                  >
                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                  </button>
                </div>
              `).join('')}
            </div>
          ` : `
            <div class="media-preview ${singleValue ? '' : 'hidden'}" id="${fieldId}-preview">
              ${singleValue ? renderMediaPreview(singleValue, 'Selected media', 'w-32 h-32 object-cover rounded-lg border border-white/20') : ''}
            </div>
          `}

          <div class="media-actions mt-2 space-x-2">
            <button
              type="button"
              onclick="openMediaSelector('${fieldId}', ${isMultiple})"
              class="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-all"
              ${disabled ? 'disabled' : ''}
            >
              <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
              </svg>
              ${isMultiple ? 'Select Media (Multiple)' : 'Select Media'}
            </button>
            ${(isMultiple ? mediaValues.length > 0 : singleValue) ? `
              <button
                type="button"
                onclick="clearMediaField('${fieldId}')"
                class="inline-flex items-center px-4 py-2 bg-red-600 text-white rounded-xl hover:bg-red-700 transition-all"
                ${disabled ? 'disabled' : ''}
              >
                ${isMultiple ? 'Clear All' : 'Remove'}
              </button>
            ` : ''}
          </div>
        </div>
      `
      break

    case 'object':
      // Structured object field (like SEO with nested properties)
      return renderStructuredObjectField(field, options, baseClasses, errorClasses)

    case 'array':
      // Check if this is a blocks field (has discriminator/blocks config) or a regular array
      const itemsConfig = opts.items && typeof opts.items === 'object' ? opts.items : {}
      if (itemsConfig.blocks && typeof itemsConfig.blocks === 'object') {
        // Blocks field with discriminated union
        return renderBlocksField(field, options, baseClasses, errorClasses)
      }
      // Regular structured array field
      return renderStructuredArrayField(field, options, baseClasses, errorClasses)

    default:
      fieldHTML = `
        <input
          type="text"
          id="${fieldId}"
          name="${fieldName}"
          value="${escapeHtml(value)}"
          class="${baseClasses} ${errorClasses}"
          ${required}
          ${disabled ? 'disabled' : ''}
        >
      `
  }
  
  const showLabel = field.field_type !== 'boolean'

  return `
    <div class="form-group">
      ${showLabel ? `
      <label for="${fieldId}" class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">
        ${escapeHtml(field.field_label)}
        ${field.is_required ? '<span class="text-pink-600 dark:text-pink-400 ml-1">*</span>' : ''}
      </label>
      ` : ''}
      ${fieldHTML}
      ${errors.length > 0 ? `
        <div class="mt-2 text-sm text-pink-600 dark:text-pink-400">
          ${errors.map(error => `<div>${escapeHtml(error)}</div>`).join('')}
        </div>
      ` : ''}
      ${opts.helpText ? `
        <div class="mt-2 text-xs text-zinc-500 dark:text-zinc-400">
          ${escapeHtml(opts.helpText)}
        </div>
      ` : ''}
    </div>
  `
}

export function renderFieldGroup(title: string, fields: string[], collapsible: boolean = false): string {
  const groupId = title.toLowerCase().replace(/\s+/g, '-')

  return `
    <div class="field-group rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 mb-6">
      <div class="field-group-header border-b border-zinc-950/5 dark:border-white/10 px-6 py-4 ${collapsible ? 'cursor-pointer' : ''}" ${collapsible ? `onclick="toggleFieldGroup('${groupId}')"` : ''}>
        <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white flex items-center">
          ${escapeHtml(title)}
          ${collapsible ? `
            <svg id="${groupId}-icon" class="w-5 h-5 ml-2 transform transition-transform text-zinc-500 dark:text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
            </svg>
          ` : ''}
        </h3>
      </div>
      <div id="${groupId}-content" class="field-group-content px-6 py-6 space-y-6 ${collapsible ? 'collapsible' : ''}">
        ${fields.join('')}
      </div>
    </div>
  `
}

function renderBlocksField(
  field: FieldDefinition,
  options: FieldRenderOptions,
  baseClasses: string,
  errorClasses: string
): string {
  const { value = [], pluginStatuses = {} } = options
  const opts = field.field_options || {}
  const itemsConfig = opts.items && typeof opts.items === 'object' ? opts.items : {}
  const blocks = normalizeBlockDefinitions(itemsConfig.blocks)
  const discriminator =
    typeof itemsConfig.discriminator === 'string' && itemsConfig.discriminator
      ? itemsConfig.discriminator
      : 'blockType'
  const blockValues = normalizeBlocksValue(value, discriminator)
  const fieldId = `field-${field.field_name}`
  const fieldName = field.field_name
  const emptyState =
    blockValues.length === 0
      ? `
    <div class="rounded-lg border border-dashed border-zinc-200 dark:border-white/10 px-4 py-6 text-center text-sm text-zinc-500 dark:text-zinc-400" data-blocks-empty>
      No blocks yet. Add your first block to get started.
    </div>
  `
      : ''

  const blockOptions = blocks
    .map((block) => `<option value="${escapeHtml(block.name)}">${escapeHtml(block.label)}</option>`)
    .join('')

  const blockItems = blockValues
    .map((blockValue, index) =>
      renderBlockItem(field, blockValue, blocks, discriminator, index, pluginStatuses)
    )
    .join('')

  const templates = blocks
    .map((block) => renderBlockTemplate(field, block, discriminator, pluginStatuses))
    .join('')

  return `
    <div
      class="blocks-field space-y-4"
      data-blocks='${escapeHtml(JSON.stringify(blocks))}'
      data-blocks-discriminator="${escapeHtml(discriminator)}"
      data-field-name="${escapeHtml(fieldName)}"
    >
      <input type="hidden" id="${fieldId}" name="${fieldName}" value="${escapeHtml(JSON.stringify(blockValues))}">

      <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex-1">
          <select
            class="${baseClasses} ${errorClasses}"
            data-role="block-type-select"
          >
            <option value="">Choose a block...</option>
            ${blockOptions}
          </select>
        </div>
        <button
          type="button"
          data-action="add-block"
          class="inline-flex items-center justify-center rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white/10 dark:hover:bg-white/20"
        >
          Add Block
        </button>
      </div>

      <div class="space-y-4" data-blocks-list>
        ${blockItems || emptyState}
      </div>

      ${templates}
    </div>
    ${getDragSortableScript()}
    ${getBlocksFieldScript()}
  `
}

function renderStructuredObjectField(
  field: FieldDefinition,
  options: FieldRenderOptions,
  baseClasses: string,
  errorClasses: string
): string {
  const { value = {}, pluginStatuses = {} } = options
  const opts = field.field_options || {}
  const properties = opts.properties && typeof opts.properties === 'object' ? opts.properties : {}
  const fieldId = `field-${field.field_name}`
  const fieldName = field.field_name
  const objectValue = normalizeStructuredObjectValue(value)

  const subfields = Object.entries(properties)
    .map(([propertyName, propertyConfig]) =>
      renderStructuredSubfield(
        field,
        propertyName,
        propertyConfig,
        objectValue,
        pluginStatuses,
        field.field_name
      )
    )
    .join('')

  return `
    <div class="space-y-4" data-structured-object data-field-name="${escapeHtml(fieldName)}">
      <input type="hidden" id="${fieldId}" name="${fieldName}" value="${escapeHtml(JSON.stringify(objectValue))}">
      <div class="space-y-4" data-structured-object-fields>
        ${subfields}
      </div>
    </div>
    ${getStructuredFieldScript()}
  `
}

function renderStructuredArrayField(
  field: FieldDefinition,
  options: FieldRenderOptions,
  baseClasses: string,
  errorClasses: string
): string {
  const { value = [], pluginStatuses = {} } = options
  const opts = field.field_options || {}
  const itemsConfig = opts.items && typeof opts.items === 'object' ? opts.items : {}
  const fieldId = `field-${field.field_name}`
  const fieldName = field.field_name
  const arrayValue = normalizeStructuredArrayValue(value)
  const arrayTitle = opts.itemLabel || field.field_label || 'Items'
  const hasItemTitle = typeof opts.itemTitle === 'string' && opts.itemTitle.trim() !== ''
  const arrayItemTitle = hasItemTitle ? opts.itemTitle.trim() : 'Item'
  const addItemLabel = hasItemTitle ? `Add ${arrayItemTitle}` : 'Add item'

  const items = arrayValue
    .map((itemValue, index) =>
      renderStructuredArrayItem(
        field,
        itemsConfig,
        String(index),
        itemValue,
        pluginStatuses,
        arrayItemTitle,
      ),
    )
    .join('')

  const emptyState =
    arrayValue.length === 0
      ? `
    <div class="rounded-lg border border-dashed border-zinc-200 dark:border-white/10 px-4 py-6 text-center text-sm text-zinc-500 dark:text-zinc-400" data-structured-empty>
      No items yet. Add the first item to get started.
    </div>
  `
      : ''

  return `
    <div class="space-y-4" data-structured-array data-field-name="${escapeHtml(fieldName)}">
      <input type="hidden" id="${fieldId}" name="${fieldName}" value="${escapeHtml(JSON.stringify(arrayValue))}">

      <div class="flex items-center justify-between gap-3">
        <div class="text-sm text-zinc-500 dark:text-zinc-400">
          ${escapeHtml(arrayTitle)}
        </div>
        <button
          type="button"
          data-action="add-item"
          class="inline-flex items-center justify-center rounded-lg bg-zinc-900 px-3 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white/10 dark:hover:bg-white/20"
        >
          ${escapeHtml(addItemLabel)}
        </button>
      </div>

      <div class="space-y-4" data-structured-array-list>
        ${items || emptyState}
      </div>

      <template data-structured-array-template>
        ${renderStructuredArrayItem(
          field,
          itemsConfig,
          '__INDEX__',
          {},
          pluginStatuses,
          arrayItemTitle,
        )}
      </template>
    </div>
    ${getDragSortableScript()}
    ${getStructuredFieldScript()}
  `
}

function renderStructuredArrayItem(
  field: FieldDefinition,
  itemConfig: Record<string, any>,
  index: string,
  itemValue: any,
  pluginStatuses: FieldRenderOptions['pluginStatuses'],
  arrayItemTitle: string,
): string {
  const itemFields = renderStructuredItemFields(field, itemConfig, index, itemValue, pluginStatuses)

  return `
    <div class="structured-array-item rounded-lg border border-zinc-200 dark:border-white/10 bg-white/60 dark:bg-white/5 p-4 shadow-sm" data-array-index="${escapeHtml(index)}" draggable="true">
      <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-center gap-3">
          <div class="drag-handle cursor-move text-zinc-400 dark:text-zinc-500 hover:text-zinc-600 dark:hover:text-zinc-400" data-action="drag-handle" title="Drag to reorder">
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 8h16M4 16h16"/>
            </svg>
          </div>
          <div class="text-sm font-semibold text-zinc-900 dark:text-white cursor-pointer" data-action="toggle-item">
            ${escapeHtml(arrayItemTitle)} <span class="ml-2 text-xs font-normal text-zinc-500 dark:text-zinc-400" data-array-order-label></span>
          </div>
        </div>
        <div class="flex flex-wrap gap-2 text-xs">
          <button type="button" data-action="move-up" class="inline-flex items-center justify-center rounded-md border border-zinc-200 px-2 py-1 text-zinc-600 hover:bg-zinc-100 dark:border-white/10 dark:text-zinc-300 dark:hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent dark:disabled:hover:bg-transparent" aria-label="Move item up" title="Move up">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="4">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 6l-4 4m4-4l4 4m-4-4v12"/>
            </svg>
          </button>
          <button type="button" data-action="move-down" class="inline-flex items-center justify-center rounded-md border border-zinc-200 px-2 py-1 text-zinc-600 hover:bg-zinc-100 dark:border-white/10 dark:text-zinc-300 dark:hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent dark:disabled:hover:bg-transparent" aria-label="Move item down" title="Move down">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="4">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 18l4-4m-4 4l-4-4m4 4V6"/>
            </svg>
          </button>
          <button type="button" data-action="remove-item" class="inline-flex items-center gap-x-1 px-2.5 py-1.5 text-xs font-medium text-pink-700 dark:text-pink-300 hover:bg-pink-50 dark:hover:bg-pink-900/20 rounded-lg transition-colors">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/>
            </svg>
            Delete item
          </button>
        </div>
      </div>
      <div class="mt-4 space-y-4" data-array-item-fields>
        ${itemFields}
      </div>
    </div>
  `
}

function renderStructuredItemFields(
  field: FieldDefinition,
  itemConfig: Record<string, any>,
  index: string,
  itemValue: any,
  pluginStatuses: FieldRenderOptions['pluginStatuses']
): string {
  const itemType = itemConfig?.type || 'string'
  if (itemType === 'object' && itemConfig?.properties && typeof itemConfig.properties === 'object') {
    const fieldPrefix = `array-${field.field_name}-${index}`
    return Object.entries(itemConfig.properties)
      .map(([propertyName, propertyConfig]) =>
        renderStructuredSubfield(
          field,
          propertyName,
          propertyConfig,
          itemValue || {},
          pluginStatuses,
          fieldPrefix
        )
      )
      .join('')
  }

  const normalizedField = normalizeBlockField(itemConfig, 'Item')
  const fieldValue = itemValue ?? normalizedField.defaultValue ?? ''
  const fieldDefinition: FieldDefinition = {
    id: `array-${field.field_name}-${index}-value`,
    field_name: `array-${field.field_name}-${index}-value`,
    field_type: normalizedField.type,
    field_label: normalizedField.label,
    field_options: normalizedField.options,
    field_order: 0,
    is_required: normalizedField.required,
    is_searchable: false,
  }

  return `
    <div class="structured-subfield" data-structured-field="__value" data-field-type="${escapeHtml(normalizedField.type)}">
      ${renderDynamicField(fieldDefinition, { value: fieldValue, pluginStatuses })}
    </div>
  `
}

function renderStructuredSubfield(
  field: FieldDefinition,
  propertyName: string,
  propertyConfig: any,
  objectValue: Record<string, any>,
  pluginStatuses: FieldRenderOptions['pluginStatuses'],
  fieldPrefix: string
): string {
  const normalizedField = normalizeBlockField(propertyConfig, propertyName)
  const fieldValue = objectValue?.[propertyName] ?? normalizedField.defaultValue ?? ''
  const fieldDefinition: FieldDefinition = {
    id: `${fieldPrefix}-${propertyName}`,
    field_name: `${fieldPrefix}__${propertyName}`,
    field_type: normalizedField.type,
    field_label: normalizedField.label,
    field_options: normalizedField.options,
    field_order: 0,
    is_required: normalizedField.required,
    is_searchable: false,
  }

  return `
    <div class="structured-subfield" data-structured-field="${escapeHtml(propertyName)}" data-field-type="${escapeHtml(normalizedField.type)}">
      ${renderDynamicField(fieldDefinition, { value: fieldValue, pluginStatuses })}
    </div>
  `
}

function normalizeStructuredObjectValue(value: any): Record<string, any> {
  if (!value) return {}
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
    } catch {
      return {}
    }
  }
  if (typeof value === 'object' && !Array.isArray(value)) return value
  return {}
}

function normalizeStructuredArrayValue(value: any): any[] {
  if (!value) return []
  if (Array.isArray(value)) return value
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  }
  return []
}

function normalizeBlockDefinitions(
  rawBlocks: any
): Array<{ name: string; label: string; description?: string; properties: Record<string, any> }> {
  if (!rawBlocks || typeof rawBlocks !== 'object') return []

  return Object.entries(rawBlocks)
    .filter(([name, block]) => typeof name === 'string' && block && typeof block === 'object')
    .map(([name, block]: [string, any]) => ({
      name,
      label: block.label || name,
      description: block.description,
      properties: block.properties && typeof block.properties === 'object' ? block.properties : {},
    }))
}

function normalizeBlocksValue(value: any, discriminator: string): any[] {
  const normalizeItem = (item: any) => {
    if (!item || typeof item !== 'object') return null
    if (item[discriminator]) return item
    if (item.blockType && item.data && typeof item.data === 'object') {
      return { [discriminator]: item.blockType, ...item.data }
    }
    return item
  }

  const fromArray = (items: any[]) =>
    items.map(normalizeItem).filter((item) => item && typeof item === 'object')

  if (Array.isArray(value)) return fromArray(value)
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return Array.isArray(parsed) ? fromArray(parsed) : []
    } catch {
      return []
    }
  }
  return []
}

function renderBlockTemplate(
  field: FieldDefinition,
  block: { name: string; label: string; description?: string; properties: Record<string, any> },
  discriminator: string,
  pluginStatuses: FieldRenderOptions['pluginStatuses']
): string {
  return `
    <template data-block-template="${escapeHtml(block.name)}">
      ${renderBlockCard(field, block, discriminator, '__INDEX__', {}, pluginStatuses)}
    </template>
  `
}

function renderBlockItem(
  field: FieldDefinition,
  blockValue: any,
  blocks: Array<{
    name: string
    label: string
    description?: string
    properties: Record<string, any>
  }>,
  discriminator: string,
  index: number,
  pluginStatuses: FieldRenderOptions['pluginStatuses']
): string {
  const blockType = blockValue?.[discriminator] || blockValue?.blockType
  const blockDefinition = blocks.find((block) => block.name === blockType)

  if (!blockDefinition) {
    return `
      <div class="rounded-lg border border-amber-200 bg-amber-50/50 px-4 py-3 text-sm text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200" data-block-raw="${escapeHtml(JSON.stringify(blockValue || {}))}">
        Unknown block type: <strong>${escapeHtml(String(blockType || 'unknown'))}</strong>. This block will be preserved as-is.
      </div>
    `
  }

  const data =
    blockValue && typeof blockValue === 'object'
      ? Object.fromEntries(Object.entries(blockValue).filter(([key]) => key !== discriminator))
      : {}

  return renderBlockCard(field, blockDefinition, discriminator, String(index), data, pluginStatuses)
}

function renderBlockCard(
  field: FieldDefinition,
  block: { name: string; label: string; description?: string; properties: Record<string, any> },
  discriminator: string,
  index: string,
  data: Record<string, any>,
  pluginStatuses: FieldRenderOptions['pluginStatuses']
): string {
  const blockFields = Object.entries(block.properties)
    .map(([fieldName, fieldConfig]) => {
      if (fieldConfig?.type === 'array' && fieldConfig?.items?.blocks) {
        return `
        <div class="rounded-lg border border-dashed border-amber-200 bg-amber-50/50 px-4 py-3 text-xs text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200">
          Nested blocks are not supported yet for "${escapeHtml(fieldName)}".
        </div>
      `
      }

      const normalizedField = normalizeBlockField(fieldConfig, fieldName)
      const fieldValue = data?.[fieldName] ?? normalizedField.defaultValue ?? ''
      const fieldDefinition: FieldDefinition = {
        id: `block-${field.field_name}-${index}-${fieldName}`,
        field_name: `block-${field.field_name}-${index}-${fieldName}`,
        field_type: normalizedField.type,
        field_label: normalizedField.label,
        field_options: normalizedField.options,
        field_order: 0,
        is_required: normalizedField.required,
        is_searchable: false,
      }

      return `
      <div class="blocks-subfield" data-block-field="${escapeHtml(fieldName)}" data-field-type="${escapeHtml(normalizedField.type)}">
        ${renderDynamicField(fieldDefinition, { value: fieldValue, pluginStatuses })}
      </div>
    `
    })
    .join('')

  return `
    <div class="blocks-item rounded-lg border border-zinc-200 dark:border-white/10 bg-white/60 dark:bg-white/5 p-4 shadow-sm" data-block-type="${escapeHtml(block.name)}" data-block-discriminator="${escapeHtml(discriminator)}" draggable="true">
      <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-start gap-3">
          <div class="drag-handle cursor-move text-zinc-400 dark:text-zinc-500 hover:text-zinc-600 dark:hover:text-zinc-400" data-action="drag-handle" title="Drag to reorder">
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 8h16M4 16h16"/>
            </svg>
          </div>
          <div>
            <div class="text-sm font-semibold text-zinc-900 dark:text-white">
              ${escapeHtml(block.label)}
              <span class="ml-2 text-xs font-normal text-zinc-500 dark:text-zinc-400" data-block-order-label></span>
            </div>
            ${block.description ? `<p class="text-xs text-zinc-500 dark:text-zinc-400">${escapeHtml(block.description)}</p>` : ''}
          </div>
        </div>
        <div class="flex flex-wrap gap-2 text-xs">
          <button type="button" data-action="move-up" class="inline-flex items-center justify-center rounded-md border border-zinc-200 px-2 py-1 text-zinc-600 hover:bg-zinc-100 dark:border-white/10 dark:text-zinc-300 dark:hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent dark:disabled:hover:bg-transparent" aria-label="Move block up" title="Move up">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="4">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 6l-4 4m4-4l4 4m-4-4v12"/>
            </svg>
          </button>
          <button type="button" data-action="move-down" class="inline-flex items-center justify-center rounded-md border border-zinc-200 px-2 py-1 text-zinc-600 hover:bg-zinc-100 dark:border-white/10 dark:text-zinc-300 dark:hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent dark:disabled:hover:bg-transparent" aria-label="Move block down" title="Move down">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="4">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 18l4-4m-4 4l-4-4m4 4V6"/>
            </svg>
          </button>
          <button type="button" data-action="remove-block" class="inline-flex items-center gap-x-1 px-2.5 py-1.5 text-xs font-medium text-pink-700 dark:text-pink-300 hover:bg-pink-50 dark:hover:bg-pink-900/20 rounded-lg transition-colors">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/>
            </svg>
            Delete block
          </button>
        </div>
      </div>
      <div class="mt-4 space-y-4">
        ${blockFields}
      </div>
    </div>
  `
}

function normalizeBlockField(fieldConfig: any, fieldName: string) {
  const type = fieldConfig?.type || 'text'
  const label = fieldConfig?.title || fieldName
  const required = fieldConfig?.required === true
  const options = { ...fieldConfig }

  if (type === 'select' && Array.isArray(fieldConfig?.enum)) {
    options.options = fieldConfig.enum.map((value: string, index: number) => ({
      value,
      label: fieldConfig.enumLabels?.[index] || value,
    }))
  }

  return {
    type,
    label,
    required,
    defaultValue: fieldConfig?.default,
    options,
  }
}

function getStructuredFieldScript(): string {
  return `
    ${getReadFieldValueScript()}
    <script>
      if (!window.__sonicStructuredFieldInit) {
        window.__sonicStructuredFieldInit = true;

        function initializeStructuredFields() {
          const readFieldValue = window.sonicReadFieldValue;

          const readStructuredValue = (container) => {
            const fields = Array.from(container.querySelectorAll('.structured-subfield'));
            if (fields.length === 1 && fields[0].dataset.structuredField === '__value') {
              return readFieldValue(fields[0]);
            }

            return fields.reduce((acc, fieldWrapper) => {
              const fieldName = fieldWrapper.dataset.structuredField;
              if (!fieldName || fieldName === '__value') return acc;
              acc[fieldName] = readFieldValue(fieldWrapper);
              return acc;
            }, {});
          };

          document.querySelectorAll('[data-structured-object]').forEach((container) => {
            if (container.dataset.structuredInitialized === 'true') {
              return;
            }
            container.dataset.structuredInitialized = 'true';
            const hiddenInput = container.querySelector('input[type="hidden"]');

            const updateHiddenInput = () => {
              if (!hiddenInput) return;
              const value = readStructuredValue(container);
              hiddenInput.value = JSON.stringify(value);
            };

            container.addEventListener('input', updateHiddenInput);
            container.addEventListener('change', updateHiddenInput);
            updateHiddenInput();
          });

          document.querySelectorAll('[data-structured-array]').forEach((container) => {
            if (container.dataset.structuredInitialized === 'true') {
              return;
            }
            container.dataset.structuredInitialized = 'true';
            const list = container.querySelector('[data-structured-array-list]');
            const hiddenInput = container.querySelector('input[type="hidden"]');
            const template = container.querySelector('template[data-structured-array-template]');

            const updateOrderLabels = () => {
              const items = Array.from(container.querySelectorAll('.structured-array-item'));
              items.forEach((item, index) => {
                const label = item.querySelector('[data-array-order-label]');
                if (label) {
                  label.textContent = '#'+ (index + 1);
                }

                const moveUpButton = item.querySelector('[data-action="move-up"]');
                if (moveUpButton instanceof HTMLButtonElement) {
                  moveUpButton.disabled = index === 0;
                }

                const moveDownButton = item.querySelector('[data-action="move-down"]');
                if (moveDownButton instanceof HTMLButtonElement) {
                  moveDownButton.disabled = index === items.length - 1;
                }
              });
            };

            const updateHiddenInput = () => {
              if (!hiddenInput || !list) return;
              const items = Array.from(list.querySelectorAll('.structured-array-item'));
              const values = items.map((item) => readStructuredValue(item));
              hiddenInput.value = JSON.stringify(values);

              const emptyState = list.querySelector('[data-structured-empty]');
              if (emptyState) {
                emptyState.style.display = values.length === 0 ? 'block' : 'none';
              }
              updateOrderLabels();
            };

            if (typeof window.initializeDragSortable === 'function' && list) {
              window.initializeDragSortable(list, {
                itemSelector: '.structured-array-item',
                handleSelector: '[data-action="drag-handle"]',
                onUpdate: updateHiddenInput
              });
            }

            container.addEventListener('click', (event) => {
              const target = event.target;
              if (!(target instanceof Element)) return;
              const actionButton = target.closest('[data-action]');
              if (!actionButton || actionButton.hasAttribute('disabled')) return;

              const action = actionButton.getAttribute('data-action');

              if (action === 'add-item') {
                if (!list || !template) return;
                const nextIndex = list.querySelectorAll('.structured-array-item').length;
                const html = template.innerHTML.replace(/__INDEX__/g, String(nextIndex));
                list.insertAdjacentHTML('beforeend', html);
                if (typeof initializeTinyMCE === 'function') {
                  initializeTinyMCE();
                }
                if (typeof window.initializeQuillEditors === 'function') {
                  window.initializeQuillEditors();
                }
                if (typeof initializeMDXEditor === 'function') {
                  initializeMDXEditor();
                }
                updateHiddenInput();
                return;
              }

              const item = actionButton.closest('.structured-array-item');
              if (!item || !list) return;

              if (action === 'remove-item') {
                if (typeof requestRepeaterDelete === 'function') {
                  requestRepeaterDelete(() => {
                    item.remove();
                    updateHiddenInput();
                  });
                } else {
                  item.remove();
                  updateHiddenInput();
                }
                return;
              }

              if (action === 'move-up') {
                const previous = item.previousElementSibling;
                if (previous) {
                  list.insertBefore(item, previous);
                  updateHiddenInput();
                }
                return;
              }

              if (action === 'move-down') {
                const next = item.nextElementSibling;
                if (next) {
                  list.insertBefore(next, item);
                  updateHiddenInput();
                }
              }
            });

            container.addEventListener('input', (event) => {
              const target = event.target;
              if (!(target instanceof Element)) return;
              if (target.closest('[data-structured-array-list]')) {
                updateHiddenInput();
              }
            });

            container.addEventListener('change', (event) => {
              const target = event.target;
              if (!(target instanceof Element)) return;
              if (target.closest('[data-structured-array-list]')) {
                updateHiddenInput();
              }
            });

            updateHiddenInput();
          });
        }

        window.initializeStructuredFields = initializeStructuredFields;

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initializeStructuredFields);
        } else {
          initializeStructuredFields();
        }

        document.addEventListener('htmx:afterSwap', function() {
          setTimeout(initializeStructuredFields, 50);
        });
      } else if (typeof window.initializeStructuredFields === 'function') {
        window.initializeStructuredFields();
      }
    </script>
  `
}

function getBlocksFieldScript(): string {
  return `
    ${getReadFieldValueScript()}
    <script>
      if (!window.__sonicBlocksFieldInit) {
        window.__sonicBlocksFieldInit = true;

        function initializeBlocksFields() {
          document.querySelectorAll('.blocks-field').forEach((container) => {
            if (container.dataset.blocksInitialized === 'true') {
              return;
            }

            container.dataset.blocksInitialized = 'true';
            const list = container.querySelector('[data-blocks-list]');
            const hiddenInput = container.querySelector('input[type="hidden"]');
            const typeSelect = container.querySelector('[data-role="block-type-select"]');
            const discriminator = container.dataset.blocksDiscriminator || 'blockType';

            const updateOrderLabels = () => {
              const items = Array.from(container.querySelectorAll('.blocks-item'));
              items.forEach((item, index) => {
                const label = item.querySelector('[data-block-order-label]');
                if (label) {
                  label.textContent = '#'+ (index + 1);
                }

                const moveUpButton = item.querySelector('[data-action="move-up"]');
                if (moveUpButton instanceof HTMLButtonElement) {
                  moveUpButton.disabled = index === 0;
                }

                const moveDownButton = item.querySelector('[data-action="move-down"]');
                if (moveDownButton instanceof HTMLButtonElement) {
                  moveDownButton.disabled = index === items.length - 1;
                }
              });
            };

            const readFieldValue = window.sonicReadFieldValue;

            const readBlockItem = (item) => {
              if (item.dataset.blockRaw) {
                try {
                  return JSON.parse(item.dataset.blockRaw);
                } catch (error) {
                  return {};
                }
              }

              const blockType = item.dataset.blockType;
              const data = {};

              item.querySelectorAll('.blocks-subfield').forEach((fieldWrapper) => {
                const fieldName = fieldWrapper.dataset.blockField;
                if (!fieldName) {
                  return;
                }
                data[fieldName] = readFieldValue(fieldWrapper);
              });

              return { [discriminator]: blockType, ...data };
            };

            const updateHiddenInput = () => {
              if (!hiddenInput || !list) return;
              const items = Array.from(list.querySelectorAll('.blocks-item, [data-block-raw]'));
              const blocksData = items.map((item) => readBlockItem(item));
              hiddenInput.value = JSON.stringify(blocksData);

              const emptyState = list.querySelector('[data-blocks-empty]');
              if (emptyState) {
                emptyState.style.display = blocksData.length === 0 ? 'block' : 'none';
              }
              updateOrderLabels();
            };

            const initializeEditors = () => {
              if (typeof initializeTinyMCE === 'function') {
                initializeTinyMCE();
              }
              if (typeof window.initializeQuillEditors === 'function') {
                window.initializeQuillEditors();
              }
              if (typeof initializeMDXEditor === 'function') {
                initializeMDXEditor();
              }
            };

            if (typeof window.initializeDragSortable === 'function' && list) {
              window.initializeDragSortable(list, {
                itemSelector: '.blocks-item',
                handleSelector: '[data-action="drag-handle"]',
                onUpdate: updateHiddenInput
              });
            }

            container.addEventListener('click', (event) => {
              const target = event.target;
              if (!(target instanceof Element)) return;
              const actionButton = target.closest('[data-action]');
              if (!actionButton) return;

              if (actionButton.hasAttribute('disabled')) {
                return;
              }

              const action = actionButton.getAttribute('data-action');
              if (action === 'add-block') {
                const blockType = typeSelect ? typeSelect.value : '';
                if (!blockType || !list) return;
                const template = container.querySelector('template[data-block-template="' + blockType + '"]');
                if (!template) return;

                const nextIndex = list.querySelectorAll('.blocks-item').length;
                const html = template.innerHTML.replace(/__INDEX__/g, String(nextIndex));
                list.insertAdjacentHTML('beforeend', html);
                if (typeSelect) {
                  typeSelect.value = '';
                }
                initializeEditors();
                if (typeof window.initializeStructuredFields === 'function') {
                  window.initializeStructuredFields();
                }
                updateHiddenInput();
                return;
              }

              const item = actionButton.closest('.blocks-item');
              if (!item || !list) return;

              if (action === 'remove-block') {
                if (typeof requestRepeaterDelete === 'function') {
                  requestRepeaterDelete(() => {
                    item.remove();
                    updateHiddenInput();
                  }, 'block');
                } else {
                  item.remove();
                  updateHiddenInput();
                }
                return;
              }

              if (action === 'move-up') {
                const previous = item.previousElementSibling;
                if (previous) {
                  list.insertBefore(item, previous);
                  updateHiddenInput();
                }
                return;
              }

              if (action === 'move-down') {
                const next = item.nextElementSibling;
                if (next) {
                  list.insertBefore(next, item);
                  updateHiddenInput();
                }
              }
            });

            container.addEventListener('input', (event) => {
              const target = event.target;
              if (!(target instanceof Element)) return;
              if (target.closest('[data-blocks-list]')) {
                updateHiddenInput();
              }
            });

            container.addEventListener('change', (event) => {
              const target = event.target;
              if (!(target instanceof Element)) return;
              if (target.closest('[data-blocks-list]')) {
                updateHiddenInput();
              }
            });

            updateHiddenInput();
          });
        }

        window.initializeBlocksFields = initializeBlocksFields;

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initializeBlocksFields);
        } else {
          initializeBlocksFields();
        }

        document.addEventListener('htmx:afterSwap', function() {
          setTimeout(initializeBlocksFields, 50);
        });
      } else if (typeof window.initializeBlocksFields === 'function') {
        window.initializeBlocksFields();
      }
    </script>
  `
}

function escapeHtml(text: string): string {
  if (typeof text !== 'string') return String(text || '')
  return text.replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char] || char))
}
