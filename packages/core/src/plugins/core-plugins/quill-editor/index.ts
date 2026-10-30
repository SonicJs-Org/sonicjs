/**
 * Quill Rich Text Editor Plugin
 *
 * Provides Quill editor integration for rich text editing in SonicJS
 * https://quilljs.com/
 */

import { definePlugin } from '../../sdk/define-plugin'

/**
 * Quill Editor Configuration Options
 */
export interface QuillOptions {
  theme?: 'snow' | 'bubble'
  placeholder?: string
  height?: number
  toolbar?: 'full' | 'simple' | 'minimal' | string[][]
  modules?: Record<string, any>
  formats?: string[]
}

/**
 * Default Quill toolbar configurations
 */
const QUILL_TOOLBARS = {
  full: [
    [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
    ['bold', 'italic', 'underline', 'strike'],
    [{ 'color': [] }, { 'background': [] }],
    [{ 'align': [] }],
    [{ 'list': 'ordered'}, { 'list': 'bullet' }],
    [{ 'indent': '-1'}, { 'indent': '+1' }],
    ['blockquote', 'code-block'],
    ['link', 'image', 'video'],
    ['clean']
  ],
  simple: [
    ['bold', 'italic', 'underline'],
    [{ 'list': 'ordered'}, { 'list': 'bullet' }],
    ['link']
  ],
  minimal: [
    ['bold', 'italic'],
    ['link']
  ]
}

/**
 * Render a Quill editor field
 * @param fieldId - The field ID
 * @param fieldName - The field name
 * @param value - The current value
 * @param options - Quill configuration options
 * @returns HTML string for the Quill editor field
 */
export function renderQuillField(
  fieldId: string,
  fieldName: string,
  value: string = '',
  options: QuillOptions = {}
): string {
  const {
    theme = 'snow',
    placeholder = 'Enter content...',
    height = 300,
    toolbar = 'full'
  } = options

  // Escape HTML for hidden input
  const escapeHtml = (str: string) => {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
  }

  return `
    <div class="quill-editor-container" data-field-id="${fieldId}">
      <!-- Quill Editor Container -->
      <div
        id="${fieldId}-editor"
        class="quill-editor bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100"
        data-theme="${theme}"
        data-toolbar="${toolbar}"
        data-placeholder="${placeholder}"
        data-height="${height}"
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
}

/**
 * Generate Quill initialization script
 * @returns HTML script tag with Quill initialization code
 */
export function getQuillInitScript(): string {
  return `
    <script>
      // Global Quill initialization function
      window.initializeQuillEditors = function() {
        console.log('[Quill] initializeQuillEditors called');
        if (typeof Quill === 'undefined') {
          console.warn('[Quill] Quill is not loaded yet. Retrying...');
          setTimeout(window.initializeQuillEditors, 100);
          return;
        }

        console.log('[Quill] Quill is loaded, searching for editors...');
        // Find all Quill editor containers that haven't been initialized
        const containers = document.querySelectorAll('.quill-editor-container');
        console.log('[Quill] Found', containers.length, 'editor containers');

        containers.forEach((container, index) => {
          console.log('[Quill] Processing container', index);
          try {
          const editorDiv = container.querySelector('.quill-editor');
          if (!editorDiv || editorDiv.classList.contains('ql-container')) {
            return; // Already initialized or invalid
          }

          const fieldId = container.getAttribute('data-field-id');
          const hiddenInput = document.getElementById(fieldId);
          const theme = editorDiv.getAttribute('data-theme') || 'snow';
          const toolbarPreset = editorDiv.getAttribute('data-toolbar') || 'full';
          const placeholder = editorDiv.getAttribute('data-placeholder') || 'Enter content...';
          const height = parseInt(editorDiv.getAttribute('data-height') || '300');

          // Get toolbar configuration
          const toolbarConfig = ${JSON.stringify(QUILL_TOOLBARS)};
          const toolbar = toolbarConfig[toolbarPreset] || toolbarConfig.full;

          // Initialize Quill
          const quill = new Quill('#' + editorDiv.id, {
            theme: theme,
            placeholder: placeholder,
            modules: {
              toolbar: toolbar
            },
            formats: [
              'header', 'bold', 'italic', 'underline', 'strike',
              'color', 'background', 'align',
              'list', 'bullet', 'indent',
              'blockquote', 'code-block',
              'link', 'image', 'video'
            ]
          });

          // Set editor height
          const editorElement = editorDiv.querySelector('.ql-editor');
          if (editorElement) {
            editorElement.style.minHeight = height + 'px';
          }

          // Sync content to hidden input on change
          quill.on('text-change', function() {
            const html = quill.root.innerHTML;
            if (hiddenInput) {
              hiddenInput.value = html;
            }
          });

          // Store quill instance for potential later access
          editorDiv.quillInstance = quill;
          console.log('[Quill] Successfully initialized editor', index);
          } catch (error) {
            console.error('[Quill] Error initializing editor', index, ':', error);
          }
        });
        console.log('[Quill] Initialization complete');
      };

      // Initialize on DOM ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', window.initializeQuillEditors);
      } else {
        window.initializeQuillEditors();
      }

      // Re-initialize after HTMX swaps
      if (typeof htmx !== 'undefined') {
        document.body.addEventListener('htmx:afterSwap', window.initializeQuillEditors);
      }
    </script>
  `
}

/**
 * Generate Quill CDN links
 * @param version - Quill version (default: 2.0.2)
 * @returns HTML script and link tags for Quill CDN
 */
export function getQuillCDN(version: string = '2.0.2'): string {
  return `
    <!-- Quill Editor CSS -->
    <link href="https://cdn.jsdelivr.net/npm/quill@${version}/dist/quill.snow.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/quill@${version}/dist/quill.bubble.css" rel="stylesheet">

    <!-- Quill Editor JS -->
    <script src="https://cdn.jsdelivr.net/npm/quill@${version}/dist/quill.js"></script>

    <!-- Quill Dark Mode Styles -->
    <style>
      /* Dark mode styles for Quill editor */
      .dark .ql-toolbar {
        background-color: #18181b !important;
        border-color: #3f3f46 !important;
      }

      .dark .ql-toolbar button,
      .dark .ql-toolbar .ql-picker-label {
        color: #e4e4e7 !important;
      }

      .dark .ql-toolbar button:hover,
      .dark .ql-toolbar .ql-picker-label:hover {
        color: #fff !important;
      }

      .dark .ql-toolbar button.ql-active,
      .dark .ql-toolbar .ql-picker-label.ql-active {
        color: #3b82f6 !important;
      }

      .dark .ql-stroke {
        stroke: #e4e4e7 !important;
      }

      .dark .ql-fill {
        fill: #e4e4e7 !important;
      }

      .dark .ql-picker-options {
        background-color: #18181b !important;
        border-color: #3f3f46 !important;
      }

      .dark .ql-picker-item:hover {
        background-color: #27272a !important;
      }

      .dark .ql-container {
        background-color: #09090b !important;
        border-color: #3f3f46 !important;
        color: #e4e4e7 !important;
      }

      .dark .ql-editor {
        color: #e4e4e7 !important;
      }

      .dark .ql-editor.ql-blank::before {
        color: #71717a !important;
      }

      /* Improve contrast for dark mode */
      .dark .ql-snow .ql-stroke {
        stroke: #e4e4e7 !important;
      }

      .dark .ql-snow .ql-stroke.ql-fill {
        fill: #e4e4e7 !important;
      }

      .dark .ql-snow .ql-fill {
        fill: #e4e4e7 !important;
      }

      .dark .ql-snow .ql-picker-options {
        background-color: #18181b !important;
      }

      .dark .ql-snow .ql-picker-item:hover {
        color: #3b82f6 !important;
      }
    </style>
  `
}

export const quillEditorPlugin = definePlugin({
  id: 'quill-editor',
  version: '1.0.0',
  name: 'Quill Editor',
  description: 'Quill rich text editor integration for SonicJS.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  activate: async () => console.info('✅ Quill Editor plugin activated'),
  deactivate: async () => console.info('❌ Quill Editor plugin deactivated'),
})

export function createQuillEditorPlugin() {
  return quillEditorPlugin
}
