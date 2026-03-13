import { Plugin } from '../../../types/plugin'
import { PluginBuilder } from '../../sdk/plugin-builder'

/**
 * EasyMDE Markdown Editor Plugin
 *
 * Provides markdown editing capabilities for richtext fields.
 * When active, this plugin injects the EasyMDE editor into all richtext field types.
 * When inactive, richtext fields fall back to plain textareas.
 */

const builder = PluginBuilder.create({
  name: 'easy-mdx',
  version: '1.0.0',
  description: 'Lightweight markdown editor with live preview'
})

builder.metadata({
  author: {
    name: 'SonicJS Team',
    email: 'team@sonicjs.com'
  },
  license: 'MIT',
  compatibility: '^2.0.0'
})

builder.lifecycle({
  activate: async () => {
    console.info('✅ EasyMDE editor plugin activated')
  },
  deactivate: async () => {
    console.info('❌ EasyMDE editor plugin deactivated')
  }
})

const easyMdxPlugin = builder.build() as Plugin

export default easyMdxPlugin

/**
 * Get EasyMDE CDN script tags
 * @returns HTML script and style tags for EasyMDE
 */
export function getMDXEditorScripts(): string {
  return `
    <!-- EasyMDE Markdown Editor -->
    <link rel="stylesheet" href="https://unpkg.com/easymde/dist/easymde.min.css">
    <script src="https://unpkg.com/easymde/dist/easymde.min.js"></script>
    <style>
      /* Dark mode styling for EasyMDE */
      .EasyMDEContainer {
        background-color: #1e293b;
      }

      .EasyMDEContainer .CodeMirror {
        background-color: #1e293b;
        color: #e2e8f0;
        border-color: #334155;
      }

      .EasyMDEContainer .CodeMirror-scroll {
        background-color: #1e293b;
      }

      .EasyMDEContainer .CodeMirror-cursor {
        border-left-color: #e2e8f0;
      }

      .EasyMDEContainer .CodeMirror-gutters {
        background-color: #0f172a;
        border-right-color: #334155;
      }

      .EasyMDEContainer .CodeMirror-linenumber {
        color: #64748b;
      }

      .editor-toolbar {
        background-color: #0f172a;
        border-color: #334155;
      }

      .editor-toolbar button {
        color: #94a3b8 !important;
      }

      .editor-toolbar button:hover,
      .editor-toolbar button.active {
        background-color: #334155;
        border-color: #475569;
        color: #e2e8f0 !important;
      }

      .editor-toolbar i.separator {
        border-left-color: #334155;
        border-right-color: #334155;
      }

      .editor-statusbar {
        background-color: #0f172a;
        color: #64748b;
        border-top-color: #334155;
      }

      .editor-preview,
      .editor-preview-side {
        background-color: #1e293b;
        color: #e2e8f0;
      }

      .CodeMirror-selected {
        background-color: #334155 !important;
      }

      .CodeMirror-focused .CodeMirror-selected {
        background-color: #475569 !important;
      }

      /* Syntax highlighting for dark mode */
      .cm-header {
        color: #60a5fa;
      }

      .cm-strong {
        color: #fbbf24;
      }

      .cm-em {
        color: #a78bfa;
      }

      .cm-link {
        color: #34d399;
      }

      .cm-url {
        color: #34d399;
      }

      .cm-quote {
        color: #94a3b8;
        font-style: italic;
      }

      .cm-comment {
        color: #64748b;
      }
    </style>
  `
}

/**
 * Get EasyMDE initialization script
 * @param config - Optional configuration object
 * @returns JavaScript initialization code
 */
export function getMDXEditorInitScript(config?: {
  defaultHeight?: number
  toolbar?: string
  placeholder?: string
}): string {
  const defaultHeight = config?.defaultHeight || 400
  const toolbar = config?.toolbar || 'full'
  const placeholder = config?.placeholder || 'Start writing your content...'

  return `
    // Initialize EasyMDE (Markdown Editor) only for markdown-marked fields
    function initializeMDXEditor() {
      if (typeof EasyMDE === 'undefined') {
        console.warn('EasyMDE not loaded yet, retrying...');
        setTimeout(initializeMDXEditor, 100);
        return;
      }

      // Find all textareas that need EasyMDE
      document.querySelectorAll('.richtext-container[data-editor-provider="easymde"] textarea').forEach((textarea) => {
        // Skip if already initialized
        if (textarea.dataset.mdxeditorInitialized === 'true') {
          return;
        }

        // Mark as initialized
        textarea.dataset.mdxeditorInitialized = 'true';

        // Get configuration from data attributes
        const container = textarea.closest('.richtext-container');
        const height = container?.dataset.height || ${defaultHeight};
        const editorToolbar = container?.dataset.toolbar || '${toolbar}';

        // Initialize EasyMDE
        try {
          const toolbarButtons = editorToolbar === 'minimal'
            ? ['bold', 'italic', 'heading', '|', 'quote', 'unordered-list', 'ordered-list', '|', 'link', 'preview']
            : ['bold', 'italic', 'heading', '|', 'quote', 'unordered-list', 'ordered-list', '|', 'link', 'image', 'table', '|', 'preview', 'side-by-side', 'fullscreen', '|', 'guide'];

          const easyMDE = new EasyMDE({
            element: textarea,
            placeholder: '${placeholder}',
            spellChecker: false,
            minHeight: height + 'px',
            toolbar: toolbarButtons,
            status: ['lines', 'words', 'cursor'],
            renderingConfig: {
              singleLineBreaks: false,
              codeSyntaxHighlighting: true
            }
          });

          // Store reference to editor instance
          textarea.easyMDEInstance = easyMDE;

          // Sync changes back to textarea
          easyMDE.codemirror.on("change", () => {
            textarea.value = easyMDE.value();
            textarea.dispatchEvent(new Event("input", { bubbles: true }));
            textarea.dispatchEvent(new Event("change", { bubbles: true }));
          });

          console.log('EasyMDE initialized for field:', textarea.id || textarea.name);
        } catch (error) {
          console.error('Error initializing EasyMDE:', error);
          // Show textarea as fallback
          textarea.style.display = 'block';
        }
      });
    }

    // Initialize on DOMContentLoaded
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initializeMDXEditor);
    } else {
      // DOM already loaded, initialize immediately
      initializeMDXEditor();
    }

    // Also reinitialize after HTMX swaps (for dynamic content)
    document.addEventListener('htmx:afterSwap', function(event) {
      // Give the DOM a moment to settle
      setTimeout(initializeMDXEditor, 100);
    });
  `
}

/**
 * Check if EasyMDE editor plugin is active
 * @param pluginService - Plugin service instance
 * @returns Promise<boolean>
 */
export async function isEasyMdxActive(pluginService: any): Promise<boolean> {
  try {
    const status = await pluginService.getPluginStatus('easy-mdx')
    return status?.is_active === true
  } catch (error) {
    console.error('Error checking EasyMDE editor plugin status:', error)
    return false
  }
}
