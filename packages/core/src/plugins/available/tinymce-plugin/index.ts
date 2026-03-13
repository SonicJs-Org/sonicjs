import { Plugin } from '../../../types/plugin'
import { PluginBuilder } from '../../sdk/plugin-builder'

/**
 * TinyMCE Rich Text Editor Plugin
 *
 * Provides WYSIWYG editing capabilities for richtext fields.
 * When active, this plugin injects the TinyMCE editor into all richtext field types.
 * When inactive, richtext fields fall back to plain textareas.
 */

const builder = PluginBuilder.create({
  name: 'tinymce-plugin',
  version: '1.0.0',
  description: 'Powerful WYSIWYG rich text editor for content creation'
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
    console.info('✅ TinyMCE plugin activated')
  },
  deactivate: async () => {
    console.info('❌ TinyMCE plugin deactivated')
  }
})

const tinymcePlugin = builder.build() as Plugin

export default tinymcePlugin

/**
 * Get TinyMCE CDN script tag
 * @param apiKey - Optional TinyMCE API key (defaults to 'no-api-key')
 * @returns HTML script tag for TinyMCE CDN
 */
export function getTinyMCEScript(apiKey: string = 'no-api-key'): string {
  return `<script src="https://cdn.tiny.cloud/1/${apiKey}/tinymce/6/tinymce.min.js" referrerpolicy="origin"></script>`
}

/**
 * Get TinyMCE initialization script
 * @param config - Optional configuration object
 * @returns JavaScript initialization code
 */
export function getTinyMCEInitScript(config?: {
  skin?: string
  defaultHeight?: number
  defaultToolbar?: string
}): string {
  const skin = config?.skin || 'oxide-dark'
  const contentCss = skin.includes('dark') ? 'dark' : 'default'
  const defaultHeight = config?.defaultHeight || 300

  return `
    // Initialize TinyMCE only for TinyMCE-backed richtext fields
    function initializeTinyMCE() {
      if (typeof tinymce !== 'undefined') {
        // Find all textareas that need TinyMCE
        document.querySelectorAll('.richtext-container[data-editor-provider="tinymce"] textarea').forEach((textarea) => {
          // Skip if already initialized
          if (tinymce.get(textarea.id)) {
            return;
          }

          // Get configuration from data attributes
          const container = textarea.closest('.richtext-container');
          const height = container?.dataset.height || ${defaultHeight};
          const toolbar = container?.dataset.toolbar || 'full';

          tinymce.init({
            selector: '#' + textarea.id,
            skin: '${skin}',
            content_css: '${contentCss}',
            height: parseInt(height),
            menubar: false,
            plugins: [
              'advlist', 'autolink', 'lists', 'link', 'image', 'charmap', 'preview',
              'anchor', 'searchreplace', 'visualblocks', 'code', 'fullscreen',
              'insertdatetime', 'media', 'table', 'help', 'wordcount'
            ],
            toolbar: toolbar === 'simple'
              ? 'bold italic underline | bullist numlist | link'
              : toolbar === 'minimal'
                ? 'bold italic | link'
                : 'undo redo | blocks | bold italic forecolor | alignleft aligncenter alignright alignjustify | bullist numlist outdent indent | removeformat | help',
            content_style: 'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; font-size: 14px }'
          });
        });
      }
    }

    // Initialize on DOMContentLoaded
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initializeTinyMCE);
    } else {
      // DOM already loaded, initialize immediately
      initializeTinyMCE();
    }

    // Also reinitialize after HTMX swaps (for dynamic content)
    document.addEventListener('htmx:afterSwap', function(event) {
      // Give the DOM a moment to settle
      setTimeout(initializeTinyMCE, 100);
    });
  `
}

/**
 * Check if TinyMCE plugin is active
 * @param pluginService - Plugin service instance
 * @returns Promise<boolean>
 */
export async function isTinyMCEActive(pluginService: any): Promise<boolean> {
  try {
    const status = await pluginService.getPluginStatus('tinymce-plugin')
    return status?.is_active === true
  } catch (error) {
    console.error('Error checking TinyMCE plugin status:', error)
    return false
  }
}
