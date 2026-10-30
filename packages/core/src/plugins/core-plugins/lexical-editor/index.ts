/**
 * Lexical Rich Text Editor Plugin
 *
 * Provides Lexical editor integration for rich text editing in SonicJS.
 * https://github.com/facebook/lexical
 *
 * On by default for greenfield installs (defaultActive: true).
 * Used as the default rich text field editor — collections with field type
 * 'richtext' render Lexical when this plugin is active.
 */

import { definePlugin } from '../../sdk/define-plugin'

export const LEXICAL_VERSION = '0.21.0'

export type LexicalToolbarItem =
  | 'bold' | 'italic' | 'underline' | 'strikethrough'
  | 'h1' | 'h2' | 'h3'
  | 'bulletList' | 'orderedList'
  | 'blockquote' | 'link' | 'code'
  | 'undo' | 'redo' | '|'

export interface LexicalOptions {
  /**
   * Toolbar preset or explicit item list.
   * - 'full': all tools including undo/redo
   * - 'standard': common formatting without undo/redo
   * - 'minimal': bold, italic, link only
   * - string[]: explicit list of toolbar items
   */
  toolbar?: 'full' | 'standard' | 'minimal' | LexicalToolbarItem[]
  placeholder?: string
  height?: number
}

const TOOLBAR_PRESETS: Record<string, LexicalToolbarItem[]> = {
  full: [
    'undo', 'redo', '|',
    'bold', 'italic', 'underline', 'strikethrough', '|',
    'h1', 'h2', 'h3', '|',
    'bulletList', 'orderedList', 'blockquote', '|',
    'link', 'code',
  ],
  standard: [
    'bold', 'italic', 'underline', '|',
    'h1', 'h2', 'h3', '|',
    'bulletList', 'orderedList', '|',
    'link',
  ],
  minimal: ['bold', 'italic', '|', 'link'],
}

const TOOLBAR_ICONS: Record<string, string> = {
  bold: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8.21 13c2.106 0 3.412-1.087 3.412-2.823 0-1.306-.984-2.283-2.324-2.386v-.055a2.176 2.176 0 0 0 1.852-2.14c0-1.51-1.162-2.46-3.014-2.46H3.843V13H8.21zM5.908 4.674h1.696c.963 0 1.517.451 1.517 1.244 0 .834-.629 1.32-1.73 1.32H5.908V4.674zm0 6.788V8.598h1.73c1.217 0 1.88.492 1.88 1.415 0 .943-.643 1.449-1.832 1.449H5.908z"/></svg>',
  italic: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M7.991 11.674 9.53 4.455c.123-.595.246-.71 1.347-.807l.11-.52H7.211l-.11.52c1.06.096 1.128.212 1.005.807L6.57 11.674c-.123.595-.246.71-1.346.806l-.11.52h3.774l.11-.52c-1.06-.095-1.129-.211-1.006-.806z"/></svg>',
  underline: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M5.313 3.136h-1.23V9.54c0 2.105 1.47 3.623 3.917 3.623s3.917-1.518 3.917-3.623V3.136h-1.23v6.323c0 1.49-.978 2.57-2.687 2.57-1.709 0-2.687-1.08-2.687-2.57V3.136zM12.5 15h-9v-1h9v1z"/></svg>',
  strikethrough: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6.333 5.686c0 .31.083.581.27.814H5.166a2.776 2.776 0 0 1-.099-.76c0-1.627 1.436-2.768 3.48-2.768 1.969 0 3.39 1.175 3.39 2.800 0 .73-.21 1.35-.617 1.82-.43.482-.938.756-1.45.87l-.01.01h.002c.069-.002.133-.004.2-.004 1.56 0 2.621.99 2.621 2.39 0 1.7-1.368 2.75-3.636 2.75-1.942 0-3.31-1.15-3.394-2.768h1.107c.101 1.007.893 1.648 2.287 1.648 1.395 0 2.18-.636 2.18-1.63 0-.997-.754-1.62-2.18-1.62h-.894v-1.006h.894c1.293 0 2.073-.578 2.073-1.525 0-.903-.668-1.453-1.85-1.453-1.12 0-1.88.55-1.98 1.35z"/><path d="M6 7h4v1H6z"/></svg>',
  h1: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8.637 13V3.669H7.379V7.62H2.758V3.67H1.5V13h1.258V8.728h4.621V13h1.258zm5.329 0V3.669h-1.244L10.5 5.316v1.265l2.16-1.565h.062V13h1.244z"/></svg>',
  h2: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M7.638 13V3.669H6.38V7.62H1.759V3.67H.5V13h1.258V8.728h4.62V13h1.259zm3.022-6.733v-.048c0-.889.63-1.668 1.716-1.668.957 0 1.675.608 1.675 1.572 0 .855-.554 1.504-1.067 2.085l-3.513 3.999V13H15.5v-1.094h-4.245v-.075l2.481-2.844c.875-.998 1.586-1.784 1.586-2.953 0-1.463-1.155-2.556-2.919-2.556-1.941 0-2.966 1.326-2.966 2.74v.049h1.223z"/></svg>',
  h3: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M7.637 13V3.669H6.379V7.62H1.758V3.67H.5V13h1.258V8.728h4.62V13h1.259zm3.625-4.272h1.018c1.142 0 1.935.67 1.949 1.674.013 1.005-.78 1.737-2.01 1.73-1.08-.007-1.853-.588-1.935-1.32H9.108c.069 1.327 1.224 2.386 3.083 2.386 1.935 0 3.343-1.155 3.309-2.819-.03-1.002-.6-1.89-1.344-2.099v-.038c.867-.197 1.406-.83 1.406-1.725 0-.822-.566-1.38-1.364-1.386-1.35-.014-2.46 1.03-2.52 2.264H10.4c.05-.76.69-1.244 1.462-1.244.76 0 1.284.435 1.284 1.101 0 .673-.542 1.135-1.374 1.135h-.91v1.1z"/></svg>',
  bulletList: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M5 11.5a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm-3 1a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm0 4a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm0 4a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/></svg>',
  orderedList: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M5 11.5a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5z"/><path d="M1.713 11.865v-.474H2c.217 0 .363-.137.363-.317 0-.185-.158-.31-.361-.31-.223 0-.367.145-.373.38H1.25c.01-.57.54-.906 1.011-.906.522 0 .924.293.924.86 0 .405-.257.61-.548.71v.019c.384.07.636.34.636.75 0 .66-.540 1.021-1.08 1.021-.52 0-1.01-.316-1.02-.929h.418c.005.234.194.378.502.378.276 0 .44-.144.44-.364 0-.23-.184-.38-.487-.38H1.8v-.4h-.087zm1.362-7.249h-.086L2.5 5.996v.431l.59-.229h.016v2.232h.427V4.616h-.457z"/></svg>',
  blockquote: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M12 12a1 1 0 0 0 1-1V8.558a1 1 0 0 0-1-1h-1.388c0-.351.021-.703.062-1.054.062-.372.166-.703.31-.992.145-.29.331-.517.559-.683.227-.186.516-.279.868-.279V3c-.579 0-1.085.124-1.52.372a3.322 3.322 0 0 0-1.085.992 4.92 4.92 0 0 0-.62 1.458A7.712 7.712 0 0 0 9 7.558V11a1 1 0 0 0 1 1h2Zm-6 0a1 1 0 0 0 1-1V8.558a1 1 0 0 0-1-1H4.612c0-.351.021-.703.062-1.054.062-.372.166-.703.31-.992.145-.29.331-.517.559-.683.227-.186.516-.279.868-.279V3c-.579 0-1.085.124-1.52.372a3.322 3.322 0 0 0-1.085.992 4.92 4.92 0 0 0-.62 1.458A7.712 7.712 0 0 0 3 7.558V11a1 1 0 0 0 1 1h2Z"/></svg>',
  link: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M4.715 6.542 3.343 7.914a3 3 0 1 0 4.243 4.243l1.828-1.829A3 3 0 0 0 8.586 5.5L8 6.086a1.002 1.002 0 0 0-.154.199 2 2 0 0 1 .861 3.337L6.88 11.45a2 2 0 1 1-2.83-2.83l.793-.792a4.018 4.018 0 0 1-.128-1.287z"/><path d="M6.586 4.672A3 3 0 0 0 7.414 9.5l.775-.776a2 2 0 0 1-.896-3.346L9.12 3.55a2 2 0 1 1 2.83 2.83l-.793.792c.112.42.155.855.128 1.287l1.372-1.372a3 3 0 1 0-4.243-4.243L6.586 4.672z"/></svg>',
  code: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M5.854 4.854a.5.5 0 1 0-.708-.708l-3.5 3.5a.5.5 0 0 0 0 .708l3.5 3.5a.5.5 0 0 0 .708-.708L2.707 8l3.147-3.146zm4.292 0a.5.5 0 0 1 .708-.708l3.5 3.5a.5.5 0 0 1 0 .708l-3.5 3.5a.5.5 0 0 1-.708-.708L13.293 8l-3.147-3.146z"/></svg>',
  undo: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 3a5 5 0 1 1-4.546 2.914.5.5 0 0 0-.908-.417A6 6 0 1 0 8 2v1z"/><path d="M8 4.466V.534a.25.25 0 0 0-.41-.192L5.23 2.308a.25.25 0 0 0 0 .384l2.36 1.966A.25.25 0 0 0 8 4.466z"/></svg>',
  redo: '<svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2v1z"/><path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466z"/></svg>',
}

export function renderLexicalField(
  fieldId: string,
  fieldName: string,
  value: string = '',
  options: LexicalOptions = {}
): string {
  const { toolbar = 'standard', placeholder = 'Enter content...', height = 300 } = options
  const toolbarItems: LexicalToolbarItem[] =
    typeof toolbar === 'string'
      ? (TOOLBAR_PRESETS[toolbar] ?? TOOLBAR_PRESETS.standard!)
      : toolbar

  const escapedValue = value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')

  const toolbarHTML = toolbarItems
    .map(item => {
      if (item === '|') {
        return `<div class="lexical-toolbar-sep" aria-hidden="true"></div>`
      }
      return `<button type="button" class="lexical-toolbar-btn" data-action="${item}" title="${item}" aria-label="${item}">${TOOLBAR_ICONS[item] ?? item}</button>`
    })
    .join('')

  return `
    <div
      class="lexical-editor-wrapper"
      data-field-id="${fieldId}"
      data-toolbar="${typeof toolbar === 'string' ? toolbar : 'custom'}"
      data-height="${height}"
      data-placeholder="${placeholder}"
    >
      <div class="lexical-toolbar" id="${fieldId}-toolbar" role="toolbar" aria-label="Text formatting">
        ${toolbarHTML}
      </div>
      <div class="lexical-editor-surface" style="min-height:${height}px">
        <div
          id="${fieldId}-editor"
          class="lexical-content-editable"
          contenteditable="true"
          role="textbox"
          aria-multiline="true"
          aria-label="${placeholder}"
          spellcheck="true"
        ></div>
        <div id="${fieldId}-placeholder" class="lexical-placeholder" aria-hidden="true">${placeholder}</div>
      </div>
      <input type="hidden" id="${fieldId}" name="${fieldName}" value="${escapedValue}">
    </div>
  `
}

export function getLexicalStyles(): string {
  return `
    <style id="lexical-editor-styles">
      /* ── Wrapper ────────────────────────────────────────────────────── */
      .lexical-editor-wrapper {
        border: 1px solid rgba(0,0,0,0.10);
        border-radius: 0.5rem;
        overflow: hidden;
        background: #fff;
      }
      .dark .lexical-editor-wrapper {
        border-color: rgba(255,255,255,0.10);
        background: #18181b;
      }

      /* ── Toolbar ────────────────────────────────────────────────────── */
      .lexical-toolbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 2px;
        padding: 6px 8px;
        border-bottom: 1px solid rgba(0,0,0,0.08);
        background: #f4f4f5;
      }
      .dark .lexical-toolbar {
        background: #27272a;
        border-bottom-color: rgba(255,255,255,0.08);
      }
      .lexical-toolbar-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        padding: 0;
        border: none;
        border-radius: 4px;
        background: transparent;
        color: #52525b;
        cursor: pointer;
        transition: background 0.1s, color 0.1s;
      }
      .lexical-toolbar-btn:hover {
        background: rgba(0,0,0,0.08);
        color: #18181b;
      }
      .lexical-toolbar-btn.active {
        background: rgba(59,130,246,0.15);
        color: #2563eb;
      }
      .dark .lexical-toolbar-btn { color: #a1a1aa; }
      .dark .lexical-toolbar-btn:hover { background: rgba(255,255,255,0.1); color: #fff; }
      .dark .lexical-toolbar-btn.active { background: rgba(59,130,246,0.2); color: #60a5fa; }
      .lexical-toolbar-sep {
        width: 1px;
        height: 20px;
        margin: 0 4px;
        background: rgba(0,0,0,0.12);
      }
      .dark .lexical-toolbar-sep { background: rgba(255,255,255,0.12); }

      /* ── Editor surface ─────────────────────────────────────────────── */
      .lexical-editor-surface {
        position: relative;
      }
      .lexical-content-editable {
        padding: 12px 14px;
        min-height: inherit;
        outline: none;
        font-size: 0.9375rem;
        line-height: 1.7;
        color: #18181b;
        caret-color: #18181b;
        word-break: break-word;
        overflow-wrap: anywhere;
      }
      .dark .lexical-content-editable {
        color: #e4e4e7;
        caret-color: #e4e4e7;
      }
      .lexical-placeholder {
        position: absolute;
        top: 12px;
        left: 14px;
        pointer-events: none;
        color: #a1a1aa;
        font-size: 0.9375rem;
        line-height: 1.7;
        display: none;
      }

      /* ── Content styles ─────────────────────────────────────────────── */
      .lexical-content-editable h1, .lexical-h1 { font-size: 1.75em; font-weight: 700; margin: 0.5em 0 0.25em; line-height: 1.2; }
      .lexical-content-editable h2, .lexical-h2 { font-size: 1.375em; font-weight: 600; margin: 0.5em 0 0.25em; line-height: 1.3; }
      .lexical-content-editable h3, .lexical-h3 { font-size: 1.15em; font-weight: 600; margin: 0.5em 0 0.25em; line-height: 1.4; }
      .lexical-content-editable p { margin: 0.25em 0; }
      .lexical-content-editable ul, .lexical-ul { list-style: disc; padding-left: 1.5em; margin: 0.25em 0; }
      .lexical-content-editable ol, .lexical-ol { list-style: decimal; padding-left: 1.5em; margin: 0.25em 0; }
      .lexical-content-editable li, .lexical-li { margin: 0.1em 0; }
      .lexical-content-editable blockquote, .lexical-blockquote {
        border-left: 3px solid #d4d4d8;
        margin: 0.5em 0;
        padding: 0.25em 0 0.25em 0.875em;
        color: #71717a;
        font-style: italic;
      }
      .dark .lexical-content-editable blockquote,
      .dark .lexical-blockquote { border-left-color: #3f3f46; color: #a1a1aa; }
      .lexical-content-editable a, .lexical-link { color: #2563eb; text-decoration: underline; }
      .dark .lexical-content-editable a, .dark .lexical-link { color: #60a5fa; }
      .lexical-bold { font-weight: bold; }
      .lexical-italic { font-style: italic; }
      .lexical-underline { text-decoration: underline; }
      .lexical-strikethrough { text-decoration: line-through; }
      .lexical-code-inline {
        font-family: ui-monospace, monospace;
        font-size: 0.875em;
        background: rgba(0,0,0,0.06);
        border-radius: 3px;
        padding: 0 3px;
      }
      .dark .lexical-code-inline { background: rgba(255,255,255,0.1); }
    </style>
  `
}

export function getLexicalImportMap(version: string = LEXICAL_VERSION): string {
  const base = `https://esm.sh`
  const ext = `?external=lexical`
  return `
    <script type="importmap" id="lexical-importmap">
    {
      "imports": {
        "lexical": "${base}/lexical@${version}",
        "@lexical/rich-text": "${base}/@lexical/rich-text@${version}${ext}",
        "@lexical/history": "${base}/@lexical/history@${version}${ext}",
        "@lexical/list": "${base}/@lexical/list@${version}${ext}",
        "@lexical/link": "${base}/@lexical/link@${version}${ext}",
        "@lexical/html": "${base}/@lexical/html@${version}${ext}",
        "@lexical/selection": "${base}/@lexical/selection@${version}${ext}"
      }
    }
    </script>
  `
}

export function getLexicalLoaderScript(): string {
  return `
    <script type="module" id="lexical-loader">
    (async function() {
      try {
        const [
          lexicalCore,
          richTextMod,
          historyMod,
          listMod,
          linkMod,
          htmlMod,
          selectionMod,
        ] = await Promise.all([
          import('lexical'),
          import('@lexical/rich-text'),
          import('@lexical/history'),
          import('@lexical/list'),
          import('@lexical/link'),
          import('@lexical/html'),
          import('@lexical/selection'),
        ]);

        window.__lexical = {
          // core
          createEditor: lexicalCore.createEditor,
          $getRoot: lexicalCore.$getRoot,
          $getSelection: lexicalCore.$getSelection,
          $isRangeSelection: lexicalCore.$isRangeSelection,
          $createParagraphNode: lexicalCore.$createParagraphNode,
          $createTextNode: lexicalCore.$createTextNode,
          FORMAT_TEXT_COMMAND: lexicalCore.FORMAT_TEXT_COMMAND,
          UNDO_COMMAND: lexicalCore.UNDO_COMMAND,
          REDO_COMMAND: lexicalCore.REDO_COMMAND,
          // rich-text
          registerRichText: richTextMod.registerRichText,
          HeadingNode: richTextMod.HeadingNode,
          QuoteNode: richTextMod.QuoteNode,
          $createHeadingNode: richTextMod.$createHeadingNode,
          $createQuoteNode: richTextMod.$createQuoteNode,
          $isHeadingNode: richTextMod.$isHeadingNode,
          // history
          createEmptyHistoryState: historyMod.createEmptyHistoryState,
          registerHistory: historyMod.registerHistory,
          // list
          ListNode: listMod.ListNode,
          ListItemNode: listMod.ListItemNode,
          INSERT_UNORDERED_LIST_COMMAND: listMod.INSERT_UNORDERED_LIST_COMMAND,
          INSERT_ORDERED_LIST_COMMAND: listMod.INSERT_ORDERED_LIST_COMMAND,
          REMOVE_LIST_COMMAND: listMod.REMOVE_LIST_COMMAND,
          registerList: listMod.registerList,
          $isListNode: listMod.$isListNode,
          // link
          LinkNode: linkMod.LinkNode,
          AutoLinkNode: linkMod.AutoLinkNode,
          TOGGLE_LINK_COMMAND: linkMod.TOGGLE_LINK_COMMAND,
          registerLinkPlugin: linkMod.registerLinkPlugin,
          // html
          $generateHtmlFromNodes: htmlMod.$generateHtmlFromNodes,
          $generateNodesFromDOM: htmlMod.$generateNodesFromDOM,
          // selection
          $setBlocksType: selectionMod.$setBlocksType,
          loaded: true,
        };

        window.dispatchEvent(new CustomEvent('lexical:ready'));
        if (typeof window.initializeLexicalEditors === 'function') {
          window.initializeLexicalEditors();
        }
      } catch (err) {
        console.error('[Lexical] Failed to load:', err);
      }
    })();
    </script>
  `
}

export function getLexicalInitScript(settings: { defaultHeight?: number; defaultToolbar?: string } = {}): string {
  const defaultHeight = settings.defaultHeight ?? 300
  const defaultToolbar = settings.defaultToolbar ?? 'standard'

  return `
    <script>
    (function() {
      // ─── Toolbar action handler ────────────────────────────────────────
      function handleToolbarAction(editor, action, L) {
        editor.focus();
        switch (action) {
          case 'bold':
          case 'italic':
          case 'underline':
          case 'strikethrough':
          case 'code':
            editor.dispatchCommand(L.FORMAT_TEXT_COMMAND, action);
            break;
          case 'h1':
          case 'h2':
          case 'h3':
            editor.update(function() {
              var sel = L.$getSelection();
              if (L.$isRangeSelection(sel)) {
                var heading = action;
                L.$setBlocksType(sel, function() {
                  var node = L.$createHeadingNode(heading);
                  return node;
                });
              }
            });
            break;
          case 'bulletList':
            editor.dispatchCommand(L.INSERT_UNORDERED_LIST_COMMAND, undefined);
            break;
          case 'orderedList':
            editor.dispatchCommand(L.INSERT_ORDERED_LIST_COMMAND, undefined);
            break;
          case 'blockquote':
            editor.update(function() {
              var sel = L.$getSelection();
              if (L.$isRangeSelection(sel)) {
                L.$setBlocksType(sel, function() { return L.$createQuoteNode(); });
              }
            });
            break;
          case 'link':
            var url = window.prompt('Enter URL (leave empty to remove link):', 'https://');
            if (url !== null) {
              editor.dispatchCommand(L.TOGGLE_LINK_COMMAND, url || null);
            }
            break;
          case 'undo':
            editor.dispatchCommand(L.UNDO_COMMAND, undefined);
            break;
          case 'redo':
            editor.dispatchCommand(L.REDO_COMMAND, undefined);
            break;
        }
      }

      // ─── Toolbar active-state updater ─────────────────────────────────
      function updateToolbarState(editorState, toolbar, L) {
        editorState.read(function() {
          var sel = L.$getSelection();
          var isRange = L.$isRangeSelection(sel);

          var activeMap = {
            bold: isRange && sel.hasFormat('bold'),
            italic: isRange && sel.hasFormat('italic'),
            underline: isRange && sel.hasFormat('underline'),
            strikethrough: isRange && sel.hasFormat('strikethrough'),
            code: isRange && sel.hasFormat('code'),
          };

          toolbar.querySelectorAll('.lexical-toolbar-btn').forEach(function(btn) {
            var action = btn.getAttribute('data-action');
            if (action in activeMap) {
              btn.classList.toggle('active', !!activeMap[action]);
            }
          });
        });
      }

      // ─── Initialize one editor instance ──────────────────────────────
      function initEditor(wrapper) {
        var L = window.__lexical;
        var fieldId = wrapper.getAttribute('data-field-id');
        var height = parseInt(wrapper.getAttribute('data-height') || '${defaultHeight}', 10);
        var placeholder = wrapper.getAttribute('data-placeholder') || 'Enter content...';

        var editorEl = document.getElementById(fieldId + '-editor');
        var hiddenInput = document.getElementById(fieldId);
        var placeholderEl = document.getElementById(fieldId + '-placeholder');
        var toolbar = document.getElementById(fieldId + '-toolbar');

        if (!editorEl || !hiddenInput) return;

        var editor = L.createEditor({
          namespace: fieldId,
          nodes: [
            L.HeadingNode, L.QuoteNode,
            L.ListNode, L.ListItemNode,
            L.LinkNode, L.AutoLinkNode,
          ],
          theme: {
            heading: { h1: 'lexical-h1', h2: 'lexical-h2', h3: 'lexical-h3' },
            list: {
              ul: 'lexical-ul',
              ol: 'lexical-ol',
              listitem: 'lexical-li',
              nested: { listitem: 'lexical-li-nested' },
            },
            quote: 'lexical-blockquote',
            link: 'lexical-link',
            text: {
              bold: 'lexical-bold',
              italic: 'lexical-italic',
              underline: 'lexical-underline',
              strikethrough: 'lexical-strikethrough',
              code: 'lexical-code-inline',
            },
          },
          onError: function(err) { console.error('[Lexical]', fieldId, err); },
        });

        // Attach to DOM
        editor.setRootElement(editorEl);

        // Register editor plugins
        L.registerRichText(editor);
        L.registerHistory(editor, L.createEmptyHistoryState(), 300);
        if (typeof L.registerList === 'function') L.registerList(editor);
        if (typeof L.registerLinkPlugin === 'function') L.registerLinkPlugin(editor);

        // Load initial HTML content
        var initialHtml = hiddenInput.value;
        if (initialHtml && initialHtml.trim()) {
          editor.update(function() {
            var parser = new DOMParser();
            var dom = parser.parseFromString(initialHtml, 'text/html');
            var nodes = L.$generateNodesFromDOM(editor, dom);
            var root = L.$getRoot();
            root.clear();
            root.append.apply(root, nodes);
          });
        }

        // Sync HTML to hidden input on every change
        editor.registerUpdateListener(function(ref) {
          ref.editorState.read(function() {
            hiddenInput.value = L.$generateHtmlFromNodes(editor, null);
          });

          // Update placeholder visibility
          ref.editorState.read(function() {
            var root = L.$getRoot();
            var first = root.getFirstChild();
            var isEmpty = root.getChildrenSize() === 1 &&
              first && first.getType() === 'paragraph' &&
              first.getChildrenSize() === 0;
            if (placeholderEl) {
              placeholderEl.style.display = isEmpty ? 'block' : 'none';
            }
          });

          // Update toolbar active states
          if (toolbar) {
            updateToolbarState(ref.editorState, toolbar, L);
          }
        });

        // Wire toolbar buttons
        if (toolbar) {
          toolbar.querySelectorAll('.lexical-toolbar-btn').forEach(function(btn) {
            btn.addEventListener('mousedown', function(e) {
              e.preventDefault(); // prevent blur
            });
            btn.addEventListener('click', function(e) {
              e.preventDefault();
              handleToolbarAction(editor, btn.getAttribute('data-action'), L);
            });
          });
        }

        // Store instance for access by other scripts
        editorEl._lexicalEditor = editor;
        wrapper.setAttribute('data-lexical-initialized', 'true');
      }

      // ─── Initialize all uninitialised editors ─────────────────────────
      window.initializeLexicalEditors = function(scope) {
        if (!window.__lexical || !window.__lexical.loaded) return;
        var root = scope || document;
        root.querySelectorAll('.lexical-editor-wrapper:not([data-lexical-initialized])').forEach(initEditor);
      };

      // Run on DOM ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() { window.initializeLexicalEditors(); });
      } else {
        window.initializeLexicalEditors();
      }

      // Re-run after HTMX swaps
      document.addEventListener('htmx:afterSwap', function() {
        setTimeout(function() { window.initializeLexicalEditors(); }, 50);
      });

      // Re-run if Lexical loads after this script
      window.addEventListener('lexical:ready', function() {
        window.initializeLexicalEditors();
      });
    })();
    </script>
  `
}

export const lexicalEditorPlugin = definePlugin({
  id: 'lexical-editor',
  version: '1.0.0',
  name: 'Lexical Editor',
  description: 'Lexical rich text editor integration for SonicJS — default editor for richtext fields',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  activate: async () => console.info('✅ Lexical Editor plugin activated'),
  deactivate: async () => console.info('❌ Lexical Editor plugin deactivated'),
})

export function createLexicalEditorPlugin() {
  return lexicalEditorPlugin
}
