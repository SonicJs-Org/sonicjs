import { html, raw } from 'hono/html'
import type { HtmlEscapedString } from 'hono/utils/html'

export interface QRPreviewData {
  /** Raw SVG string from QRService.generate() */
  svg: string
  /** Short code for URL display */
  shortCode?: string | undefined
  /** Base URL for full short URL */
  baseUrl?: string | undefined
  /** QR code ID (for download endpoints) */
  qrId?: string | undefined
}

/**
 * Render the QR code preview partial for HTMX updates
 * This is returned by the /admin/qr-codes/preview endpoint
 */
export function renderQRPreview(data: QRPreviewData): HtmlEscapedString | Promise<HtmlEscapedString> {
  const { svg, shortCode, baseUrl = '', qrId } = data
  const shortUrl = shortCode ? `${baseUrl}/qr/${shortCode}` : 'URL will be generated on save'

  return html`
    <!-- QR Code Display -->
    <div class="mb-4 bg-white rounded-lg shadow-inner flex items-center justify-center">
      <div class="qr-svg-container flex items-center justify-center w-full max-w-[280px] aspect-square [&>svg]:w-full [&>svg]:h-full [&>svg]:max-w-full [&>svg]:max-h-full">
        ${raw(svg || '<p class="text-zinc-400 text-sm">No preview</p>')}
      </div>
    </div>

    <!-- Short URL -->
    <div class="text-center mb-4 w-full">
      <p class="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Short URL</p>
      <code class="text-sm font-mono text-zinc-900 dark:text-zinc-100 bg-zinc-100 dark:bg-zinc-800 px-3 py-1.5 rounded-lg inline-block max-w-full truncate">
        ${shortUrl}
      </code>
    </div>

    <!-- Download Buttons -->
    <div class="flex gap-2 justify-center">
      <button type="button"
              onclick="downloadQRSvg()"
              class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-300 bg-white dark:bg-zinc-800 rounded-lg ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
        </svg>
        SVG
      </button>
      <button type="button"
              onclick="downloadQRPng()"
              class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-300 bg-white dark:bg-zinc-800 rounded-lg ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
        </svg>
        PNG
      </button>
    </div>

    ${qrId ? html`
    <!-- DPI selector for PNG (shown only when qrId exists) -->
    <div class="mt-3 flex items-center justify-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
      <label for="png-dpi">PNG DPI:</label>
      <select id="png-dpi" class="text-xs rounded border-zinc-300 dark:border-zinc-600 dark:bg-zinc-800 px-2 py-1">
        <option value="72">72 (web)</option>
        <option value="150">150 (screen)</option>
        <option value="300" selected>300 (print)</option>
      </select>
    </div>
    ` : ''}
  `
}

/**
 * Render a loading state for the preview
 */
export function renderQRPreviewLoading(): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <div class="flex flex-col items-center justify-center py-12">
      <svg class="animate-spin h-8 w-8 text-zinc-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
      <p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Generating preview...</p>
    </div>
  `
}

/**
 * Render an error state for the preview
 */
export function renderQRPreviewError(message: string): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <div class="flex flex-col items-center justify-center py-8 text-center">
      <svg class="h-12 w-12 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
      </svg>
      <p class="mt-2 text-sm text-red-600 dark:text-red-400">${message}</p>
    </div>
  `
}
