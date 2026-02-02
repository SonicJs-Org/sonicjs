import { html } from 'hono/html'
import type { HtmlEscapedString } from 'hono/utils/html'
import { renderAdminLayoutCatalyst } from '@sonicjs-cms/core/templates'
import type { QRCode, CornerShape, DotShape, QRGeneratorSettings } from '../types'
import { renderQRPreview } from './qr-preview.template'

export interface QRFormPageData {
  /** Whether this is an edit form (true) or create form (false) */
  isEdit: boolean
  /** The QR code being edited (only populated for edit forms) */
  qrCode?: QRCode
  /** Validation error message to display */
  error?: string
  /** Warning message to display */
  warning?: string
  /** Preserved filter params from list page for back navigation */
  referrerParams?: string
  /** Current user */
  user: any
  /** Base URL for preview short URL display */
  baseUrl?: string
  /** Pre-generated short code for new QR codes (used in preview and on save) */
  provisionalShortCode?: string
  /** Initial SVG for preview (generated with defaults or current settings) */
  initialSvg?: string
  /** Plugin settings for default values (new QR codes only) */
  defaultSettings?: QRGeneratorSettings
}

// Default color swatches for color pickers
const defaultSwatches = ['#000000', '#ffffff', '#1e40af', '#dc2626', '#16a34a', '#ca8a04', '#9333ea', '#0d9488']

// Corner shape options with SVG icons
const cornerShapeOptions: Array<{ value: CornerShape; label: string; icon: string }> = [
  {
    value: 'square',
    label: 'Square',
    icon: `<svg class="w-8 h-8" viewBox="0 0 32 32" fill="currentColor"><rect x="4" y="4" width="24" height="24"/></svg>`
  },
  {
    value: 'rounded',
    label: 'Rounded',
    icon: `<svg class="w-8 h-8" viewBox="0 0 32 32" fill="currentColor"><rect x="4" y="4" width="24" height="24" rx="4"/></svg>`
  },
  {
    value: 'dots',
    label: 'Dots',
    icon: `<svg class="w-8 h-8" viewBox="0 0 32 32" fill="currentColor"><circle cx="16" cy="16" r="12"/></svg>`
  },
  {
    value: 'extra-rounded',
    label: 'Extra Rounded',
    icon: `<svg class="w-8 h-8" viewBox="0 0 32 32" fill="currentColor"><rect x="4" y="4" width="24" height="24" rx="8"/></svg>`
  }
]

// Dot shape options with SVG icons
const dotShapeOptions: Array<{ value: DotShape; label: string; icon: string }> = [
  {
    value: 'square',
    label: 'Square',
    icon: `<svg class="w-6 h-6" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16"/></svg>`
  },
  {
    value: 'rounded',
    label: 'Rounded',
    icon: `<svg class="w-6 h-6" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16" rx="3"/></svg>`
  },
  {
    value: 'dots',
    label: 'Dots',
    icon: `<svg class="w-6 h-6" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="8"/></svg>`
  },
  {
    value: 'diamond',
    label: 'Diamond',
    icon: `<svg class="w-6 h-6" viewBox="0 0 24 24" fill="currentColor"><polygon points="12,2 22,12 12,22 2,12"/></svg>`
  }
]

/**
 * Render a collapsible section with toggle functionality
 */
function renderCollapsibleSection(props: {
  id: string
  title: string
  defaultOpen: boolean
  content: string
}): string {
  return `
    <div class="border-b border-zinc-200 dark:border-zinc-800 pb-6 mb-6">
      <button type="button" class="flex w-full items-center justify-between text-left"
              onclick="toggleSection('${props.id}')">
        <h2 class="text-base font-semibold text-zinc-950 dark:text-white">${props.title}</h2>
        <svg id="${props.id}-icon" class="h-5 w-5 text-zinc-500 transform transition-transform ${props.defaultOpen ? 'rotate-180' : ''}"
             fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
        </svg>
      </button>
      <div id="${props.id}-content" class="${props.defaultOpen ? '' : 'hidden'} mt-4 space-y-4">
        ${props.content}
      </div>
    </div>
  `
}

/**
 * Render a color picker with swatches, native picker, and hex input
 */
function renderColorPicker(props: {
  name: string
  label: string
  value: string
  required?: boolean
  htmxAttrs?: string
}): string {
  const { name, label, value, required = false, htmxAttrs = '' } = props
  const swatchesHtml = defaultSwatches.map(color => `
    <button type="button"
            class="w-6 h-6 rounded-md border border-zinc-300 dark:border-zinc-600 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-1"
            style="background-color: ${color}"
            onclick="setColor('${name}', '${color}')"
            title="${color}">
    </button>
  `).join('')

  return `
    <div class="space-y-2">
      <label class="block text-sm font-medium text-zinc-900 dark:text-zinc-100">
        ${label}
        ${required ? '<span class="text-red-500">*</span>' : ''}
      </label>
      <div class="flex items-center gap-3">
        <!-- Color preview box -->
        <div id="${name}-preview"
             class="w-10 h-10 rounded-lg border border-zinc-300 dark:border-zinc-600 shadow-sm"
             style="background-color: ${value}">
        </div>
        <!-- Native color picker -->
        <input type="color"
               id="${name}-picker"
               value="${value}"
               onchange="syncColor('${name}', this.value)"
               class="w-10 h-10 rounded-lg border-0 p-0 cursor-pointer"
               ${htmxAttrs}
        />
        <!-- Hex input -->
        <input type="text"
               id="${name}-hex"
               name="${name}"
               value="${value}"
               pattern="^#[0-9A-Fa-f]{6}$"
               placeholder="#000000"
               onchange="syncColorFromHex('${name}', this.value)"
               class="w-24 rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500 font-mono"
               ${required ? 'required' : ''}
               ${htmxAttrs}
        />
      </div>
      <!-- Color swatches -->
      <div class="flex gap-1.5 mt-2">
        ${swatchesHtml}
      </div>
    </div>
  `
}

/**
 * Render a shape selector with visual icons
 */
function renderShapeSelector(props: {
  name: string
  label: string
  value: string
  options: Array<{ value: string; label: string; icon: string }>
  htmxAttrs?: string
}): string {
  const { name, label, value, options, htmxAttrs = '' } = props

  const optionsHtml = options.map(opt => `
    <label class="relative cursor-pointer">
      <input type="radio"
             name="${name}"
             value="${opt.value}"
             ${opt.value === value ? 'checked' : ''}
             class="peer sr-only"
             ${htmxAttrs}
      />
      <div class="flex flex-col items-center p-3 rounded-lg border-2 border-zinc-200 dark:border-zinc-700
                  peer-checked:border-indigo-500 peer-checked:bg-indigo-50 dark:peer-checked:bg-indigo-900/20
                  hover:border-zinc-300 dark:hover:border-zinc-600 transition-colors">
        <div class="text-zinc-600 dark:text-zinc-400 peer-checked:text-indigo-600 dark:peer-checked:text-indigo-400">
          ${opt.icon}
        </div>
        <span class="mt-1 text-xs text-zinc-600 dark:text-zinc-400">${opt.label}</span>
      </div>
    </label>
  `).join('')

  return `
    <div class="space-y-2">
      <label class="block text-sm font-medium text-zinc-900 dark:text-zinc-100">${label}</label>
      <div class="grid grid-cols-4 gap-2">
        ${optionsHtml}
      </div>
    </div>
  `
}

/**
 * Render the QR code create/edit form page
 */
export function renderQRFormPage(data: QRFormPageData): HtmlEscapedString | Promise<HtmlEscapedString> {
  const { isEdit, qrCode, error, warning, referrerParams, baseUrl = '', initialSvg = '', provisionalShortCode = '', defaultSettings } = data
  const pageTitle = isEdit ? 'Edit QR Code' : 'New QR Code'
  const submitText = isEdit ? 'Update QR Code' : 'Create QR Code'
  const formAction = isEdit ? `/admin/qr-codes/${qrCode?.id}` : '/admin/qr-codes'
  // Use provisional short code for new QR codes, or existing short code for edits
  const shortCode = qrCode?.shortCode || provisionalShortCode

  const backUrl = referrerParams
    ? `/admin/qr-codes?${referrerParams}`
    : '/admin/qr-codes'

  // Default values - use plugin settings for new QR codes, or existing values for edits
  const defaults = defaultSettings || {
    defaultForegroundColor: '#000000',
    defaultBackgroundColor: '#ffffff',
    defaultErrorCorrection: 'M' as const,
    defaultSize: 300,
    defaultCornerShape: 'square' as const,
    defaultDotShape: 'square' as const,
    defaultLogoUrl: ''
  }

  const values = {
    name: qrCode?.name || '',
    destinationUrl: qrCode?.destinationUrl || '',
    shortCode: shortCode,  // Use provisional short code for new, existing for edit
    foregroundColor: qrCode?.foregroundColor || defaults.defaultForegroundColor,
    backgroundColor: qrCode?.backgroundColor || defaults.defaultBackgroundColor,
    eyeColor: qrCode?.eyeColor || '',
    cornerShape: qrCode?.cornerShape || defaults.defaultCornerShape || 'square',
    dotShape: qrCode?.dotShape || defaults.defaultDotShape || 'square',
    errorCorrection: qrCode?.errorCorrection || defaults.defaultErrorCorrection,
    size: qrCode?.size || defaults.defaultSize,
    logoUrl: qrCode?.logoUrl || defaults.defaultLogoUrl || ''
  }

  // HTMX attributes for preview updates
  const htmxPreviewAttrs = `hx-post="/admin/qr-codes/preview" hx-trigger="input delay:300ms, change" hx-target="#qr-preview" hx-swap="innerHTML" hx-include="#qr-form"`

  // Build section content
  const basicInfoContent = `
    <!-- Name -->
    <div>
      <label for="name" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
        Name
        <span class="text-zinc-500 dark:text-zinc-400 font-normal">(optional)</span>
      </label>
      <input type="text"
             id="name"
             name="name"
             value="${values.name}"
             placeholder="My QR Code"
             class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
      />
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        A friendly name to identify this QR code
      </p>
    </div>

    <!-- Destination URL -->
    <div>
      <label for="destination_url" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
        Destination URL
        <span class="text-red-500">*</span>
      </label>
      <input type="url"
             id="destination_url"
             name="destination_url"
             value="${values.destinationUrl}"
             placeholder="https://example.com/page"
             required
             ${htmxPreviewAttrs}
             class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
      />
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        The URL users will be redirected to when scanning this QR code
      </p>
    </div>

    <!-- Short URL Display -->
    <div>
      <label class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
        Short URL
      </label>
      <div class="flex items-center gap-2">
        <code class="flex-1 rounded-lg bg-zinc-100 dark:bg-zinc-800 px-3 py-2 text-sm font-mono text-zinc-700 dark:text-zinc-300">
          ${values.shortCode ? `${baseUrl}/qr/${values.shortCode}` : 'Will be generated on save'}
        </code>
        ${values.shortCode ? `
          <button type="button"
                  onclick="copyToClipboard('${baseUrl}/qr/${values.shortCode}')"
                  class="p-2 rounded-lg text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                  title="Copy to clipboard">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
            </svg>
          </button>
        ` : ''}
      </div>
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        This short URL redirects to the destination and tracks scan analytics
      </p>
    </div>
  `

  const colorsContent = `
    ${renderColorPicker({
      name: 'foreground_color',
      label: 'Foreground Color',
      value: values.foregroundColor,
      required: true,
      htmxAttrs: htmxPreviewAttrs
    })}

    ${renderColorPicker({
      name: 'background_color',
      label: 'Background Color',
      value: values.backgroundColor,
      required: true,
      htmxAttrs: htmxPreviewAttrs
    })}

    <!-- Eye Color (optional) -->
    <div class="space-y-2">
      <div class="flex items-center gap-2">
        <input type="checkbox"
               id="use_eye_color"
               ${values.eyeColor ? 'checked' : ''}
               onchange="toggleEyeColor(this.checked)"
               class="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
        />
        <label for="use_eye_color" class="text-sm font-medium text-zinc-900 dark:text-zinc-100">
          Use custom eye color
        </label>
      </div>
      <div id="eye-color-picker" class="${values.eyeColor ? '' : 'hidden'}">
        ${renderColorPicker({
          name: 'eye_color',
          label: 'Eye Color (Position Markers)',
          value: values.eyeColor || values.foregroundColor,
          htmxAttrs: htmxPreviewAttrs
        })}
      </div>
    </div>
  `

  const shapesContent = `
    ${renderShapeSelector({
      name: 'corner_shape',
      label: 'Corner Shape (Position Markers)',
      value: values.cornerShape,
      options: cornerShapeOptions,
      htmxAttrs: htmxPreviewAttrs
    })}

    ${renderShapeSelector({
      name: 'dot_shape',
      label: 'Dot Shape (Data Modules)',
      value: values.dotShape,
      options: dotShapeOptions,
      htmxAttrs: htmxPreviewAttrs
    })}
  `

  const advancedContent = `
    <!-- Error Correction Level -->
    <div>
      <label for="error_correction" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
        Error Correction Level
      </label>
      <select id="error_correction"
              name="error_correction"
              ${htmxPreviewAttrs}
              class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
        <option value="L" ${values.errorCorrection === 'L' ? 'selected' : ''}>L - Low (7% recovery)</option>
        <option value="M" ${values.errorCorrection === 'M' ? 'selected' : ''}>M - Medium (15% recovery)</option>
        <option value="Q" ${values.errorCorrection === 'Q' ? 'selected' : ''}>Q - Quartile (25% recovery)</option>
        <option value="H" ${values.errorCorrection === 'H' ? 'selected' : ''}>H - High (30% recovery)</option>
      </select>
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        Higher levels allow more damage but create denser codes. Auto-set to H when logo is added.
      </p>
    </div>

    <!-- Size -->
    <div>
      <label for="size" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
        Size (pixels)
      </label>
      <input type="number"
             id="size"
             name="size"
             value="${values.size}"
             min="100"
             max="1000"
             step="50"
             ${htmxPreviewAttrs}
             class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
      />
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        Output size in pixels (100-1000). Larger sizes provide more detail for printing.
      </p>
    </div>
  `

  const logoContent = `
    <!-- Logo Upload -->
    <div class="space-y-4">
      ${values.logoUrl ? `
        <!-- Current Logo Preview -->
        <div class="flex items-center gap-4">
          <img src="${values.logoUrl}" alt="Current logo" class="w-16 h-16 object-contain rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white" />
          <div class="flex-1">
            <p class="text-sm text-zinc-700 dark:text-zinc-300">Current logo</p>
            <button type="button"
                    onclick="removeLogo()"
                    class="mt-1 text-sm text-red-600 hover:text-red-500">
              Remove logo
            </button>
          </div>
        </div>
      ` : ''}

      <!-- Logo Dropzone -->
      <div id="logo-dropzone"
           class="border-2 border-dashed border-zinc-300 dark:border-zinc-700 rounded-lg p-6 text-center hover:border-indigo-500 transition-colors cursor-pointer"
           ondragover="handleDragOver(event)"
           ondrop="handleLogoDrop(event)"
           onclick="document.getElementById('logo-input').click()">
        <svg class="mx-auto h-12 w-12 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
        </svg>
        <p class="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          <span class="font-medium text-indigo-600 dark:text-indigo-400">Upload a logo</span> or drag and drop
        </p>
        <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
          PNG or SVG, max 25% coverage
        </p>
        <input type="file"
               id="logo-input"
               accept="image/png,image/svg+xml"
               onchange="handleLogoSelect(this.files)"
               class="hidden"
        />
      </div>
      <input type="hidden" id="logo_url" name="logo_url" value="${values.logoUrl}" />

      <p class="text-xs text-zinc-500 dark:text-zinc-400">
        Adding a logo automatically increases error correction to High (H) for better scan reliability.
      </p>
    </div>
  `

  // Build the full form content - scripts MUST come first before any onclick handlers
  const content = html`
    ${getFormScripts()}
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">
            ${pageTitle}
          </h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            ${isEdit ? 'Modify an existing QR code' : 'Create a new trackable QR code'}
          </p>
        </div>
      </div>

      <!-- Error/Warning Messages -->
      ${error ? renderAlert('error', error) : ''}
      ${warning ? renderAlert('warning', warning) : ''}

      <!-- Two-column layout -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Form Column -->
        <div>
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <form id="qr-form"
                  hx-${isEdit ? 'put' : 'post'}="${formAction}"
                  hx-target="#form-messages"
                  hx-swap="innerHTML"
                  class="p-6">
              <div id="form-messages"></div>

              ${isEdit && qrCode ? html`<input type="hidden" id="qr-id" name="id" value="${qrCode.id}" />` : ''}
              <input type="hidden" id="short-code" name="short_code" value="${values.shortCode}" />

              ${html([renderCollapsibleSection({
                id: 'section-basic',
                title: 'Basic Info',
                defaultOpen: true,
                content: basicInfoContent
              })] as unknown as TemplateStringsArray)}

              ${html([renderCollapsibleSection({
                id: 'section-colors',
                title: 'Colors',
                defaultOpen: true,
                content: colorsContent
              })] as unknown as TemplateStringsArray)}

              ${html([renderCollapsibleSection({
                id: 'section-shapes',
                title: 'Shapes',
                defaultOpen: true,
                content: shapesContent
              })] as unknown as TemplateStringsArray)}

              ${html([renderCollapsibleSection({
                id: 'section-advanced',
                title: 'Advanced',
                defaultOpen: false,
                content: advancedContent
              })] as unknown as TemplateStringsArray)}

              ${html([renderCollapsibleSection({
                id: 'section-logo',
                title: 'Logo',
                defaultOpen: !isEdit || !!values.logoUrl,
                content: logoContent
              })] as unknown as TemplateStringsArray)}

              <!-- Form Actions -->
              <div class="flex items-center justify-end gap-x-4 pt-4 border-t border-zinc-200 dark:border-zinc-800">
                <a href="${backUrl}"
                   class="px-4 py-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100 bg-white dark:bg-zinc-800 rounded-lg ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700">
                  Cancel
                </a>
                <button type="submit"
                        class="px-4 py-2 text-sm font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 shadow-sm">
                  ${submitText}
                </button>
              </div>
            </form>
          </div>
        </div>

        <!-- Preview Column (sticky) -->
        <div class="lg:sticky lg:top-6 lg:self-start">
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-sm font-medium text-zinc-500 dark:text-zinc-400 mb-4">Preview</h3>
            <div id="qr-preview" class="flex flex-col items-center">
              ${renderQRPreview({
                svg: initialSvg,
                shortCode: values.shortCode,
                baseUrl,
                qrId: qrCode?.id
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  `

  return renderLayout(pageTitle, content)
}

/**
 * Render alert message box
 */
function renderAlert(type: 'error' | 'warning', message: string): HtmlEscapedString | Promise<HtmlEscapedString> {
  const colors = {
    error: 'bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-400 border-red-200 dark:border-red-800',
    warning: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800'
  }

  return html`
    <div class="mb-6 rounded-lg border ${colors[type]} p-4">
      <p class="text-sm">${message}</p>
    </div>
  `
}

/**
 * Get form interaction scripts
 */
function getFormScripts(): HtmlEscapedString | Promise<HtmlEscapedString> {
  // Note: HTMX is already loaded by admin layout (v2.0.3)
  return html`
    <script>
      // Define all functions immediately in global scope
      window.toggleSection = function(id) {
        const content = document.getElementById(id + '-content');
        const icon = document.getElementById(id + '-icon');
        if (content && icon) {
          content.classList.toggle('hidden');
          icon.classList.toggle('rotate-180');
        }
      }

      // Set color from swatch button
      window.setColor = function(name, color) {
        const picker = document.getElementById(name + '-picker');
        const hex = document.getElementById(name + '-hex');
        const preview = document.getElementById(name + '-preview');

        if (picker) picker.value = color;
        if (hex) {
          hex.value = color;
          // Trigger HTMX update
          htmx.trigger(hex, 'change');
        }
        if (preview) preview.style.backgroundColor = color;
      }

      // Sync from native color picker to hex input
      window.syncColor = function(name, color) {
        const hex = document.getElementById(name + '-hex');
        const preview = document.getElementById(name + '-preview');

        if (hex) {
          hex.value = color;
          // Trigger HTMX update
          htmx.trigger(hex, 'change');
        }
        if (preview) preview.style.backgroundColor = color;
      }

      // Sync from hex input to native picker (with validation)
      window.syncColorFromHex = function(name, value) {
        // Validate hex color format: #RRGGBB
        if (value && value.length === 7 && value[0] === '#' && /^[0-9A-Fa-f]{6}/.test(value.slice(1))) {
          const picker = document.getElementById(name + '-picker');
          const preview = document.getElementById(name + '-preview');

          if (picker) picker.value = value;
          if (preview) preview.style.backgroundColor = value;
        }
      }

      // Toggle eye color picker visibility
      window.toggleEyeColor = function(enabled) {
        const picker = document.getElementById('eye-color-picker');
        if (picker) {
          picker.classList.toggle('hidden', !enabled);
          if (!enabled) {
            // Clear the eye color value when disabled
            const eyeColorInput = document.getElementById('eye_color-hex');
            if (eyeColorInput) {
              eyeColorInput.value = '';
              htmx.trigger(eyeColorInput, 'change');
            }
          }
        }
      }

      // Copy text to clipboard
      window.copyToClipboard = function(text) {
        navigator.clipboard.writeText(text).then(() => {
          // Show brief success feedback
          const btn = event.currentTarget;
          const originalHtml = btn.innerHTML;
          btn.innerHTML = '<svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
          setTimeout(() => { btn.innerHTML = originalHtml; }, 1500);
        });
      }

      // Handle drag over for logo dropzone
      window.handleDragOver = function(event) {
        event.preventDefault();
        event.currentTarget.classList.add('border-indigo-500', 'bg-indigo-50', 'dark:bg-indigo-900/10');
      }

      // Handle logo file drop
      window.handleLogoDrop = function(event) {
        event.preventDefault();
        event.currentTarget.classList.remove('border-indigo-500', 'bg-indigo-50', 'dark:bg-indigo-900/10');
        const files = event.dataTransfer.files;
        if (files.length > 0) {
          handleLogoSelect(files);
        }
      }

      // Handle logo file selection
      window.handleLogoSelect = function(files) {
        if (files.length === 0) return;

        const file = files[0];
        // Check for PNG or SVG file types
        if (file.type !== 'image/png' && file.type !== 'image/svg+xml') {
          alert('Please select a PNG or SVG file');
          return;
        }

        const reader = new FileReader();
        reader.onload = function(e) {
          const dataUrl = e.target.result;
          document.getElementById('logo_url').value = dataUrl;

          // Update dropzone to show preview
          const dropzone = document.getElementById('logo-dropzone');
          dropzone.innerHTML = '<img src="' + dataUrl + '" alt="Logo preview" class="h-20 w-20 object-contain mx-auto" /><p class="mt-2 text-sm text-zinc-600 dark:text-zinc-400">Click to change</p>';

          // Trigger preview update
          const form = document.getElementById('qr-form');
          htmx.trigger(form.querySelector('[name="destination_url"]'), 'change');
        };
        reader.readAsDataURL(file);
      }

      // Remove logo
      window.removeLogo = function() {
        document.getElementById('logo_url').value = '';

        // Reset dropzone
        const dropzone = document.getElementById('logo-dropzone');
        dropzone.innerHTML = '<svg class="mx-auto h-12 w-12 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg><p class="mt-2 text-sm text-zinc-600 dark:text-zinc-400"><span class="font-medium text-indigo-600 dark:text-indigo-400">Upload a logo</span> or drag and drop</p><p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">PNG or SVG, max 25% coverage</p>';

        // Trigger preview update
        const form = document.getElementById('qr-form');
        htmx.trigger(form.querySelector('[name="destination_url"]'), 'change');
      }

      // Download QR code as SVG
      window.downloadQRSvg = function() {
        const svgElement = document.querySelector('#qr-preview svg');
        if (!svgElement) return;

        const svgData = new XMLSerializer().serializeToString(svgElement);
        const blob = new Blob([svgData], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = 'qr-code.svg';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }

      // Download QR code as PNG
      window.downloadQRPng = function() {
        const qrId = document.getElementById('qr-id')?.value;
        const dpi = document.getElementById('png-dpi')?.value || '300';

        if (qrId) {
          // Saved QR code - use API endpoint
          window.location.href = '/admin/qr-codes/' + qrId + '/download/png?dpi=' + dpi;
        } else {
          // New QR code - generate from current SVG
          const svgElement = document.querySelector('#qr-preview svg');
          if (!svgElement) return;

          // Use canvas to convert SVG to PNG
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          const svgData = new XMLSerializer().serializeToString(svgElement);
          const img = new Image();

          img.onload = function() {
            const scale = parseInt(dpi) / 72;
            canvas.width = img.width * scale;
            canvas.height = img.height * scale;
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

            canvas.toBlob(function(blob) {
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'qr-code.png';
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              URL.revokeObjectURL(url);
            }, 'image/png');
          };

          img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
        }
      }

      // Handle HTMX form submission (only for actual form submit, not preview)
      document.body.addEventListener('htmx:afterRequest', function(event) {
        // Only redirect on successful form submission, not preview updates
        const path = event.detail.pathInfo?.requestPath || '';
        const isPreview = path.includes('/preview');
        if (!isPreview && event.detail.successful && event.detail.xhr.status >= 200 && event.detail.xhr.status < 300) {
          window.location.href = '/admin/qr-codes';
        }
      });

      // Handle form validation errors
      document.body.addEventListener('htmx:responseError', function(event) {
        const messagesDiv = document.getElementById('form-messages');
        if (messagesDiv && !messagesDiv.innerHTML.trim()) {
          messagesDiv.innerHTML = '<div class="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-400 p-4 mb-4"><p class="text-sm">Failed to save QR code. Please check your input and try again.</p></div>';
        }
      });

      // Show loading state during preview updates
      document.body.addEventListener('htmx:beforeRequest', function(event) {
        if (event.detail.pathInfo.path === '/admin/qr-codes/preview') {
          const preview = document.getElementById('qr-preview');
          if (preview) {
            preview.classList.add('opacity-50');
          }
        }
      });

      document.body.addEventListener('htmx:afterSwap', function(event) {
        if (event.detail.pathInfo.path === '/admin/qr-codes/preview') {
          const preview = document.getElementById('qr-preview');
          if (preview) {
            preview.classList.remove('opacity-50');
          }
        }
      });
    </script>
  `
}

/**
 * Render page layout using shared admin layout template
 */
function renderLayout(title: string, content: any): HtmlEscapedString | Promise<HtmlEscapedString> {
  return renderAdminLayoutCatalyst({
    title,
    currentPath: '/admin/qr-codes',
    content: content.toString()
  }) as HtmlEscapedString
}
