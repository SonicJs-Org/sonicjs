/**
 * Schema-driven plugin settings.
 *
 * Plugins declare `configSchema: { key: ConfigSchemaField }` on definePlugin.
 * The host renders the admin settings UI from the schema, parses FormData back
 * into typed values, and exposes the resulting record via `ctx.settings.load()`.
 *
 * Field kinds: 'string' | 'number' | 'boolean' | 'select'. New kinds get added
 * here once and every consumer picks them up.
 *
 * Phase 1 — settings UI only. The renderer emits plain HTML strings designed to
 * compose into the existing admin layout (no client-side JS). FormData parsing
 * coalesces unchecked-checkbox omission into `false` (the only browser quirk
 * the renderer must account for).
 */

import { escapeHtml } from '../../utils/sanitize'

// ── Field model ──────────────────────────────────────────────────────────────

interface BaseField {
  label: string
  description?: string
  required?: boolean
}

export interface StringField extends BaseField {
  type: 'string'
  default?: string
  format?: 'email' | 'url' | 'password'
  /** Render as `<input type="password">`. Implied when `format === 'password'`. */
  sensitive?: boolean
  placeholder?: string
  minLength?: number
  maxLength?: number
}

export interface NumberField extends BaseField {
  type: 'number'
  default?: number
  min?: number
  max?: number
  step?: number
}

export interface BooleanField extends BaseField {
  type: 'boolean'
  default?: boolean
}

export interface SelectField extends BaseField {
  type: 'select'
  default?: string
  /** Either `['us','eu']` shorthand or `[{ value, label }]` for distinct display strings. */
  options: readonly string[] | readonly { value: string; label: string }[]
}

export type ConfigSchemaField = StringField | NumberField | BooleanField | SelectField

export type ConfigSchema = Record<string, ConfigSchemaField>

/** Parsed shape — typed record inferred from the schema. */
export type SettingsFor<S extends ConfigSchema> = {
  [K in keyof S]: S[K] extends StringField
    ? string
    : S[K] extends NumberField
    ? number
    : S[K] extends BooleanField
    ? boolean
    : S[K] extends SelectField
    ? string
    : never
}

// ── Parse ────────────────────────────────────────────────────────────────────

export interface ParsedField {
  key: string
  field: ConfigSchemaField
}

/** Stable, ordered field list (preserves declaration order). */
export function parseConfigSchema(schema: ConfigSchema): ParsedField[] {
  return Object.entries(schema).map(([key, field]) => ({ key, field }))
}

// ── Render ───────────────────────────────────────────────────────────────────

/**
 * Render all fields as HTML controls. Output is a sequence of `<div class="field">…</div>`
 * blocks designed to drop into the admin form template (no surrounding `<form>` or
 * submit button — those belong to the page that calls this).
 */
export function renderSchemaFields(
  schema: ConfigSchema,
  currentValues: Record<string, unknown> = {}
): string {
  return parseConfigSchema(schema)
    .map(({ key, field }) => {
      const value = key in currentValues ? currentValues[key] : (field as { default?: unknown }).default
      return renderField(key, field, value)
    })
    .join('\n')
}

function renderField(key: string, field: ConfigSchemaField, value: unknown): string {
  const id = `field-${key}`
  const requiredAttr = field.required ? ' required' : ''
  const labelHtml = `${escapeHtml(field.label)}${field.required ? ' *' : ''}`
  const helpHtml = field.description ? `<p class="help text-sm text-gray-400 mt-1">${escapeHtml(field.description)}</p>` : ''

  switch (field.type) {
    case 'string': {
      const isPassword = field.sensitive === true || field.format === 'password'
      const inputType = isPassword ? 'password' : field.format === 'email' ? 'email' : field.format === 'url' ? 'url' : 'text'
      const placeholder = field.placeholder ? ` placeholder="${escapeHtml(field.placeholder)}"` : ''
      const min = field.minLength != null ? ` minlength="${field.minLength}"` : ''
      const max = field.maxLength != null ? ` maxlength="${field.maxLength}"` : ''
      return `
<div class="field mb-4">
  <label for="${id}" class="block text-sm font-medium mb-1">${labelHtml}</label>
  <input id="${id}" name="${escapeHtml(key)}" type="${inputType}"
    class="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
    value="${escapeHtml(String(value ?? ''))}"${placeholder}${min}${max}${requiredAttr} />
  ${helpHtml}
</div>`.trim()
    }
    case 'number': {
      const min = field.min != null ? ` min="${field.min}"` : ''
      const max = field.max != null ? ` max="${field.max}"` : ''
      const step = field.step != null ? ` step="${field.step}"` : ''
      return `
<div class="field mb-4">
  <label for="${id}" class="block text-sm font-medium mb-1">${labelHtml}</label>
  <input id="${id}" name="${escapeHtml(key)}" type="number"
    class="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
    value="${value == null ? '' : escapeHtml(String(value))}"${min}${max}${step}${requiredAttr} />
  ${helpHtml}
</div>`.trim()
    }
    case 'boolean': {
      const checked = value === true ? ' checked' : ''
      return `
<div class="field mb-4">
  <label class="flex items-center gap-2 text-sm font-medium">
    <input name="${escapeHtml(key)}" type="checkbox" class="rounded"${checked} />
    ${labelHtml}
  </label>
  ${helpHtml}
</div>`.trim()
    }
    case 'select': {
      const optionsHtml = field.options
        .map((o) => {
          const opt = typeof o === 'string' ? { value: o, label: o } : o
          const selected = opt.value === value ? ' selected' : ''
          return `<option value="${escapeHtml(opt.value)}"${selected}>${escapeHtml(opt.label)}</option>`
        })
        .join('')
      return `
<div class="field mb-4">
  <label for="${id}" class="block text-sm font-medium mb-1">${labelHtml}</label>
  <select id="${id}" name="${escapeHtml(key)}"
    class="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"${requiredAttr}>
    ${optionsHtml}
  </select>
  ${helpHtml}
</div>`.trim()
    }
  }
}

// ── FormData → settings ──────────────────────────────────────────────────────

/**
 * Coerce FormData entries into typed settings per the schema. Notably:
 * - Unchecked checkboxes are omitted by the browser; we coalesce to `false`.
 * - Numbers parse via `Number()` and fall back to the field's default if invalid.
 * - Strings preserve empty string (NOT default) so an admin can intentionally clear.
 */
export function parseFormDataToSettings(schema: ConfigSchema, form: FormData): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const { key, field } of parseConfigSchema(schema)) {
    switch (field.type) {
      case 'string': {
        const raw = form.get(key)
        result[key] = raw == null ? field.default ?? '' : String(raw)
        break
      }
      case 'number': {
        const raw = form.get(key)
        if (raw == null || raw === '') {
          result[key] = field.default
        } else {
          const n = Number(raw)
          result[key] = Number.isFinite(n) ? n : field.default
        }
        break
      }
      case 'boolean': {
        // Unchecked checkbox → not present in FormData → false.
        result[key] = form.get(key) != null
        break
      }
      case 'select': {
        const raw = form.get(key)
        result[key] = raw == null ? field.default ?? '' : String(raw)
        break
      }
    }
  }
  return result
}

// ── Defaults ─────────────────────────────────────────────────────────────────

/** Fill missing keys with field defaults. Existing keys (incl. `false`/`0`/'') win. */
export function applySchemaDefaults<S extends ConfigSchema>(
  schema: S,
  stored: Record<string, unknown>
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...stored }
  for (const { key, field } of parseConfigSchema(schema)) {
    if (result[key] === undefined) {
      const def = (field as { default?: unknown }).default
      if (def !== undefined) result[key] = def
    }
  }
  return result
}
