/**
 * User Profile Custom Fields Renderer
 *
 * Generates the HTML section for custom profile fields by adapting
 * ProfileFieldDefinition into FieldDefinition and calling renderDynamicField.
 */

import { renderDynamicField, type FieldDefinition } from '../../../templates/components/dynamic-field.template'
import type { UserProfileConfig, ProfileFieldDefinition } from './user-profile-registry'

export function toFieldDefinition(field: ProfileFieldDefinition, index: number): FieldDefinition {
  return {
    id: `custom_${field.name}`,
    field_name: `custom_${field.name}`,
    field_type: field.type,
    field_label: field.label,
    field_options: {
      placeholder: field.placeholder || '',
      helpText: field.helpText || '',
      enum: field.options || [],
      enumLabels: field.options || [],
    },
    field_order: index,
    is_required: field.required || false,
    is_searchable: false,
  }
}

export function renderCustomProfileSection(
  config: UserProfileConfig | null,
  customData: Record<string, any>
): string {
  if (!config || config.fields.length === 0) return ''

  const visibleFields = config.fields.filter(f => !f.hidden)
  if (visibleFields.length === 0) return ''

  const fieldsHtml = visibleFields
    .map((field, index) => {
      const fieldDef = toFieldDefinition(field, index)
      const value = customData[field.name] ?? field.default ?? ''
      return renderDynamicField(fieldDef, { value })
    })
    .join('\n')

  return `
              <!-- Custom Profile Fields -->
              <div class="pt-6 border-t border-zinc-950/5 dark:border-white/5">
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Custom Profile Fields</h3>
                <div class="space-y-4">
                  ${fieldsHtml}
                </div>
              </div>`
}
