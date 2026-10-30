import { type SdkFieldConfig, type SdkFieldType } from './types'

export function mapFieldType(field: SdkFieldConfig): string {
  const type = field.type as SdkFieldType

  switch (type) {
    case 'string':
    case 'email':
    case 'url':
    case 'slug':
    case 'color':
    case 'richtext':
    case 'markdown':
    case 'lexical':
    case 'textarea':
      return 'string'

    case 'number':
      return 'number'

    case 'boolean':
    case 'checkbox':
      return 'boolean'

    case 'date':
    case 'datetime':
      return 'string | number'

    case 'json':
      return 'Record<string, unknown>'

    case 'object': {
      if (field.properties && Object.keys(field.properties).length > 0) {
        const inner = Object.entries(field.properties)
          .map(([k, v]) => `${k}: ${mapFieldType(v)}`)
          .join('; ')
        return `{ ${inner} }`
      }
      return 'Record<string, unknown>'
    }

    case 'array': {
      if (field.items) return `${mapFieldType(field.items)}[]`
      return 'unknown[]'
    }

    case 'reference':
    case 'media':
    case 'file':
    case 'user':
      return 'string'

    case 'select':
    case 'radio': {
      const enumVals = field.enum
      if (enumVals && enumVals.length > 0) {
        return enumVals.map((v) => `'${String(v).replace(/'/g, "\\'")}'`).join(' | ')
      }
      return 'string'
    }

    case 'multiselect': {
      const enumVals = field.enum
      if (enumVals && enumVals.length > 0) {
        const union = enumVals.map((v) => `'${String(v).replace(/'/g, "\\'")}'`).join(' | ')
        return `(${union})[]`
      }
      return 'string[]'
    }

    default:
      return 'unknown'
  }
}
