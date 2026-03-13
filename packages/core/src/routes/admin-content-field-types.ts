export function resolveSchemaFieldType(fieldConfig: Record<string, any>): string {
  if (fieldConfig.type === 'slug' || fieldConfig.format === 'slug') {
    return 'slug'
  }

  if (fieldConfig.type && fieldConfig.type !== 'string') {
    return fieldConfig.type
  }

  if (fieldConfig.format === 'richtext') {
    return 'richtext'
  }

  if (fieldConfig.format === 'media') {
    return 'media'
  }

  if (fieldConfig.format === 'date-time') {
    return 'date'
  }

  if (Array.isArray(fieldConfig.enum)) {
    return 'select'
  }

  return fieldConfig.type || 'string'
}

export function buildSchemaFieldOptions(fieldConfig: Record<string, any>): Record<string, any> {
  const fieldOptions = { ...fieldConfig }
  const resolvedFieldType = resolveSchemaFieldType(fieldConfig)

  if (resolvedFieldType === 'select' && Array.isArray(fieldConfig.enum)) {
    fieldOptions.options = fieldConfig.enum.map((value: string, index: number) => ({
      value,
      label: fieldConfig.enumLabels?.[index] || value,
    }))
  }

  return fieldOptions
}
