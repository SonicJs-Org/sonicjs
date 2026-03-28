export function isMarkdownEditorType(fieldType: string): boolean {
  return fieldType === 'markdown' || fieldType === 'mdxeditor' || fieldType === 'easymde'
}

export function normalizeFieldType(fieldType: string): string {
  if (isMarkdownEditorType(fieldType)) {
    return 'markdown'
  }

  if (fieldType === 'tinymce') {
    return 'richtext'
  }

  return fieldType
}
