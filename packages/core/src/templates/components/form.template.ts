export interface FormField {
  name: string
  label: string
  type: 'text' | 'email' | 'textarea' | 'select' | 'checkbox' | 'rich_text' | 'number' | 'date' | 'multi_select' | 'file'
  value?: any
  placeholder?: string
  required?: boolean
  readonly?: boolean
  helpText?: string
  options?: Array<{ value: string; label: string; selected?: boolean }>
  rows?: number
  className?: string
  validation?: {
    min?: number
    max?: number
    pattern?: string
  }
}

export interface FormData {
  id?: string
  action?: string
  method?: string
  hxPost?: string
  hxPut?: string
  hxTarget?: string
  fields: FormField[]
  submitButtons: Array<{
    label: string
    type?: 'submit' | 'button'
    value?: string
    name?: string
    className?: string
    onclick?: string
  }>
  title?: string
  description?: string
  className?: string
  csrfToken?: string
}

export function renderForm(data: FormData): string {
  return `
    <form
      ${data.id ? `id="${data.id}"` : ''}
      ${data.hxPost ? `hx-post="${data.hxPost}"` : data.hxPut ? `hx-put="${data.hxPut}"` : data.action ? `action="${data.action}"` : ''}
      ${data.hxTarget ? `hx-target="${data.hxTarget}"` : ''}
      method="${data.method || 'POST'}"
      class="${data.className || 'space-y-6'}"
      ${data.fields.some(f => f.type === 'file') ? 'enctype="multipart/form-data"' : ''}
    >
      ${data.csrfToken ? `<input type="hidden" name="_csrf" value="${data.csrfToken}">` : ''}
      ${data.title ? `
        <div class="mb-6">
          <h2 class="text-lg font-medium text-gray-1">${data.title}</h2>
          ${data.description ? `<p class="mt-1 text-sm text-gray-4">${data.description}</p>` : ''}
        </div>
      ` : ''}
      
      <div id="form-messages"></div>
      
      ${data.fields.map(field => renderFormField(field)).join('')}
      
      <div class="flex justify-between items-center pt-6 border-t border-gray-7">
        <div class="flex space-x-4">
          ${data.submitButtons.map(button => `
            <button 
              type="${button.type || 'submit'}"
              ${button.name ? `name="${button.name}"` : ''}
              ${button.value ? `value="${button.value}"` : ''}
              ${button.onclick ? `onclick="${button.onclick}"` : ''}
              class="btn ${button.className || 'btn-primary'}"
            >
              ${button.label}
            </button>
          `).join('')}
        </div>
      </div>
    </form>
  `
}

export function renderFormField(field: FormField): string {
  const fieldId = `field-${field.name}`
  const required = field.required ? 'required' : ''
  const readonly = field.readonly ? 'readonly' : ''
  const placeholder = field.placeholder ? `placeholder="${field.placeholder}"` : ''

  let fieldHTML = ''

  switch (field.type) {
    case 'text':
    case 'email':
    case 'number':
    case 'date':
      fieldHTML = `
        <input
          type="${field.type === 'date' ? 'datetime-local' : field.type}"
          id="${fieldId}"
          name="${field.name}"
          value="${field.value || ''}"
          class="form-input ${field.className || ''}"
          ${placeholder}
          ${required}
          ${readonly}
          ${field.validation?.min !== undefined ? `min="${field.validation.min}"` : ''}
          ${field.validation?.max !== undefined ? `max="${field.validation.max}"` : ''}
          ${field.validation?.pattern ? `pattern="${field.validation.pattern}"` : ''}
        >
      `
      break
      
    case 'textarea':
      fieldHTML = `
        <textarea 
          id="${fieldId}"
          name="${field.name}" 
          class="form-textarea ${field.className || ''}" 
          rows="${field.rows || 4}"
          ${placeholder}
          ${required}
        >${field.value || ''}</textarea>
      `
      break
      
    case 'rich_text':
      const uniqueId = `${field.name}-${Date.now()}`
      fieldHTML = `
        <div class="markdown-field">
          <textarea id="${uniqueId}" name="${field.name}" class="form-textarea" rows="8">${field.value || ''}</textarea>
          <script>
            if (typeof EasyMDE !== 'undefined') {
              new EasyMDE({
                element: document.getElementById('${uniqueId}'),
                minHeight: '300px',
                spellChecker: false,
                status: ['autosave', 'lines', 'words', 'cursor'],
                autosave: {
                  enabled: true,
                  uniqueId: '${uniqueId}',
                  delay: 1000
                },
                renderingConfig: {
                  singleLineBreaks: false,
                  codeSyntaxHighlighting: true
                }
              });
            }
          </script>
        </div>
      `
      break
      
    case 'select':
      fieldHTML = `
        <select 
          id="${fieldId}"
          name="${field.name}" 
          class="form-input ${field.className || ''}" 
          ${required}
        >
          ${field.options ? field.options.map(option => `
            <option value="${option.value}" ${option.selected || field.value === option.value ? 'selected' : ''}>
              ${option.label}
            </option>
          `).join('') : ''}
        </select>
      `
      break
      
    case 'multi_select':
      fieldHTML = `
        <select 
          id="${fieldId}"
          name="${field.name}" 
          class="form-input ${field.className || ''}" 
          multiple 
          ${required}
        >
          ${field.options ? field.options.map(option => `
            <option value="${option.value}" ${option.selected ? 'selected' : ''}>
              ${option.label}
            </option>
          `).join('') : ''}
        </select>
      `
      break
      
    case 'checkbox':
      fieldHTML = `
        <input
          type="checkbox"
          id="${fieldId}"
          name="${field.name}"
          value="1"
          class="size-4 rounded border border-white/15 bg-white/5 checked:border-transparent checked:bg-white disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-white/20 focus:ring-offset-2 ${field.className || ''}"
          ${field.value ? 'checked' : ''}
          ${required}
        >
        <label for="${fieldId}" class="ml-2 text-sm text-white">${field.label}</label>
      `
      break
      
    default:
      fieldHTML = `
        <input 
          type="text" 
          id="${fieldId}"
          name="${field.name}" 
          value="${field.value || ''}"
          class="form-input ${field.className || ''}" 
          ${placeholder} 
          ${required}
        >
      `
      break
  }
  
  // For checkbox, we handle the label differently
  if (field.type === 'checkbox') {
    return `
      <div class="form-group">
        <div class="flex items-center">
          ${fieldHTML}
        </div>
        ${field.helpText ? `<p class="text-sm text-zinc-500 dark:text-zinc-400 mt-1 ml-6">${field.helpText}</p>` : ''}
      </div>
    `
  }

  return `
    <div class="form-group">
      <label for="${fieldId}" class="form-label">
        ${field.label}${field.required ? ' *' : ''}
      </label>
      ${fieldHTML}
      ${field.helpText ? `<p class="text-sm text-zinc-500 dark:text-zinc-400 mt-1">${field.helpText}</p>` : ''}
    </div>
  `
}