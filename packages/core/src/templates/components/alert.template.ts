import { escapeHtml } from '../../utils/sanitize'

export type AlertType = 'success' | 'error' | 'warning' | 'info'

export interface AlertData {
  type: AlertType
  title?: string
  message: string
  dismissible?: boolean
  className?: string
  icon?: boolean
}

export function renderAlert(data: AlertData): string {
  const typeClasses = {
    success: 'bg-green-50 dark:bg-green-500/10 border border-green-600/20 dark:border-green-500/20',
    error: 'bg-error/10 border border-red-600/20 dark:border-red-500/20',
    warning: 'bg-amber-50 dark:bg-amber-500/10 border border-amber-600/20 dark:border-amber-500/20',
    info: 'bg-blue-50 dark:bg-blue-500/10 border border-blue-600/20 dark:border-blue-500/20'
  }

  const iconClasses = {
    success: 'text-green-600 dark:text-green-400',
    error: 'text-red-600 dark:text-red-400',
    warning: 'text-amber-600 dark:text-amber-400',
    info: 'text-blue-600 dark:text-blue-400'
  }

  const textClasses = {
    success: 'text-green-900 dark:text-green-300',
    error: 'text-red-900 dark:text-red-300',
    warning: 'text-amber-900 dark:text-amber-300',
    info: 'text-blue-900 dark:text-blue-300'
  }

  const messageTextClasses = {
    success: 'text-green-700 dark:text-green-400',
    error: 'text-red-700 dark:text-red-400',
    warning: 'text-amber-700 dark:text-amber-400',
    info: 'text-blue-700 dark:text-blue-400'
  }

  const icons = {
    success: `<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />`,
    error: `<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />`,
    warning: `<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />`,
    info: `<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />`
  }

  return `
    <div class="rounded-lg p-4 ${typeClasses[data.type]} ${data.className || ''}" ${data.dismissible ? 'id="dismissible-alert"' : ''}>
      <div class="flex">
        ${data.icon !== false ? `
          <div class="flex-shrink-0">
            <svg class="h-5 w-5 ${iconClasses[data.type]}" viewBox="0 0 20 20" fill="currentColor">
              ${icons[data.type]}
            </svg>
          </div>
        ` : ''}
        <div class="${data.icon !== false ? 'ml-3' : ''}">
          ${data.title ? `
            <h3 class="text-sm font-semibold ${textClasses[data.type]}">
              ${escapeHtml(data.title)}
            </h3>
          ` : ''}
          <div class="${data.title ? 'mt-1 text-sm' : 'text-sm'} ${messageTextClasses[data.type]}">
            <p>${escapeHtml(data.message)}</p>
          </div>
        </div>
        ${data.dismissible ? `
          <div class="ml-auto pl-3">
            <div class="-mx-1.5 -my-1.5">
              <button
                type="button"
                class="inline-flex rounded-md p-1.5 ${iconClasses[data.type]} hover:bg-opacity-20 focus:outline-none focus:ring-2 focus:ring-offset-2"
                onclick="document.getElementById('dismissible-alert').remove()"
              >
                <span class="sr-only">Dismiss</span>
                <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          </div>
        ` : ''}
      </div>
    </div>
  `
}

export function renderSuccessAlert(message: string, title?: string): string {
  return renderAlert({ type: 'success', message, title })
}

export function renderErrorAlert(message: string, title?: string): string {
  return renderAlert({ type: 'error', message, title })
}

export function renderWarningAlert(message: string, title?: string): string {
  return renderAlert({ type: 'warning', message, title })
}

export function renderInfoAlert(message: string, title?: string): string {
  return renderAlert({ type: 'info', message, title })
}
