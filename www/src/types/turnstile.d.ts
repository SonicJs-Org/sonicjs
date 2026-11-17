// Shared ambient type for the Cloudflare Turnstile widget script loaded on
// pages that embed a Turnstile challenge (e.g. ContactForm). Previously
// declared inside SupportContactForm.tsx; moved here when that component
// was removed so this augmentation isn't lost.
declare global {
  interface Window {
    turnstile?: {
      render: (
        el: HTMLElement,
        opts: {
          sitekey: string
          callback: (token: string) => void
          'expired-callback'?: () => void
          'error-callback'?: () => void
          theme?: 'auto' | 'light' | 'dark'
        },
      ) => string
      reset: (id?: string) => void
    }
  }
}

export {}
