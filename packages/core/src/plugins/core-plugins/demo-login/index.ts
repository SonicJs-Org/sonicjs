/**
 * Demo Login Plugin — Payload-shaped port.
 *
 * Prefills login form with demo credentials. The legacy `template:render` /
 * `page:before-render` hooks aren't in the typed catalog; we subscribe them
 * dynamically in onBoot via the raw hook system so they keep working.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { setDemoModeActive } from '../../../services/demo-mode'

const demoLoginJs = `
  // Demo Login Prefill Script
  (function() {
    'use strict';

    function prefillLoginForm() {
      const emailInput = document.getElementById('email');
      const passwordInput = document.getElementById('password');

      if (emailInput && passwordInput) {
        emailInput.value = 'admin@sonicjs.com';
        passwordInput.value = 'sonicjs!';

        const form = emailInput.closest('form');
        if (form) {
          const notice = document.createElement('div');
          notice.className = 'mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg text-blue-800 text-sm';
          notice.innerHTML = '🎯 <strong>Demo Mode:</strong> Login form prefilled with demo credentials';
          form.insertBefore(notice, form.firstChild);
        }
      }
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', prefillLoginForm);
    } else {
      prefillLoginForm();
    }

    document.addEventListener('htmx:afterSwap', function(event) {
      if (event.detail.target.id === 'main-content' ||
          document.getElementById('email')) {
        setTimeout(prefillLoginForm, 100);
      }
    });
  })();
`

const loginPrefillHandler = async (data: any) => {
  if (data.pageType === 'auth-login' || data.template?.includes('login')) {
    data.scripts = data.scripts ?? []
    data.inlineScripts = data.inlineScripts ?? []
    data.inlineScripts.push(demoLoginJs)
  }
  return data
}

export const demoLoginPlugin = definePlugin({
  id: 'demo-login-plugin',
  version: '1.0.0',
  name: 'Demo Login',
  description: 'Prefills login form with demo credentials (admin@sonicjs.com/sonicjs!) for easy site demonstration.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS' },

  async onBoot(ctx) {
    setDemoModeActive()
    // Legacy non-typed hooks — subscribe via the raw bus.
    const hooks = (ctx.raw as any)?.hooks
    if (hooks?.register) {
      hooks.register('template:render', loginPrefillHandler)
      hooks.register('page:before-render', loginPrefillHandler)
    }
  },
})
