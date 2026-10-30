import type { AuthSettings } from '../../services/auth-validation'

export function renderAuthSettingsForm(settings: AuthSettings): string {
  const fields = settings.requiredFields
  const validation = settings.validation
  const registration = settings.registration

  return `
    <div class="space-y-8">
      <!-- Required Fields Section -->
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Registration Fields</h3>
        <p class="text-sm text-gray-400 mb-6">Configure which fields are required during user registration and their minimum lengths.</p>

        <div class="space-y-6">
          ${Object.entries(fields).map(([fieldName, config]: [string, any]) => `
            <div class="border-b border-white/10 pb-6 last:border-b-0 last:pb-0">
              <div class="flex items-start justify-between mb-4">
                <div>
                  <h4 class="text-sm font-medium text-white">${config.label}</h4>
                  <p class="text-xs text-gray-400 mt-1">Field type: ${config.type}</p>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    name="requiredFields_${fieldName}_required"
                    ${config.required ? 'checked' : ''}
                    class="sr-only peer"
                  >
                  <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                  <span class="ml-3 text-sm font-medium text-gray-300">Required</span>
                </label>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-xs font-medium text-gray-400 mb-2">Minimum Length</label>
                  <input
                    type="number"
                    name="requiredFields_${fieldName}_minLength"
                    value="${config.minLength}"
                    min="0"
                    max="100"
                    class="backdrop-blur-sm bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white placeholder-gray-300 focus:border-blue-400 focus:outline-none transition-colors w-full"
                  >
                </div>
                <div>
                  <label class="block text-xs font-medium text-gray-400 mb-2">Field Label</label>
                  <input
                    type="text"
                    name="requiredFields_${fieldName}_label"
                    value="${config.label}"
                    class="backdrop-blur-sm bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white placeholder-gray-300 focus:border-blue-400 focus:outline-none transition-colors w-full"
                  >
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Password Requirements Section -->
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Password Requirements</h3>
        <p class="text-sm text-gray-400 mb-6">Additional password complexity requirements.</p>

        <div class="space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <label class="text-sm font-medium text-gray-300">Require Uppercase Letter</label>
              <p class="text-xs text-gray-400">Password must contain at least one uppercase letter (A-Z)</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="validation_passwordRequirements_requireUppercase"
                ${validation.passwordRequirements.requireUppercase ? 'checked' : ''}
                class="sr-only peer"
              >
              <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          <div class="flex items-center justify-between">
            <div>
              <label class="text-sm font-medium text-gray-300">Require Lowercase Letter</label>
              <p class="text-xs text-gray-400">Password must contain at least one lowercase letter (a-z)</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="validation_passwordRequirements_requireLowercase"
                ${validation.passwordRequirements.requireLowercase ? 'checked' : ''}
                class="sr-only peer"
              >
              <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          <div class="flex items-center justify-between">
            <div>
              <label class="text-sm font-medium text-gray-300">Require Numbers</label>
              <p class="text-xs text-gray-400">Password must contain at least one number (0-9)</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="validation_passwordRequirements_requireNumbers"
                ${validation.passwordRequirements.requireNumbers ? 'checked' : ''}
                class="sr-only peer"
              >
              <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          <div class="flex items-center justify-between">
            <div>
              <label class="text-sm font-medium text-gray-300">Require Special Characters</label>
              <p class="text-xs text-gray-400">Password must contain at least one special character (!@#$%^&*)</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="validation_passwordRequirements_requireSpecialChars"
                ${validation.passwordRequirements.requireSpecialChars ? 'checked' : ''}
                class="sr-only peer"
              >
              <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>
        </div>
      </div>

      <!-- Registration Settings Section -->
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Registration Settings</h3>
        <p class="text-sm text-gray-400 mb-6">General registration behavior.</p>

        <div class="space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <label class="text-sm font-medium text-gray-300">Allow User Registration</label>
              <p class="text-xs text-gray-400">Enable or disable public user registration</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="registration_enabled"
                ${registration.enabled ? 'checked' : ''}
                class="sr-only peer"
              >
              <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          <div class="flex items-center justify-between">
            <div>
              <label class="text-sm font-medium text-gray-300">Require Email Verification</label>
              <p class="text-xs text-gray-400">Users must verify their email before accessing the system</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="registration_requireEmailVerification"
                ${registration.requireEmailVerification ? 'checked' : ''}
                class="sr-only peer"
              >
              <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-300 mb-2">Default User Role</label>
            <select
              name="registration_defaultRole"
              class="backdrop-blur-sm bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:border-blue-400 focus:outline-none transition-colors w-full"
            >
              <option value="viewer" ${registration.defaultRole === 'viewer' ? 'selected' : ''}>Viewer</option>
              <option value="editor" ${registration.defaultRole === 'editor' ? 'selected' : ''}>Editor</option>
              <option value="admin" ${registration.defaultRole === 'admin' ? 'selected' : ''}>Admin</option>
            </select>
            <p class="text-xs text-gray-400 mt-1">Role assigned to new users upon registration</p>
          </div>
        </div>
      </div>

      <!-- Validation Settings Section -->
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Validation Settings</h3>
        <p class="text-sm text-gray-400 mb-6">Additional validation rules.</p>

        <div class="space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <label class="text-sm font-medium text-gray-300">Enforce Email Format</label>
              <p class="text-xs text-gray-400">Validate that email addresses are in correct format</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="validation_emailFormat"
                ${validation.emailFormat ? 'checked' : ''}
                class="sr-only peer"
              >
              <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

        </div>
      </div>
    </div>
  `
}
