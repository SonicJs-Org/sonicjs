import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderAlert } from '../alert.template'

export interface UserProfile {
  id: string
  email: string
  username: string
  first_name: string
  last_name: string
  phone?: string
  bio?: string
  avatar_url?: string
  timezone: string
  language: string
  theme: string
  email_notifications: boolean
  two_factor_enabled: boolean
  role: string
  created_at: number
  last_login_at?: number
}

export interface ProfilePageData {
  profile: UserProfile
  timezones: Array<{ value: string; label: string }>
  languages: Array<{ value: string; label: string }>
  error?: string
  success?: string
  customProfileFieldsHtml?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

export function renderAvatarImage(avatarUrl: string | undefined, firstName: string, lastName: string): string {
  return `<div id="avatar-image-container" class="w-24 h-24 rounded-full mx-auto mb-4 overflow-hidden bg-gradient-to-br from-cyan-400 to-purple-400 flex items-center justify-center ring-4 ring-zinc-950/5 dark:ring-white/10">
    ${avatarUrl
      ? `<img src="${avatarUrl}" alt="Profile picture" class="w-full h-full object-cover">`
      : `<span class="text-2xl font-bold text-white">${firstName.charAt(0)}${lastName.charAt(0)}</span>`
    }
  </div>`
}

export function renderProfilePage(data: ProfilePageData): string {
  const pageContent = `
    <div class="space-y-8">
      <!-- Header -->
      <div class="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">User Profile</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Manage your account settings and preferences
          </p>
        </div>
      </div>

      <!-- Alert Messages -->
      ${data.error ? renderAlert({ type: 'error', message: data.error, dismissible: true }) : ''}
      ${data.success ? renderAlert({ type: 'success', message: data.success, dismissible: true }) : ''}

      <!-- Profile Form -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <!-- Main Profile Form -->
        <div class="lg:col-span-2">
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <!-- Form Header -->
            <div class="px-6 py-5 border-b border-zinc-950/5 dark:border-white/5">
              <div class="flex items-center gap-x-3">
                <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-950 dark:bg-white">
                  <svg class="h-5 w-5 text-white dark:text-zinc-950" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                  </svg>
                </div>
                <div>
                  <h2 class="text-base font-semibold text-zinc-950 dark:text-white">Profile Information</h2>
                  <p class="text-sm text-zinc-500 dark:text-zinc-400">Update your account details</p>
                </div>
              </div>
            </div>

            <!-- Form Content -->
            <form id="profile-form" hx-put="/admin/profile" hx-target="#form-messages" class="p-6 space-y-6">
              <div id="form-messages"></div>

              <!-- Basic Information -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">First Name</label>
                  <input
                    type="text"
                    name="first_name"
                    value="${data.profile.first_name}"
                    required
                    class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    placeholder="Enter your first name"
                  >
                </div>
                <div>
                  <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Last Name</label>
                  <input
                    type="text"
                    name="last_name"
                    value="${data.profile.last_name}"
                    required
                    class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    placeholder="Enter your last name"
                  >
                </div>
              </div>

              <div>
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Username</label>
                <input
                  type="text"
                  name="username"
                  value="${data.profile.username}"
                  required
                  class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                  placeholder="Enter your username"
                >
              </div>

              <div>
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Email Address</label>
                <input
                  type="email"
                  name="email"
                  value="${data.profile.email}"
                  required
                  class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                  placeholder="Enter your email address"
                >
              </div>

              <div>
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Phone Number</label>
                <input
                  type="tel"
                  name="phone"
                  value="${data.profile.phone || ''}"
                  class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                  placeholder="Enter your phone number"
                >
              </div>

              <div>
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Bio</label>
                <textarea
                  name="bio"
                  rows="3"
                  class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow resize-none"
                  placeholder="Tell us about yourself..."
                >${data.profile.bio || ''}</textarea>
              </div>

              ${data.customProfileFieldsHtml || ''}

              <!-- Preferences -->
              <div class="pt-6 border-t border-zinc-950/5 dark:border-white/5">
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Preferences</h3>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label for="timezone" class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">Timezone</label>
                    <div class="grid grid-cols-1">
                      <select id="timezone" name="timezone" class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400 sm:text-sm/6">
                        ${data.timezones.map(tz => `
                          <option value="${tz.value}" ${tz.value === data.profile.timezone ? 'selected' : ''}>${tz.label}</option>
                        `).join('')}
                      </select>
                      <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-600 dark:text-zinc-400 sm:size-4">
                        <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                      </svg>
                    </div>
                  </div>
                  <div>
                    <label for="language" class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">Language</label>
                    <div class="grid grid-cols-1">
                      <select id="language" name="language" class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400 sm:text-sm/6">
                        ${data.languages.map(lang => `
                          <option value="${lang.value}" ${lang.value === data.profile.language ? 'selected' : ''}>${lang.label}</option>
                        `).join('')}
                      </select>
                      <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-600 dark:text-zinc-400 sm:size-4">
                        <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Notifications -->
              <div class="pt-6 border-t border-zinc-950/5 dark:border-white/5">
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Notifications</h3>

                <div class="space-y-5">
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input
                          type="checkbox"
                          id="email_notifications"
                          name="email_notifications"
                          value="1"
                          ${data.profile.email_notifications ? 'checked' : ''}
                          class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto"
                        />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6">
                      <label for="email_notifications" class="font-medium text-zinc-950 dark:text-white">Email notifications</label>
                      <p class="text-zinc-500 dark:text-zinc-400">Receive email updates about new features and product announcements.</p>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Submit Button -->
              <div class="pt-6 border-t border-zinc-950/5 dark:border-white/5">
                <button
                  type="submit"
                  class="inline-flex justify-center items-center gap-x-2 rounded-lg bg-zinc-950 dark:bg-white px-4 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 dark:focus-visible:outline-white transition-colors"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                  </svg>
                  Update Profile
                </button>
              </div>
            </form>
          </div>
        </div>

        <!-- Profile Sidebar -->
        <div class="lg:col-span-1 space-y-6">
          <!-- Avatar -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Profile Picture</h3>

            <div class="text-center">
              ${renderAvatarImage(data.profile.avatar_url, data.profile.first_name, data.profile.last_name)}

              <form id="avatar-form" hx-post="/admin/profile/avatar" hx-target="#avatar-messages" hx-encoding="multipart/form-data">
                <input
                  type="file"
                  name="avatar"
                  accept="image/*"
                  class="hidden"
                  id="avatar-input"
                  onchange="document.getElementById('avatar-form').dispatchEvent(new Event('submit'))"
                >
                <label
                  for="avatar-input"
                  class="inline-flex items-center gap-x-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors cursor-pointer"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 13a3 3 0 11-6 0 3 3 0 016 0z"/>
                  </svg>
                  Change Picture
                </label>
              </form>

              <div id="avatar-messages" class="mt-3"></div>
            </div>
          </div>

          <!-- Account Info -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Account Information</h3>

            <dl class="space-y-3 text-sm">
              <div>
                <dt class="text-zinc-500 dark:text-zinc-400">Role</dt>
                <dd class="mt-1">
                  <span class="inline-flex items-center rounded-md bg-blue-50 dark:bg-blue-500/10 px-2 py-1 text-xs font-medium text-blue-700 dark:text-blue-400 ring-1 ring-inset ring-blue-700/10 dark:ring-blue-400/20 capitalize">
                    ${data.profile.role}
                  </span>
                </dd>
              </div>
              <div>
                <dt class="text-zinc-500 dark:text-zinc-400">Member Since</dt>
                <dd class="mt-1 text-zinc-950 dark:text-white">${new Date(data.profile.created_at).toLocaleDateString()}</dd>
              </div>
              ${data.profile.last_login_at ? `
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Last Login</dt>
                  <dd class="mt-1 text-zinc-950 dark:text-white">${new Date(data.profile.last_login_at).toLocaleDateString()}</dd>
                </div>
              ` : ''}
              <div>
                <dt class="text-zinc-500 dark:text-zinc-400">Two-Factor Auth</dt>
                <dd class="mt-1">
                  ${data.profile.two_factor_enabled
                    ? '<span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">Enabled</span>'
                    : '<span class="inline-flex items-center rounded-md bg-zinc-50 dark:bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/10 dark:ring-zinc-400/20">Disabled</span>'
                  }
                </dd>
              </div>
            </dl>
          </div>

          <!-- Security Actions -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Security</h3>

            <div class="space-y-2">
              <button
                type="button"
                onclick="showChangePasswordModal()"
                class="w-full text-left flex items-center gap-x-3 px-3 py-2 text-sm text-zinc-950 dark:text-white hover:bg-zinc-50 dark:hover:bg-zinc-800/50 rounded-lg transition-colors"
              >
                <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-3.586l4.293-4.293A6 6 0 0119 9z"/>
                </svg>
                <span class="font-medium">Change Password</span>
              </button>

              <button
                type="button"
                onclick="toggle2FA()"
                class="w-full text-left flex items-center gap-x-3 px-3 py-2 text-sm text-zinc-950 dark:text-white hover:bg-zinc-50 dark:hover:bg-zinc-800/50 rounded-lg transition-colors"
              >
                <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
                <span class="font-medium">${data.profile.two_factor_enabled ? 'Disable' : 'Enable'} 2FA</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Change Password Modal -->
    <div id="password-modal" class="fixed inset-0 bg-zinc-950/50 backdrop-blur-sm flex items-center justify-center z-50 hidden">
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-2xl ring-1 ring-zinc-950/5 dark:ring-white/10 w-full max-w-md mx-4">
        <div class="px-6 py-5 border-b border-zinc-950/5 dark:border-white/5">
          <div class="flex items-center justify-between">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white">Change Password</h3>
            <button onclick="closePasswordModal()" class="text-zinc-500 dark:text-zinc-400 hover:text-zinc-950 dark:hover:text-white transition-colors">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </button>
          </div>
        </div>

        <form id="password-form" hx-post="/admin/profile/password" hx-target="#password-messages" class="p-6 space-y-4">
          <div id="password-messages"></div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Current Password</label>
            <input
              type="password"
              name="current_password"
              required
              class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
              placeholder="Enter current password"
            >
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">New Password</label>
            <input
              type="password"
              name="new_password"
              required
              minlength="8"
              class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
              placeholder="Enter new password"
            >
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Must be at least 8 characters</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Confirm New Password</label>
            <input
              type="password"
              name="confirm_password"
              required
              minlength="8"
              class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
              placeholder="Confirm new password"
            >
          </div>

          <div class="flex justify-end gap-x-3 pt-4 border-t border-zinc-950/5 dark:border-white/5">
            <button
              type="button"
              onclick="closePasswordModal()"
              class="rounded-lg bg-white dark:bg-zinc-800 px-4 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              class="inline-flex items-center gap-x-2 rounded-lg bg-zinc-950 dark:bg-white px-4 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              Update Password
            </button>
          </div>
        </form>
      </div>
    </div>

    <script>
      function showChangePasswordModal() {
        document.getElementById('password-modal').classList.remove('hidden');
      }

      function closePasswordModal() {
        document.getElementById('password-modal').classList.add('hidden');
        document.getElementById('password-form').reset();
      }

      function toggle2FA() {
        // TODO: Implement 2FA toggle
        alert('Two-factor authentication setup coming soon!');
      }

      // Close modal on escape key
      document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && !document.getElementById('password-modal').classList.contains('hidden')) {
          closePasswordModal();
        }
      });

      // Close modal on backdrop click
      document.getElementById('password-modal').addEventListener('click', function(e) {
        if (e.target === this) {
          closePasswordModal();
        }
      });
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'User Profile',
    pageTitle: 'Profile',
    currentPath: '/admin/profile',
    user: data.user,
    version: data.version,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}
