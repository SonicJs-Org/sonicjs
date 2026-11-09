/**
 * English admin UI messages — the source of truth.
 *
 * Every other locale is typed as a partial of this object, and any key missing from a
 * locale falls back to the value here. Add new keys here first.
 *
 * Values are trusted, static strings and may be rendered into HTML as-is. Placeholders use
 * `{name}` and are filled (HTML-escaped) by `t()`.
 */
export const en = {
  common: {
    cancel: 'Cancel',
    enabled: 'Enabled',
    disabled: 'Disabled',
  },
  nav: {
    content: 'Content',
    collections: 'Collections',
    users: 'Users',
    plugins: 'Plugins',
    settings: 'Settings',
    docs: 'Docs',
    apiDocs: 'API Docs',
    developerDocs: 'Developer Docs',
    openApi: 'OpenAPI',
    myProfile: 'My Profile',
    signOut: 'Sign Out',
    closeMenu: 'Close menu',
    closeNavigation: 'Close navigation',
    togglePluginsSubmenu: 'Toggle plugins submenu',
    userFallback: 'User',
  },
  auth: {
    login: {
      pageTitle: 'Login',
      heading: 'Welcome Back',
      subheading: 'Sign in to your account to continue',
      email: 'Email Address',
      emailPlaceholder: 'Enter your email',
      password: 'Password',
      passwordPlaceholder: 'Enter your password',
      submit: 'Sign In',
      noAccount: "Don't have an account?",
      createAccount: 'Create one here',
    },
  },
  profile: {
    pageTitle: 'User Profile',
    breadcrumb: 'Profile',
    description: 'Manage your account settings and preferences',
    info: {
      heading: 'Profile Information',
      description: 'Update your account details',
    },
    fields: {
      firstName: 'First Name',
      firstNamePlaceholder: 'Enter your first name',
      lastName: 'Last Name',
      lastNamePlaceholder: 'Enter your last name',
      email: 'Email Address',
      emailPlaceholder: 'Enter your email address',
      phone: 'Phone Number',
      phonePlaceholder: 'Enter your phone number',
      bio: 'Bio',
      bioPlaceholder: 'Tell us about yourself...',
    },
    preferences: {
      heading: 'Preferences',
      timezone: 'Timezone',
      language: 'Language',
    },
    notifications: {
      heading: 'Notifications',
      email: 'Email notifications',
      emailDescription: 'Receive email updates about new features and product announcements.',
    },
    submit: 'Update Profile',
    picture: {
      heading: 'Profile Picture',
      alt: 'Profile picture',
      change: 'Change Picture',
    },
    account: {
      heading: 'Account Information',
      role: 'Role',
      memberSince: 'Member Since',
      lastLogin: 'Last Login',
      twoFactor: 'Two-Factor Auth',
    },
    security: {
      heading: 'Security',
      changePassword: 'Change Password',
      manageTwoFactor: 'Manage 2FA',
      enableTwoFactor: 'Enable 2FA',
    },
    password: {
      current: 'Current Password',
      currentPlaceholder: 'Enter current password',
      new: 'New Password',
      newPlaceholder: 'Enter new password',
      minLength: 'Must be at least 8 characters',
      confirm: 'Confirm New Password',
      confirmPlaceholder: 'Confirm new password',
      submit: 'Update Password',
    },
    messages: {
      requiredFields: 'First name, last name, and email are required.',
      invalidEmail: 'Please enter a valid email address.',
      emailTaken: 'Email is already taken by another user.',
      updated: 'Profile updated successfully!',
      updateFailed: 'Failed to update profile. Please try again.',
    },
  },
} as const
