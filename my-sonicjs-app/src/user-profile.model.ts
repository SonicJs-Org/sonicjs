/**
 * User Profile Model
 *
 * Define custom profile fields for your users. When configured, these fields
 * appear in the admin user create/edit forms.
 *
 * Uncomment and customize defineUserProfile() to activate custom fields.
 * Add to registrationFields to also show a field on the new-user form.
 */

// import { defineUserProfile } from '@sonicjs-cms/core';

// Uncomment and call defineUserProfile() to activate custom profile fields.
// The default "unconfigured" state hides the Profile Information section on
// user create/edit pages (test 80 asserts this unconfigured state).
//
// defineUserProfile({
//   fields: [
//     {
//       name: 'bio',
//       label: 'Bio',
//       type: 'textarea',
//       required: false,
//       placeholder: 'A short bio',
//     },
//     {
//       name: 'company',
//       label: 'Company',
//       type: 'text',
//       required: false,
//     },
//     {
//       name: 'jobTitle',
//       label: 'Job Title',
//       type: 'text',
//       required: false,
//     },
//     {
//       name: 'website',
//       label: 'Website',
//       type: 'text',
//       required: false,
//       placeholder: 'https://example.com',
//     },
//   ],
//   // registrationFields: ['bio'], // Fields shown on the new-user form
// });
