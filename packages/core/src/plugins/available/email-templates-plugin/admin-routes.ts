import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { requireAuth, requireRbac } from '@sonicjs-cms/core';
import { createEmailManagementService } from './services/email-management';
// import { createEmailService } from './services/email';
import { EmailTemplateRenderer } from './services/email-renderer';
import { renderAdminLayout } from '../../../templates/layouts/admin-layout-v2.template';

type Bindings = {
  DB: D1Database;
  KV: KVNamespace;
  MEDIA_BUCKET: R2Bucket;
  EMAIL_QUEUE?: Queue;
  SENDGRID_API_KEY?: string;
  DEFAULT_FROM_EMAIL?: string;
  IMAGES_ACCOUNT_ID?: string;
  IMAGES_API_TOKEN?: string;
}

type Variables = {
  user: {
    userId: string;
    email: string;
    role: string;
    exp: number;
    iat: number;
  }
}

const emailRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Middleware to require email management permission for all email management routes
emailRoutes.use('/*', requireAuth());
emailRoutes.use('/*', requireRbac('email', 'manage'));

// Email management dashboard
emailRoutes.get('/', async (c) => {
  const user = c.get('user');
  const emailService = createEmailManagementService(c.env, user.userId);

  const [themes, templates] = await Promise.all([
    emailService.getThemes(),
    emailService.getTemplates(),
  ]);

  const content = `
    <div class="space-y-8">
      <!-- Header -->
      <div class="flex justify-between items-center">
        <div>
          <h1 class="text-3xl font-bold text-gray-1">Email Management</h1>
          <p class="text-gray-4 mt-2">Manage email themes, templates, and delivery settings</p>
        </div>
        <div class="flex gap-3">
          <a href="/admin/email/themes/new" class="btn-gradient px-4 py-2 rounded-lg text-white font-medium">
            New Theme
          </a>
          <a href="/admin/email/templates/new" class="btn-gradient px-4 py-2 rounded-lg text-white font-medium">
            New Template
          </a>
        </div>
      </div>

      <!-- Statistics Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div class="bg-gray-8 rounded-lg p-6 border border-gray-7">
          <h3 class="text-sm font-medium text-gray-4">Total Themes</h3>
          <p class="text-2xl font-bold text-gray-1 mt-2">${themes.length}</p>
        </div>
        <div class="bg-gray-8 rounded-lg p-6 border border-gray-7">
          <h3 class="text-sm font-medium text-gray-4">Total Templates</h3>
          <p class="text-2xl font-bold text-gray-1 mt-2">${templates.length}</p>
        </div>
        <div class="bg-gray-8 rounded-lg p-6 border border-gray-7">
          <h3 class="text-sm font-medium text-gray-4">Active Templates</h3>
          <p class="text-2xl font-bold text-gray-1 mt-2">${templates.filter(t => t.isActive).length}</p>
        </div>
        <div class="bg-gray-8 rounded-lg p-6 border border-gray-7">
          <h3 class="text-sm font-medium text-gray-4">Default Theme</h3>
          <p class="text-sm font-medium text-gray-1 mt-2">${themes.find(t => t.isDefault)?.name || 'None'}</p>
        </div>
      </div>

      <!-- Themes Section -->
      <div class="bg-gray-8 rounded-lg border border-gray-7">
        <div class="p-6 border-b border-gray-7">
          <div class="flex justify-between items-center">
            <h2 class="text-xl font-semibold text-gray-1">Email Themes</h2>
            <a href="/admin/email/themes" class="text-primary hover:text-primary-light">View All</a>
          </div>
        </div>
        <div class="p-6">
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            ${themes.slice(0, 6).map(theme => `
              <div class="bg-gray-7 rounded-lg p-4 border border-gray-6">
                <div class="flex items-center justify-between mb-3">
                  <h3 class="font-medium text-gray-1">${theme.name}</h3>
                  ${theme.isDefault ? '<span class="text-xs bg-primary px-2 py-1 rounded text-white">Default</span>' : ''}
                </div>
                <p class="text-sm text-gray-4 mb-3">${theme.description || 'No description'}</p>
                <div class="flex gap-2">
                  <a href="/admin/email/themes/${theme.id}" class="text-xs text-primary hover:text-primary-light">Edit</a>
                  <a href="/admin/email/themes/${theme.id}/preview" class="text-xs text-gray-4 hover:text-gray-3">Preview</a>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- Templates Section -->
      <div class="bg-gray-8 rounded-lg border border-gray-7">
        <div class="p-6 border-b border-gray-7">
          <div class="flex justify-between items-center">
            <h2 class="text-xl font-semibold text-gray-1">Email Templates</h2>
            <a href="/admin/email/templates" class="text-primary hover:text-primary-light">View All</a>
          </div>
        </div>
        <div class="p-6">
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead>
                <tr class="border-b border-gray-7">
                  <th class="text-left py-3 text-sm font-medium text-gray-4">Name</th>
                  <th class="text-left py-3 text-sm font-medium text-gray-4">Slug</th>
                  <th class="text-left py-3 text-sm font-medium text-gray-4">Status</th>
                  <th class="text-left py-3 text-sm font-medium text-gray-4">Actions</th>
                </tr>
              </thead>
              <tbody>
                ${templates.slice(0, 8).map(template => `
                  <tr class="border-b border-gray-7">
                    <td class="py-3 text-gray-1">${template.name}</td>
                    <td class="py-3 text-gray-4 font-mono text-sm">${template.slug}</td>
                    <td class="py-3">
                      <span class="text-xs px-2 py-1 rounded ${template.isActive ? 'bg-green-600 text-white' : 'bg-gray-6 text-gray-3'}">
                        ${template.isActive ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td class="py-3">
                      <div class="flex gap-2">
                        <a href="/admin/email/templates/${template.id}" class="text-xs text-primary hover:text-primary-light">Edit</a>
                        <a href="/admin/email/templates/${template.id}/preview" class="text-xs text-gray-4 hover:text-gray-3">Preview</a>
                        <a href="/admin/email/templates/${template.id}/test" class="text-xs text-yellow-400 hover:text-yellow-300">Test</a>
                      </div>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;

  return c.html(renderAdminLayout({
    title: 'Email Management',
    pageTitle: 'Email Management',
    currentPath: '/admin/email',
    user: {
      name: user.email,
      email: user.email,
      role: user.role
    },
    content,
  }));
});

// Email themes routes
emailRoutes.get('/themes', async (c) => {
  const user = c.get('user');
  const emailService = createEmailManagementService(c.env, user.userId);
  const themes = await emailService.getThemes();

  const content = `
    <div class="space-y-6">
      <div class="flex justify-between items-center">
        <h1 class="text-3xl font-bold text-gray-1">Email Themes</h1>
        <a href="/admin/email/themes/new" class="btn-gradient px-4 py-2 rounded-lg text-white font-medium">
          Create New Theme
        </a>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        ${themes.map(theme => `
          <div class="bg-gray-8 rounded-lg border border-gray-7 p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-semibold text-gray-1">${theme.name}</h3>
              ${theme.isDefault ? '<span class="text-xs bg-primary px-2 py-1 rounded text-white">Default</span>' : ''}
            </div>
            <p class="text-gray-4 mb-4">${theme.description || 'No description provided'}</p>
            <div class="flex items-center justify-between text-sm text-gray-4 mb-4">
              <span>Status: ${theme.isActive ? 'Active' : 'Inactive'}</span>
              <span>Created: ${theme.createdAt.toLocaleDateString()}</span>
            </div>
            <div class="flex gap-2">
              <a href="/admin/email/themes/${theme.id}" class="bg-primary hover:bg-primary-dark px-3 py-1 rounded text-xs text-white">
                Edit
              </a>
              <a href="/admin/email/themes/${theme.id}/preview" class="bg-gray-7 hover:bg-gray-6 px-3 py-1 rounded text-xs text-gray-3">
                Preview
              </a>
              ${!theme.isDefault ? `
                <a href="/admin/email/themes/${theme.id}/delete" 
                   onclick="return confirm('Are you sure you want to delete this theme?')"
                   class="bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-xs text-white">
                  Delete
                </a>
              ` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  return c.html(renderAdminLayout({
    title: 'Email Themes',
    pageTitle: 'Email Themes',
    currentPath: '/admin/email',
    user: {
      name: user.email,
      email: user.email,
      role: user.role
    },
    content,
  }));
});

// Email templates routes
emailRoutes.get('/templates', async (c) => {
  const user = c.get('user');
  const emailService = createEmailManagementService(c.env, user.userId);
  const templates = await emailService.getTemplates();

  const content = `
    <div class="space-y-6">
      <div class="flex justify-between items-center">
        <h1 class="text-3xl font-bold text-gray-1">Email Templates</h1>
        <a href="/admin/email/templates/new" class="btn-gradient px-4 py-2 rounded-lg text-white font-medium">
          Create New Template
        </a>
      </div>

      <div class="bg-gray-8 rounded-lg border border-gray-7">
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="border-b border-gray-7">
                <th class="text-left p-6 text-sm font-medium text-gray-4">Name</th>
                <th class="text-left p-6 text-sm font-medium text-gray-4">Slug</th>
                <th class="text-left p-6 text-sm font-medium text-gray-4">Subject</th>
                <th class="text-left p-6 text-sm font-medium text-gray-4">Status</th>
                <th class="text-left p-6 text-sm font-medium text-gray-4">Created</th>
                <th class="text-left p-6 text-sm font-medium text-gray-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${templates.map(template => `
                <tr class="border-b border-gray-7">
                  <td class="p-6 text-gray-1 font-medium">${template.name}</td>
                  <td class="p-6 text-gray-4 font-mono text-sm">${template.slug}</td>
                  <td class="p-6 text-gray-3 max-w-xs truncate">${template.subject}</td>
                  <td class="p-6">
                    <span class="text-xs px-2 py-1 rounded ${template.isActive ? 'bg-green-600 text-white' : 'bg-gray-6 text-gray-3'}">
                      ${template.isActive ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td class="p-6 text-gray-4 text-sm">${template.createdAt.toLocaleDateString()}</td>
                  <td class="p-6">
                    <div class="flex gap-2">
                      <a href="/admin/email/templates/${template.id}" class="text-xs text-primary hover:text-primary-light">Edit</a>
                      <a href="/admin/email/templates/${template.id}/preview" class="text-xs text-gray-4 hover:text-gray-3">Preview</a>
                      <a href="/admin/email/templates/${template.id}/test" class="text-xs text-yellow-400 hover:text-yellow-300">Test</a>
                      <a href="/admin/email/templates/${template.id}/delete" 
                         onclick="return confirm('Are you sure you want to delete this template?')"
                         class="text-xs text-red-400 hover:text-red-300">Delete</a>
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  return c.html(renderAdminLayout({
    title: 'Email Templates',
    pageTitle: 'Email Templates',
    currentPath: '/admin/email',
    user: {
      name: user.email,
      email: user.email,
      role: user.role
    },
    content,
  }));
});

// Template preview with dummy data
emailRoutes.get('/templates/:id/preview', async (c) => {
  const user = c.get('user');
  const templateId = c.req.param('id');
  
  const emailService = createEmailManagementService(c.env, user.userId);
  const template = await emailService.getTemplateById(templateId);
  
  if (!template) {
    return c.notFound();
  }

  try {
    const renderer = new EmailTemplateRenderer(c.env.DB);
    const dummyVariables = EmailTemplateRenderer.getDummyVariables();
    const rendered = await renderer.renderTemplate(template.slug, dummyVariables);

    // Return the HTML preview
    return c.html(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Preview: ${template.name}</title>
        <style>
          body { margin: 0; padding: 20px; background: #f5f5f5; }
          .preview-container { max-width: 800px; margin: 0 auto; }
          .preview-header { background: white; padding: 20px; border-radius: 8px 8px 0 0; border-bottom: 1px solid #ddd; }
          .preview-content { background: white; border-radius: 0 0 8px 8px; }
          .back-button { display: inline-block; margin-bottom: 20px; padding: 8px 16px; background: #8b5cf6; color: white; text-decoration: none; border-radius: 4px; }
        </style>
      </head>
      <body>
        <div class="preview-container">
          <a href="/admin/email/templates" class="back-button">← Back to Templates</a>
          <div class="preview-header">
            <h1 style="margin: 0 0 10px 0;">Preview: ${template.name}</h1>
            <p style="margin: 0; color: #666;"><strong>Subject:</strong> ${rendered.subject}</p>
          </div>
          <div class="preview-content">
            ${rendered.html}
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    return c.html(`
      <h1>Preview Error</h1>
      <p>Failed to render template: ${error instanceof Error ? error.message : 'Unknown error'}</p>
      <a href="/admin/email/templates">← Back to Templates</a>
    `);
  }
});

// New theme form
emailRoutes.get('/themes/new', async (c) => {
  const user = c.get('user');

  const content = `
    <div class="space-y-6">
      <div class="flex items-center gap-4">
        <a href="/admin/email/themes" class="text-gray-4 hover:text-gray-3">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
          </svg>
        </a>
        <h1 class="text-3xl font-bold text-gray-1">Create New Email Theme</h1>
      </div>

      <form hx-post="/admin/email/themes" hx-target="#main-content" class="space-y-6">
        <div class="bg-gray-8 rounded-lg border border-gray-7 p-6">
          <h2 class="text-xl font-semibold text-gray-1 mb-4">Theme Details</h2>
          
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label class="block text-sm font-medium text-gray-3 mb-2">Theme Name</label>
              <input type="text" name="name" required 
                     class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none">
            </div>
            
            <div class="flex items-center">
              <label class="flex items-center">
                <input type="checkbox" name="isDefault" class="mr-2">
                <span class="text-sm text-gray-3">Set as default theme</span>
              </label>
            </div>
          </div>

          <div class="mt-4">
            <label class="block text-sm font-medium text-gray-3 mb-2">Description</label>
            <textarea name="description" rows="3" 
                      class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none"
                      placeholder="Brief description of this theme..."></textarea>
          </div>
        </div>

        <div class="bg-gray-8 rounded-lg border border-gray-7 p-6">
          <h2 class="text-xl font-semibold text-gray-1 mb-4">HTML Template</h2>
          <p class="text-sm text-gray-4 mb-3">Use {{content}} for the email body and {{subject}} for the subject line. Available variables: {{user.firstName}}, {{user.email}}, {{site.name}}, {{site.url}}</p>
          <textarea name="htmlTemplate" rows="15" required
                    class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none font-mono text-sm"><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{subject}}</title>
    <style>{{{styles}}}</style>
</head>
<body>
    <div class="email-container">
        <header class="email-header">
            <h1 class="logo">{{site.name}}</h1>
        </header>
        
        <main class="email-content">
            {{content}}
        </main>
        
        <footer class="email-footer">
            <p>&copy; {{date.year}} {{site.name}}. All rights reserved.</p>
            <p>Visit us at <a href="{{site.url}}">{{site.url}}</a></p>
        </footer>
    </div>
</body>
</html></textarea>
        </div>

        <div class="bg-gray-8 rounded-lg border border-gray-7 p-6">
          <h2 class="text-xl font-semibold text-gray-1 mb-4">CSS Styles</h2>
          <p class="text-sm text-gray-4 mb-3">Email-safe CSS styles. Avoid complex layouts and use inline styles when possible for better email client compatibility.</p>
          <textarea name="cssStyles" rows="12" required
                    class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none font-mono text-sm">/* Email Container */
.email-container {
    max-width: 600px;
    margin: 0 auto;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6;
    color: #333333;
    background-color: #ffffff;
}

/* Header */
.email-header {
    background: linear-gradient(135deg, #8b5cf6 0%, #a855f7 100%);
    padding: 30px 20px;
    text-align: center;
}

.logo {
    color: #ffffff;
    margin: 0;
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
}

/* Content */
.email-content {
    padding: 40px 30px;
    background-color: #ffffff;
}

.email-content h1 {
    color: #1f2937;
    font-size: 24px;
    margin-bottom: 20px;
    font-weight: 600;
}

.email-content h2 {
    color: #374151;
    font-size: 20px;
    margin: 30px 0 15px 0;
    font-weight: 600;
}

.email-content p {
    margin-bottom: 16px;
    color: #4b5563;
}

.email-content a {
    color: #8b5cf6;
    text-decoration: none;
}

.email-content a:hover {
    text-decoration: underline;
}

/* Button */
.email-button {
    display: inline-block;
    background: linear-gradient(135deg, #8b5cf6 0%, #a855f7 100%);
    color: #ffffff;
    padding: 12px 24px;
    text-decoration: none;
    border-radius: 6px;
    font-weight: 500;
    margin: 20px 0;
}

/* Footer */
.email-footer {
    background-color: #f9fafb;
    padding: 30px;
    text-align: center;
    border-top: 1px solid #e5e7eb;
}

.email-footer p {
    margin: 5px 0;
    font-size: 14px;
    color: #6b7280;
}

.email-footer a {
    color: #8b5cf6;
    text-decoration: none;
}</textarea>
        </div>

        <div class="flex gap-3">
          <button type="submit" class="btn-gradient px-6 py-2 rounded-lg text-white font-medium">
            Create Theme
          </button>
          <a href="/admin/email/themes" class="bg-gray-6 hover:bg-gray-5 px-6 py-2 rounded-lg text-gray-3 hover:text-gray-1">
            Cancel
          </a>
        </div>
      </form>
    </div>
  `;

  return c.html(renderAdminLayout({
    title: 'Create Email Theme',
    pageTitle: 'Create Email Theme',
    currentPath: '/admin/email',
    user: {
      name: user.email,
      email: user.email,
      role: user.role
    },
    content,
  }));
});

// New template form
emailRoutes.get('/templates/new', async (c) => {
  const user = c.get('user');
  const emailService = createEmailManagementService(c.env, user.userId);
  const themes = await emailService.getThemes();

  const content = `
    <div class="space-y-6">
      <div class="flex items-center gap-4">
        <a href="/admin/email/templates" class="text-gray-4 hover:text-gray-3">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
          </svg>
        </a>
        <h1 class="text-3xl font-bold text-gray-1">Create New Email Template</h1>
      </div>

      <form hx-post="/admin/email/templates" hx-target="#main-content" class="space-y-6">
        <div class="bg-gray-8 rounded-lg border border-gray-7 p-6">
          <h2 class="text-xl font-semibold text-gray-1 mb-4">Template Details</h2>
          
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label class="block text-sm font-medium text-gray-3 mb-2">Template Name</label>
              <input type="text" name="name" required 
                     class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none">
            </div>
            
            <div>
              <label class="block text-sm font-medium text-gray-3 mb-2">Slug</label>
              <input type="text" name="slug" required pattern="[a-z0-9-]+" 
                     class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none"
                     placeholder="welcome-email">
            </div>
          </div>

          <div class="mt-4">
            <label class="block text-sm font-medium text-gray-3 mb-2">Subject Line</label>
            <input type="text" name="subject" required 
                   class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none"
                   placeholder="Welcome to {{site.name}}!">
          </div>

          <div class="mt-4">
            <label class="block text-sm font-medium text-gray-3 mb-2">Email Theme</label>
            <select name="themeId" required 
                    class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none">
              <option value="">Select a theme...</option>
              ${themes.map(theme => `
                <option value="${theme.id}" ${theme.isDefault ? 'selected' : ''}>
                  ${theme.name} ${theme.isDefault ? '(Default)' : ''}
                </option>
              `).join('')}
            </select>
          </div>

          <div class="mt-4 flex items-center">
            <label class="flex items-center">
              <input type="checkbox" name="isActive" checked class="mr-2">
              <span class="text-sm text-gray-3">Active template</span>
            </label>
          </div>
        </div>

        <div class="bg-gray-8 rounded-lg border border-gray-7 p-6">
          <h2 class="text-xl font-semibold text-gray-1 mb-4">Email Content (Markdown)</h2>
          <textarea name="markdownContent" rows="12" required
                    class="form-input w-full rounded-lg border border-gray-6 bg-gray-7 px-4 py-2 text-gray-1 focus:border-primary focus:outline-none font-mono text-sm"
                    placeholder="# Welcome to {{site.name}}!&#10;&#10;Hello {{user.firstName}},&#10;&#10;Welcome to our platform! We're excited to have you on board.&#10;&#10;## Getting Started&#10;&#10;Here are some quick steps to get you started:&#10;&#10;1. Complete your profile&#10;2. Explore our features&#10;3. Join our community&#10;&#10;Best regards,&#10;The {{site.name}} Team"></textarea>
        </div>

        <div class="flex gap-3">
          <button type="submit" class="btn-gradient px-6 py-2 rounded-lg text-white font-medium">
            Create Template
          </button>
          <a href="/admin/email/templates" class="bg-gray-6 hover:bg-gray-5 px-6 py-2 rounded-lg text-gray-3 hover:text-gray-1">
            Cancel
          </a>
        </div>
      </form>
    </div>
  `;

  return c.html(renderAdminLayout({
    title: 'Create Email Template',
    pageTitle: 'Create Email Template',
    currentPath: '/admin/email',
    user: {
      name: user.email,
      email: user.email,
      role: user.role
    },
    content,
  }));
});

// Create theme (POST)
emailRoutes.post('/themes', zValidator('form', z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  htmlTemplate: z.string().min(1),
  cssStyles: z.string().min(1),
  isDefault: z.string().optional().transform(val => val === 'on')
})), async (c) => {
  const user = c.get('user');
  const data = c.req.valid('form');
  const emailService = createEmailManagementService(c.env, user.userId);

  try {
    await emailService.createTheme({
      name: data.name,
      description: data.description || null,
      htmlTemplate: data.htmlTemplate,
      cssStyles: data.cssStyles,
      isDefault: data.isDefault || false,
      isActive: true,
      createdBy: user.userId,
    });

    return c.redirect('/admin/email/themes');
  } catch (error) {
    return c.html(`
      <div class="bg-red-600 text-white p-4 rounded-lg">
        <h3 class="font-semibold">Error creating theme</h3>
        <p>${error instanceof Error ? error.message : 'Unknown error'}</p>
        <a href="/admin/email/themes/new" class="underline">← Try again</a>
      </div>
    `);
  }
});

// Create template (POST)
emailRoutes.post('/templates', zValidator('form', z.object({
  name: z.string().min(1),
  slug: z.string().min(1).regex(/^[a-z0-9-]+$/),
  subject: z.string().min(1),
  themeId: z.string().min(1),
  markdownContent: z.string().min(1),
  isActive: z.string().optional().transform(val => val === 'on')
})), async (c) => {
  const user = c.get('user');
  const data = c.req.valid('form');
  const emailService = createEmailManagementService(c.env, user.userId);

  try {
    await emailService.createTemplate({
      themeId: data.themeId,
      name: data.name,
      slug: data.slug,
      subject: data.subject,
      markdownContent: data.markdownContent,
      variables: null,
      metadata: '{}',
      isActive: data.isActive !== false,
      version: 1,
      createdBy: user.userId,
    });

    return c.redirect('/admin/email/templates');
  } catch (error) {
    return c.html(`
      <div class="bg-red-600 text-white p-4 rounded-lg">
        <h3 class="font-semibold">Error creating template</h3>
        <p>${error instanceof Error ? error.message : 'Unknown error'}</p>
        <a href="/admin/email/templates/new" class="underline">← Try again</a>
      </div>
    `);
  }
});

// Initialize email system
emailRoutes.post('/initialize', async (c) => {
  const user = c.get('user');
  const emailService = createEmailManagementService(c.env, user.userId);
  
  try {
    await emailService.initializeDefaultData();
    return c.json({ success: true, message: 'Email system initialized successfully' });
  } catch (error) {
    return c.json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

export default emailRoutes;
