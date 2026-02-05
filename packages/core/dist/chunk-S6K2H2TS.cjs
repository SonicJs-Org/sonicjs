'use strict';

var chunkSHCYIZAN_cjs = require('./chunk-SHCYIZAN.cjs');

// src/templates/filter-bar.template.ts
function renderFilterBar(data) {
  return `
    <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
      <form id="filter-form" class="flex flex-wrap gap-4 items-center">
        ${data.filters.map((filter) => `
          <div class="flex items-center space-x-2">
            <label class="text-sm font-medium text-zinc-500 dark:text-zinc-400">${filter.label}:</label>
            <select
              name="${filter.name}"
              class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-blue-600 dark:focus:ring-blue-500 focus:outline-none transition-colors"
              onchange="updateFilters()"
            >
              ${filter.options.map((option) => `
                <option value="${option.value}" ${option.selected ? "selected" : ""}>
                  ${option.label}
                </option>
              `).join("")}
            </select>
          </div>
        `).join("")}

        ${data.actions && data.actions.length > 0 ? `
          <div class="flex items-center space-x-2 ml-auto">
            ${data.actions.map((action) => `
              <button
                type="button"
                class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors"
                ${action.onclick ? `onclick="${action.onclick}"` : ""}
                ${action.hxGet ? `hx-get="${action.hxGet}"` : ""}
                ${action.hxTarget ? `hx-target="${action.hxTarget}"` : ""}
              >
                ${action.label}
              </button>
            `).join("")}
          </div>
        ` : ""}
      </form>

      <script>
        function updateFilters() {
          const form = document.getElementById('filter-form');
          const formData = new FormData(form);
          const params = new URLSearchParams(window.location.search);

          // Update params with form values
          for (const [key, value] of formData.entries()) {
            if (value) {
              params.set(key, value);
            } else {
              params.delete(key);
            }
          }

          // Reset to page 1 when filters change
          params.set('page', '1');

          // Update URL and reload
          window.location.href = window.location.pathname + '?' + params.toString();
        }
      </script>
    </div>
  `;
}

// src/templates/index.ts
chunkSHCYIZAN_cjs.init_admin_layout_catalyst_template();
chunkSHCYIZAN_cjs.init_logo_template();

// src/templates/pages/admin-forms-docs.template.ts
chunkSHCYIZAN_cjs.init_admin_layout_catalyst_template();
function renderFormsDocsPage(data) {
  const pageContent = `
    <style>
      /* Light theme matching examples page */
      .docs-container {
        display: flex;
        gap: 0;
        min-height: calc(100vh - 200px);
        background: #ffffff;
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      }
      
      .docs-sidebar {
        width: 280px;
        background: #f8f9fa;
        border-right: 1px solid #e0e0e0;
        padding: 1.5rem 0;
        overflow-y: auto;
      }
      
      .docs-sidebar h3 {
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #6b7280;
        padding: 0 1.5rem;
        margin-bottom: 0.75rem;
      }
      
      .docs-nav {
        list-style: none;
        padding: 0;
        margin: 0 0 2rem 0;
      }
      
      .docs-nav li {
        margin: 0;
      }
      
      .docs-nav a {
        display: block;
        padding: 0.75rem 1.5rem;
        color: #374151;
        text-decoration: none;
        font-size: 0.875rem;
        transition: all 0.2s;
        border-left: 3px solid transparent;
      }
      
      .docs-nav a:hover {
        background: #e9ecef;
        color: #1f2937;
      }
      
      .docs-nav a.active {
        background: #e3f2fd;
        color: #1976d2;
        border-left-color: #1976d2;
        font-weight: 500;
      }
      
      .docs-content {
        flex: 1;
        padding: 2rem;
        background: #ffffff;
        overflow-y: auto;
      }
      
      .doc-section {
        display: none;
      }
      
      .doc-section.active {
        display: block;
      }
      
      .doc-header {
        margin-bottom: 2rem;
        padding-bottom: 1rem;
        border-bottom: 2px solid #e0e0e0;
      }
      
      .doc-header h2 {
        font-size: 1.875rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 0.5rem;
      }
      
      .doc-header p {
        color: #6b7280;
        font-size: 1rem;
      }
      
      .field-example {
        background: #f8f9fa;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
      }
      
      .field-example h3 {
        font-size: 1.125rem;
        font-weight: 600;
        color: #1f2937;
        margin-bottom: 0.75rem;
      }
      
      .field-example p {
        color: #6b7280;
        font-size: 0.875rem;
        margin-bottom: 1rem;
      }
      
      .code-block {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 1rem;
        border-radius: 6px;
        overflow-x: auto;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 0.875rem;
        line-height: 1.6;
      }
      
      .info-box {
        background: #e3f2fd;
        border: 1px solid #90caf9;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1.5rem;
        color: #1565c0;
        font-size: 0.875rem;
      }
      
      .info-box strong {
        font-weight: 600;
      }
    </style>

    <div class="mb-6">
      <div class="flex items-center gap-3 mb-4">
        <a href="/admin/forms" class="inline-flex items-center text-sm text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white transition-colors">
          <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
          </svg>
          Back to Forms
        </a>
      </div>
      <h1 class="text-3xl font-bold text-zinc-950 dark:text-white">Forms Quick Reference</h1>
      <p class="mt-2 text-zinc-600 dark:text-zinc-400">Comprehensive guide to all Form.io field types and features</p>
    </div>

    <div class="docs-container">
      <!-- Sidebar Navigation -->
      <aside class="docs-sidebar">
        <h3>Quick Start</h3>
        <ul class="docs-nav">
          <li><a href="#overview" class="doc-link active">Overview</a></li>
          <li><a href="#getting-started" class="doc-link">Getting Started</a></li>
        </ul>
        
        <h3>Basic Fields</h3>
        <ul class="docs-nav">
          <li><a href="#textfield" class="doc-link">Text Field</a></li>
          <li><a href="#textarea" class="doc-link">Text Area</a></li>
          <li><a href="#number" class="doc-link">Number</a></li>
          <li><a href="#password" class="doc-link">Password</a></li>
          <li><a href="#email" class="doc-link">Email</a></li>
          <li><a href="#url" class="doc-link">URL</a></li>
          <li><a href="#phonenumber" class="doc-link">Phone Number</a></li>
        </ul>
        
        <h3>Date & Time</h3>
        <ul class="docs-nav">
          <li><a href="#datetime" class="doc-link">Date/Time</a></li>
          <li><a href="#day" class="doc-link">Day</a></li>
          <li><a href="#time" class="doc-link">Time</a></li>
        </ul>
        
        <h3>Selection Fields</h3>
        <ul class="docs-nav">
          <li><a href="#select" class="doc-link">Select Dropdown</a></li>
          <li><a href="#selectboxes" class="doc-link">Select Boxes</a></li>
          <li><a href="#radio" class="doc-link">Radio</a></li>
          <li><a href="#checkbox" class="doc-link">Checkbox</a></li>
        </ul>
        
        <h3>Advanced Fields</h3>
        <ul class="docs-nav">
          <li><a href="#currency" class="doc-link">Currency</a></li>
          <li><a href="#tags" class="doc-link">Tags</a></li>
          <li><a href="#survey" class="doc-link">Survey</a></li>
          <li><a href="#signature" class="doc-link">Signature</a></li>
          <li><a href="#file" class="doc-link">File Upload</a></li>
          <li><a href="#address" class="doc-link">Address</a></li>
          <li><a href="#turnstile" class="doc-link">\u{1F6E1}\uFE0F Turnstile</a></li>
        </ul>
        
        <h3>Layout Components</h3>
        <ul class="docs-nav">
          <li><a href="#panel" class="doc-link">Panel</a></li>
          <li><a href="#columns" class="doc-link">Columns</a></li>
          <li><a href="#tabs" class="doc-link">Tabs</a></li>
          <li><a href="#table" class="doc-link">Table</a></li>
          <li><a href="#fieldset" class="doc-link">Fieldset</a></li>
        </ul>
        
        <h3>Data Components</h3>
        <ul class="docs-nav">
          <li><a href="#datagrid" class="doc-link">Data Grid</a></li>
          <li><a href="#editgrid" class="doc-link">Edit Grid</a></li>
        </ul>
        
        <h3>Guides</h3>
        <ul class="docs-nav">
          <li><a href="#wizard" class="doc-link">Multi-Page Wizards</a></li>
          <li><a href="#embedding" class="doc-link">Embedding Forms</a></li>
          <li><a href="#validation" class="doc-link">Validation</a></li>
          <li><a href="#conditional" class="doc-link">Conditional Logic</a></li>
        </ul>
      </aside>

      <!-- Main Content Area -->
      <main class="docs-content">
        
        <!-- Overview Section -->
        <section id="overview" class="doc-section active">
          <div class="doc-header">
            <h2>\u{1F4DA} Overview</h2>
            <p>Complete reference for SonicJS Forms powered by Form.io</p>
          </div>
          
          <div class="info-box">
            <strong>\u{1F4A1} New to SonicJS Forms?</strong> Start with "Getting Started" in the sidebar, then explore the field types you need.
          </div>
          
          <h3 style="font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; color: #1f2937;">Key Features</h3>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
            <div style="padding: 1rem; background: #f0fdf4; border-radius: 8px;">
              <strong style="color: #16a34a;">\u2713 Visual Builder</strong>
              <p style="font-size: 0.875rem; color: #15803d; margin-top: 0.25rem;">Drag-and-drop interface</p>
            </div>
            <div style="padding: 1rem; background: #f0fdf4; border-radius: 8px;">
              <strong style="color: #16a34a;">\u2713 40+ Field Types</strong>
              <p style="font-size: 0.875rem; color: #15803d; margin-top: 0.25rem;">Text, date, file, signature, etc.</p>
            </div>
            <div style="padding: 1rem; background: #f0fdf4; border-radius: 8px;">
              <strong style="color: #16a34a;">\u2713 Multi-Page Wizards</strong>
              <p style="font-size: 0.875rem; color: #15803d; margin-top: 0.25rem;">Step-by-step forms</p>
            </div>
            <div style="padding: 1rem; background: #f0fdf4; border-radius: 8px;">
              <strong style="color: #16a34a;">\u2713 Headless API</strong>
              <p style="font-size: 0.875rem; color: #15803d; margin-top: 0.25rem;">JSON schema & REST API</p>
            </div>
            <div style="padding: 1rem; background: #f0fdf4; border-radius: 8px;">
              <strong style="color: #16a34a;">\u2713 File Uploads</strong>
              <p style="font-size: 0.875rem; color: #15803d; margin-top: 0.25rem;">Cloudflare R2 storage</p>
            </div>
            <div style="padding: 1rem; background: #f0fdf4; border-radius: 8px;">
              <strong style="color: #16a34a;">\u2713 100% Open Source</strong>
              <p style="font-size: 0.875rem; color: #15803d; margin-top: 0.25rem;">No vendor lock-in</p>
            </div>
          </div>
          
          <h3 style="font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; color: #1f2937;">Quick Links</h3>
          <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
            <a href="/admin/forms/examples" style="display: inline-flex; align-items: center; padding: 0.625rem 1.25rem; background: #3b82f6; color: white; border-radius: 6px; text-decoration: none; font-size: 0.875rem; font-weight: 500;">
              <svg style="width: 1rem; height: 1rem; margin-right: 0.5rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
              </svg>
              View Examples
            </a>
            <a href="/admin/forms/new" style="display: inline-flex; align-items: center; padding: 0.625rem 1.25rem; background: #10b981; color: white; border-radius: 6px; text-decoration: none; font-size: 0.875rem; font-weight: 500;">
              <svg style="width: 1rem; height: 1rem; margin-right: 0.5rem;" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/>
              </svg>
              Create New Form
            </a>
            <a href="/admin/forms" style="display: inline-flex; align-items: center; padding: 0.625rem 1.25rem; background: #6b7280; color: white; border-radius: 6px; text-decoration: none; font-size: 0.875rem; font-weight: 500;">
              <svg style="width: 1rem; height: 1rem; margin-right: 0.5rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/>
              </svg>
              View All Forms
            </a>
          </div>
        </section>

        <!-- Getting Started Section -->
        <section id="getting-started" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F680} Getting Started</h2>
            <p>Create your first form in 3 easy steps</p>
          </div>
          
          <div class="field-example">
            <h3>Step 1: Create a Form</h3>
            <p>Navigate to <code>/admin/forms</code> and click "Create Form"</p>
          </div>
          
          <div class="field-example">
            <h3>Step 2: Build Your Form</h3>
            <p>Drag and drop field types from the sidebar to build your form visually</p>
          </div>
          
          <div class="field-example">
            <h3>Step 3: Publish & Embed</h3>
            <p>Save your form and access it via:</p>
            <ul style="margin-left: 1.5rem; margin-top: 0.5rem; list-style-type: disc;">
              <li><code>/forms/your-form-name</code> - Public form page</li>
              <li><code>/forms/your-form-name/schema</code> - JSON schema API</li>
              <li><code>/api/forms/:id/submit</code> - Submission endpoint</li>
            </ul>
          </div>
        </section>

        <!-- Text Field -->
        <section id="textfield" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4DD} Text Field</h2>
            <p>Single-line text input for short text values</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Most common field type for names, titles, and short text</p>
            <pre class="code-block">{
  "type": "textfield",
  "key": "firstName",
  "label": "First Name",
  "placeholder": "Enter your first name",
  "validate": {
    "required": true,
    "minLength": 2,
    "maxLength": 50
  }
}</pre>
          </div>
          
          <div class="info-box">
            <strong>\u{1F4A1} Pro Tip:</strong> Use <code>inputMask</code> for formatted input like SSN or custom patterns.
          </div>
        </section>

        <!-- Text Area -->
        <section id="textarea" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4C4} Text Area</h2>
            <p>Multi-line text input for longer text content</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Perfect for comments, descriptions, and multi-line text</p>
            <pre class="code-block">{
  "type": "textarea",
  "key": "comments",
  "label": "Additional Comments",
  "placeholder": "Enter your comments here...",
  "rows": 5,
  "validate": {
    "required": false,
    "maxLength": 1000
  }
}</pre>
          </div>
        </section>

        <!-- Number Field -->
        <section id="number" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F522} Number</h2>
            <p>Numeric input with validation</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>For ages, quantities, scores, and any numeric value</p>
            <pre class="code-block">{
  "type": "number",
  "key": "age",
  "label": "Age",
  "placeholder": "18",
  "validate": {
    "required": true,
    "min": 18,
    "max": 120
  }
}</pre>
          </div>
        </section>

        <!-- Password Field -->
        <section id="password" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F512} Password</h2>
            <p>Masked text input for sensitive data</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Automatically masks input for security</p>
            <pre class="code-block">{
  "type": "password",
  "key": "password",
  "label": "Password",
  "placeholder": "Enter password",
  "validate": {
    "required": true,
    "minLength": 8,
    "pattern": "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$"
  }
}</pre>
          </div>
        </section>

        <!-- Email Field -->
        <section id="email" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4E7} Email</h2>
            <p>Email input with automatic validation</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Validates email format automatically</p>
            <pre class="code-block">{
  "type": "email",
  "key": "email",
  "label": "Email Address",
  "placeholder": "you@example.com",
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- URL Field -->
        <section id="url" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F310} URL</h2>
            <p>URL input with validation</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Validates URL format (http/https)</p>
            <pre class="code-block">{
  "type": "url",
  "key": "website",
  "label": "Website",
  "placeholder": "https://example.com",
  "validate": {
    "required": false
  }
}</pre>
          </div>
        </section>

        <!-- Phone Number Field -->
        <section id="phonenumber" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4DE} Phone Number</h2>
            <p>Phone number input with formatting</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Automatically formats phone numbers</p>
            <pre class="code-block">{
  "type": "phoneNumber",
  "key": "phone",
  "label": "Phone Number",
  "placeholder": "(555) 555-5555",
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- DateTime Field -->
        <section id="datetime" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4C5} Date/Time</h2>
            <p>Date and time picker</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Interactive date/time picker with format control</p>
            <pre class="code-block">{
  "type": "datetime",
  "key": "appointmentDateTime",
  "label": "Appointment Date & Time",
  "format": "yyyy-MM-dd hh:mm a",
  "enableTime": true,
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- Day Field -->
        <section id="day" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4C6} Day</h2>
            <p>Day/Month/Year selector</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Separate dropdowns for day, month, and year</p>
            <pre class="code-block">{
  "type": "day",
  "key": "birthDate",
  "label": "Date of Birth",
  "fields": {
    "day": { "placeholder": "Day" },
    "month": { "placeholder": "Month" },
    "year": { "placeholder": "Year" }
  },
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- Time Field -->
        <section id="time" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F550} Time</h2>
            <p>Time picker (hours and minutes)</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Select time in HH:MM format</p>
            <pre class="code-block">{
  "type": "time",
  "key": "preferredTime",
  "label": "Preferred Contact Time",
  "validate": {
    "required": false
  }
}</pre>
          </div>
        </section>

        <!-- Select Field -->
        <section id="select" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F53D} Select Dropdown</h2>
            <p>Single selection dropdown</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Choose one option from a list</p>
            <pre class="code-block">{
  "type": "select",
  "key": "country",
  "label": "Country",
  "placeholder": "Select your country",
  "data": {
    "values": [
      { "label": "United States", "value": "us" },
      { "label": "Canada", "value": "ca" },
      { "label": "United Kingdom", "value": "uk" },
      { "label": "Australia", "value": "au" }
    ]
  },
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- Select Boxes Field -->
        <section id="selectboxes" class="doc-section">
          <div class="doc-header">
            <h2>\u2611\uFE0F Select Boxes</h2>
            <p>Multiple checkbox selections</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Select multiple options with checkboxes</p>
            <pre class="code-block">{
  "type": "selectboxes",
  "key": "interests",
  "label": "Areas of Interest",
  "values": [
    { "label": "Sports", "value": "sports" },
    { "label": "Music", "value": "music" },
    { "label": "Technology", "value": "tech" },
    { "label": "Travel", "value": "travel" }
  ]
}</pre>
          </div>
        </section>

        <!-- Radio Field -->
        <section id="radio" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F518} Radio</h2>
            <p>Single selection with radio buttons</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Choose one option from radio buttons</p>
            <pre class="code-block">{
  "type": "radio",
  "key": "gender",
  "label": "Gender",
  "values": [
    { "label": "Male", "value": "male" },
    { "label": "Female", "value": "female" },
    { "label": "Non-binary", "value": "nonbinary" },
    { "label": "Prefer not to say", "value": "other" }
  ],
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- Checkbox Field -->
        <section id="checkbox" class="doc-section">
          <div class="doc-header">
            <h2>\u2705 Checkbox</h2>
            <p>Single checkbox for boolean values</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>For agreements, subscriptions, and yes/no options</p>
            <pre class="code-block">{
  "type": "checkbox",
  "key": "newsletter",
  "label": "Subscribe to newsletter",
  "validate": {
    "required": false
  }
}

// Required checkbox (terms agreement)
{
  "type": "checkbox",
  "key": "terms",
  "label": "I agree to the terms and conditions",
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- Currency Field -->
        <section id="currency" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4B0} Currency</h2>
            <p>Formatted currency input</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Automatically formats with currency symbol</p>
            <pre class="code-block">{
  "type": "currency",
  "key": "salary",
  "label": "Expected Salary",
  "currency": "USD",
  "placeholder": "$50,000",
  "validate": {
    "required": true,
    "min": 0
  }
}</pre>
          </div>
        </section>

        <!-- Tags Field -->
        <section id="tags" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F3F7}\uFE0F Tags</h2>
            <p>Multi-value tag input</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Type and press Enter to add tags</p>
            <pre class="code-block">{
  "type": "tags",
  "key": "skills",
  "label": "Skills",
  "placeholder": "Type and press Enter (e.g. JavaScript, Python)",
  "validate": {
    "required": false
  }
}</pre>
          </div>
        </section>

        <!-- Survey Field -->
        <section id="survey" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4CA} Survey</h2>
            <p>Matrix-style rating questions</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Multiple questions with rating scale</p>
            <pre class="code-block">{
  "type": "survey",
  "key": "satisfaction",
  "label": "Customer Satisfaction Survey",
  "questions": [
    { "label": "Product Quality", "value": "quality" },
    { "label": "Customer Service", "value": "service" },
    { "label": "Value for Money", "value": "value" }
  ],
  "values": [
    { "label": "Poor", "value": "1" },
    { "label": "Fair", "value": "2" },
    { "label": "Good", "value": "3" },
    { "label": "Excellent", "value": "4" }
  ]
}</pre>
          </div>
        </section>

        <!-- Signature Field -->
        <section id="signature" class="doc-section">
          <div class="doc-header">
            <h2>\u270D\uFE0F Signature</h2>
            <p>Digital signature pad</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Capture signatures with mouse or touch</p>
            <pre class="code-block">{
  "type": "signature",
  "key": "signature",
  "label": "Signature",
  "footer": "Sign above",
  "width": "100%",
  "height": "150px",
  "validate": {
    "required": true
  }
}</pre>
          </div>
        </section>

        <!-- File Upload Field -->
        <section id="file" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4C1} File Upload</h2>
            <p>File upload with storage options</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Upload files to Cloudflare R2 or base64 encode</p>
            <pre class="code-block">{
  "type": "file",
  "key": "resume",
  "label": "Upload Resume",
  "storage": "r2",
  "filePattern": ".pdf,.doc,.docx",
  "fileMaxSize": "5MB",
  "multiple": false,
  "validate": {
    "required": true
  }
}

// Multiple files
{
  "type": "file",
  "key": "attachments",
  "label": "Attachments",
  "storage": "base64",
  "multiple": true,
  "fileMaxSize": "10MB"
}</pre>
          </div>
          
          <div class="info-box">
            <strong>\u{1F4A1} Storage Options:</strong> Use <code>storage: "r2"</code> for Cloudflare R2 (recommended) or <code>storage: "base64"</code> to encode in submission data.
          </div>
        </section>

        <!-- Address Field -->
        <section id="address" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4CD} Address</h2>
            <p>Address autocomplete with Google Maps</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Google Maps API-powered address autocomplete</p>
            <pre class="code-block">{
  "type": "address",
  "key": "address",
  "label": "Address",
  "provider": "google",
  "map": {
    "key": "YOUR_GOOGLE_MAPS_API_KEY"
  },
  "validate": {
    "required": true
  }
}</pre>
          </div>
          
          <div class="info-box">
            <strong>\u26A0\uFE0F API Key Required:</strong> Enable Google Maps Places API and Maps JavaScript API in Google Cloud Console.
          </div>
        </section>

        <!-- Turnstile Component -->
        <section id="turnstile" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F6E1}\uFE0F Turnstile</h2>
            <p>CAPTCHA-free bot protection by Cloudflare</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Add invisible bot protection to your forms</p>
            <pre class="code-block">{
  "type": "turnstile",
  "key": "turnstile",
  "label": "Turnstile Verification",
  "theme": "auto",
  "size": "normal",
  "appearance": "always",
  "persistent": false,
  "protected": true
}</pre>
          </div>
          
          <div class="field-example">
            <h3>Configuration Options</h3>
            <pre class="code-block">{
  "type": "turnstile",
  "key": "turnstile",
  "label": "Security Check",
  "theme": "light",          // "light", "dark", "auto"
  "size": "compact",         // "normal", "compact"
  "appearance": "always",    // "always", "execute", "interaction-only"
  "action": "submit-form",   // Optional: action name for analytics
  "errorMessage": "Please complete the security verification"
}</pre>
          </div>
          
          <div class="info-box">
            <strong>\u{1F527} Setup Required:</strong> Enable the Turnstile plugin in Settings \u2192 Plugins and configure your site key and secret key from Cloudflare Dashboard.
          </div>
          
          <div class="info-box">
            <strong>\u{1F4A1} Usage Tips:</strong>
            <ul style="margin: 10px 0 0 20px; padding: 0;">
              <li><strong>Invisible Mode:</strong> Use <code>"appearance": "interaction-only"</code> for seamless UX</li>
              <li><strong>Dark Mode:</strong> Use <code>"theme": "auto"</code> to match user preferences</li>
              <li><strong>Compact Size:</strong> Use <code>"size": "compact"</code> for mobile forms</li>
              <li><strong>Backend Validation:</strong> Tokens are automatically validated server-side</li>
            </ul>
          </div>
        </section>

        <!-- Panel Component -->
        <section id="panel" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4E6} Panel</h2>
            <p>Group fields in collapsible panels</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Used for wizards and grouping related fields</p>
            <pre class="code-block">{
  "type": "panel",
  "key": "personalInfo",
  "title": "Personal Information",
  "collapsible": true,
  "collapsed": false,
  "components": [
    { "type": "textfield", "key": "firstName", "label": "First Name" },
    { "type": "textfield", "key": "lastName", "label": "Last Name" },
    { "type": "email", "key": "email", "label": "Email" }
  ]
}</pre>
          </div>
        </section>

        <!-- Columns Component -->
        <section id="columns" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4CA} Columns</h2>
            <p>Multi-column layout</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Create side-by-side fields (responsive)</p>
            <pre class="code-block">{
  "type": "columns",
  "columns": [
    {
      "components": [
        { "type": "textfield", "key": "firstName", "label": "First Name" }
      ],
      "width": 6
    },
    {
      "components": [
        { "type": "textfield", "key": "lastName", "label": "Last Name" }
      ],
      "width": 6
    }
  ]
}</pre>
          </div>
          
          <div class="info-box">
            <strong>\u{1F4A1} Width System:</strong> Width is based on 12-column grid. Use 6 for 50%, 4 for 33%, 3 for 25%, etc.
          </div>
        </section>

        <!-- Tabs Component -->
        <section id="tabs" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4D1} Tabs</h2>
            <p>Organize fields in tabs</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Create tabbed interface for complex forms</p>
            <pre class="code-block">{
  "type": "tabs",
  "components": [
    {
      "label": "Personal Info",
      "key": "tab1",
      "components": [...]
    },
    {
      "label": "Contact Info",
      "key": "tab2",
      "components": [...]
    }
  ]
}</pre>
          </div>
        </section>

        <!-- Table Component -->
        <section id="table" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4CB} Table</h2>
            <p>Table layout for forms</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Create table-based layouts</p>
            <pre class="code-block">{
  "type": "table",
  "numRows": 3,
  "numCols": 2,
  "rows": [
    [
      { "components": [{ "type": "textfield", "key": "cell1" }] },
      { "components": [{ "type": "textfield", "key": "cell2" }] }
    ]
  ]
}</pre>
          </div>
        </section>

        <!-- Fieldset Component -->
        <section id="fieldset" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F4E6} Fieldset</h2>
            <p>Group fields with border and legend</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>HTML fieldset with legend label</p>
            <pre class="code-block">{
  "type": "fieldset",
  "legend": "Contact Information",
  "components": [
    { "type": "email", "key": "email", "label": "Email" },
    { "type": "phoneNumber", "key": "phone", "label": "Phone" }
  ]
}</pre>
          </div>
        </section>

        <!-- Data Grid Component -->
        <section id="datagrid" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F5C3}\uFE0F Data Grid</h2>
            <p>Repeatable row data entry</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Add/remove rows of structured data</p>
            <pre class="code-block">{
  "type": "datagrid",
  "key": "items",
  "label": "Items",
  "addAnother": "Add Item",
  "components": [
    { "type": "textfield", "key": "name", "label": "Item Name" },
    { "type": "number", "key": "quantity", "label": "Quantity" },
    { "type": "currency", "key": "price", "label": "Price" }
  ]
}</pre>
          </div>
        </section>

        <!-- Edit Grid Component -->
        <section id="editgrid" class="doc-section">
          <div class="doc-header">
            <h2>\u270F\uFE0F Edit Grid</h2>
            <p>Editable table with modal editing</p>
          </div>
          
          <div class="field-example">
            <h3>Basic Usage</h3>
            <p>Similar to Data Grid but with modal editing</p>
            <pre class="code-block">{
  "type": "editgrid",
  "key": "contacts",
  "label": "Contacts",
  "components": [
    { "type": "textfield", "key": "name", "label": "Name" },
    { "type": "email", "key": "email", "label": "Email" },
    { "type": "phoneNumber", "key": "phone", "label": "Phone" }
  ]
}</pre>
          </div>
        </section>

        <!-- Multi-Page Wizards Guide -->
        <section id="wizard" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F9D9} Multi-Page Wizards</h2>
            <p>Create step-by-step forms with progress tracking</p>
          </div>
          
          <div class="info-box">
            <strong>\u{1F4A1} How It Works:</strong> Set <code>display: "wizard"</code> and use Panel components for each step. Form.io automatically adds navigation buttons.
          </div>
          
          <div class="field-example">
            <h3>Complete Wizard Example</h3>
            <pre class="code-block">{
  "display": "wizard",
  "components": [
    {
      "type": "panel",
      "key": "step1",
      "title": "Step 1: Personal Info",
      "components": [
        { "type": "textfield", "key": "firstName", "label": "First Name" },
        { "type": "textfield", "key": "lastName", "label": "Last Name" }
      ]
    },
    {
      "type": "panel",
      "key": "step2",
      "title": "Step 2: Contact Info",
      "components": [
        { "type": "email", "key": "email", "label": "Email" },
        { "type": "phoneNumber", "key": "phone", "label": "Phone" }
      ]
    },
    {
      "type": "panel",
      "key": "step3",
      "title": "Step 3: Review",
      "components": [
        { "type": "checkbox", "key": "terms", "label": "I agree" }
      ]
    }
  ]
}</pre>
          </div>
        </section>

        <!-- Embedding Forms Guide -->
        <section id="embedding" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F310} Embedding Forms</h2>
            <p>Multiple ways to embed forms on your website</p>
          </div>
          
          <div class="field-example">
            <h3>Method 1: JavaScript (Recommended)</h3>
            <p>Load form schema via API and render with Form.io</p>
            <pre class="code-block">&lt;div id="form"&gt;&lt;/div&gt;
&lt;script src="https://cdn.form.io/formiojs/formio.full.min.js"&gt;&lt;/script&gt;
&lt;script&gt;
  fetch('/forms/contact_form/schema')
    .then(r => r.json())
    .then(data => {
      Formio.createForm(
        document.getElementById('form'),
        data.schema
      ).then(form => {
        // Handle submission
        form.on('submitDone', (submission) => {
          console.log('Submitted:', submission);
        });
      });
    });
&lt;/script&gt;</pre>
          </div>
          
          <div class="field-example">
            <h3>Method 2: iFrame</h3>
            <p>Simple iframe embed (less flexible)</p>
            <pre class="code-block">&lt;iframe 
  src="/forms/contact_form"
  width="100%"
  height="600"
  frameborder="0"
&gt;&lt;/iframe&gt;</pre>
          </div>
          
          <div class="field-example">
            <h3>Method 3: React Component</h3>
            <p>Use Form.io React library</p>
            <pre class="code-block">import { Form } from '@formio/react';

function MyForm() {
  const [schema, setSchema] = useState(null);
  
  useEffect(() => {
    fetch('/forms/contact_form/schema')
      .then(r => r.json())
      .then(data => setSchema(data.schema));
  }, []);
  
  const handleSubmit = (submission) => {
    fetch('/api/forms/123/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(submission.data)
    });
  };
  
  return schema ? (
    &lt;Form form={schema} onSubmit={handleSubmit} /&gt;
  ) : null;
}</pre>
          </div>
        </section>

        <!-- Validation Guide -->
        <section id="validation" class="doc-section">
          <div class="doc-header">
            <h2>\u2705 Validation</h2>
            <p>Built-in validation rules</p>
          </div>
          
          <div class="field-example">
            <h3>Common Validation Rules</h3>
            <pre class="code-block">{
  "validate": {
    "required": true,           // Field must have value
    "minLength": 2,            // Minimum characters
    "maxLength": 50,           // Maximum characters
    "min": 0,                  // Minimum number value
    "max": 100,                // Maximum number value
    "pattern": "^[A-Za-z]+$",  // Regular expression
    "custom": "valid = (input === 'yes');" // Custom validation
  }
}</pre>
          </div>
          
          <div class="field-example">
            <h3>Custom Error Messages</h3>
            <pre class="code-block">{
  "validate": {
    "required": true,
    "customMessage": "Please provide your full name"
  }
}</pre>
          </div>
        </section>

        <!-- Conditional Logic Guide -->
        <section id="conditional" class="doc-section">
          <div class="doc-header">
            <h2>\u{1F500} Conditional Logic</h2>
            <p>Show/hide fields based on conditions</p>
          </div>
          
          <div class="field-example">
            <h3>Simple Conditional</h3>
            <p>Show field only when condition is met</p>
            <pre class="code-block">{
  "type": "textfield",
  "key": "companyName",
  "label": "Company Name",
  "conditional": {
    "show": true,
    "when": "hasCompany",
    "eq": true
  }
}</pre>
          </div>
          
          <div class="field-example">
            <h3>Advanced Conditional (JavaScript)</h3>
            <p>Complex conditions using custom JavaScript</p>
            <pre class="code-block">{
  "type": "textfield",
  "key": "discount",
  "label": "Discount Code",
  "customConditional": "show = (data.total > 100 && data.memberType === 'premium');"
}</pre>
          </div>
        </section>

      </main>
    </div>

    <script>
      // Navigation
      document.querySelectorAll('.doc-link').forEach(link => {
        link.addEventListener('click', function(e) {
          e.preventDefault();
          const targetId = this.getAttribute('href').substring(1);
          
          // Update active link
          document.querySelectorAll('.doc-link').forEach(l => l.classList.remove('active'));
          this.classList.add('active');
          
          // Update active section
          document.querySelectorAll('.doc-section').forEach(s => s.classList.remove('active'));
          document.getElementById(targetId).classList.add('active');
          
          // Scroll to top
          document.querySelector('.docs-content').scrollTop = 0;
        });
      });
    </script>
  `;
  const layoutData = {
    title: "Forms Quick Reference",
    pageTitle: "Forms Quick Reference",
    content: pageContent,
    user: data.user,
    version: data.version
  };
  return chunkSHCYIZAN_cjs.renderAdminLayoutCatalyst(layoutData);
}

// src/templates/pages/admin-forms-examples.template.ts
chunkSHCYIZAN_cjs.init_admin_layout_catalyst_template();
function renderFormsExamplesPage(data) {
  const pageContent = `
    <style>
      /* Light theme for examples page */
      .examples-container {
        display: flex;
        gap: 0;
        min-height: calc(100vh - 200px);
        background: #ffffff;
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      }
      
      .examples-sidebar {
        width: 280px;
        background: #f8f9fa;
        border-right: 1px solid #e0e0e0;
        padding: 1.5rem 0;
        overflow-y: auto;
      }
      
      .examples-sidebar h3 {
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #6b7280;
        padding: 0 1.5rem;
        margin-bottom: 0.75rem;
      }
      
      .examples-nav {
        list-style: none;
        padding: 0;
        margin: 0 0 2rem 0;
      }
      
      .examples-nav li {
        margin: 0;
      }
      
      .examples-nav a {
        display: block;
        padding: 0.75rem 1.5rem;
        color: #374151;
        text-decoration: none;
        font-size: 0.875rem;
        transition: all 0.2s;
        border-left: 3px solid transparent;
      }
      
      .examples-nav a:hover {
        background: #e9ecef;
        color: #1f2937;
      }
      
      .examples-nav a.active {
        background: #e3f2fd;
        color: #1976d2;
        border-left-color: #1976d2;
        font-weight: 500;
      }
      
      .examples-content {
        flex: 1;
        padding: 2rem;
        background: #ffffff;
        overflow-y: auto;
      }
      
      .example-section {
        display: none;
      }
      
      .example-section.active {
        display: block;
      }
      
      .example-header {
        margin-bottom: 2rem;
        padding-bottom: 1rem;
        border-bottom: 2px solid #e0e0e0;
      }
      
      .example-header h2 {
        font-size: 1.875rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 0.5rem;
      }
      
      .example-header p {
        color: #6b7280;
        font-size: 1rem;
      }
      
      .example-demo {
        background: #f8f9fa;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 2rem;
        margin-bottom: 2rem;
      }
      
      .example-code {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 1.5rem;
        border-radius: 8px;
        overflow-x: auto;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 0.875rem;
        line-height: 1.6;
      }
      
      .code-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1rem;
      }
      
      .code-header h3 {
        font-size: 0.875rem;
        font-weight: 600;
        color: #374151;
      }
      
      .copy-btn {
        padding: 0.375rem 0.75rem;
        font-size: 0.75rem;
        background: #f3f4f6;
        border: 1px solid #d1d5db;
        border-radius: 4px;
        cursor: pointer;
        transition: all 0.2s;
      }
      
      .copy-btn:hover {
        background: #e5e7eb;
      }
      
      /* Form.io overrides for lighter theme */
      .formio-component {
        margin-bottom: 1.25rem;
      }
      
      .formio-component label {
        color: #374151;
        font-weight: 500;
        margin-bottom: 0.5rem;
      }
      
      .formio-component input,
      .formio-component textarea,
      .formio-component select {
        border: 1px solid #d1d5db;
        border-radius: 6px;
        padding: 0.625rem 0.875rem;
      }
      
      .formio-component input:focus,
      .formio-component textarea:focus,
      .formio-component select:focus {
        outline: none;
        border-color: #3b82f6;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
      }
      
      .btn-primary {
        background: #3b82f6 !important;
        border-color: #3b82f6 !important;
        padding: 0.625rem 1.25rem !important;
        border-radius: 6px !important;
      }
      
      .btn-primary:hover {
        background: #2563eb !important;
        border-color: #2563eb !important;
      }
      
      .alert-success {
        background: #10b981 !important;
        color: white !important;
        border: none !important;
        border-radius: 6px !important;
      }
    </style>

    <div class="mb-6">
      <div class="flex items-center gap-3 mb-4">
        <a href="/admin/forms" class="inline-flex items-center text-sm text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white transition-colors">
          <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
          </svg>
          Back to Forms
        </a>
      </div>
      <h1 class="text-3xl font-bold text-zinc-950 dark:text-white">Form Examples</h1>
      <p class="mt-2 text-zinc-600 dark:text-zinc-400">Interactive examples showcasing Form.io capabilities</p>
    </div>

    <div class="examples-container">
      <!-- Sidebar Navigation -->
      <aside class="examples-sidebar">
        <h3>Getting Started</h3>
        <ul class="examples-nav">
          <li><a href="#kitchen-sink" class="example-link active">Kitchen Sink</a></li>
          <li><a href="#simple-contact" class="example-link">Simple Contact Form</a></li>
          <li><a href="#thank-you" class="example-link">Thank You Page</a></li>
        </ul>
        
        <h3>Advanced Forms</h3>
        <ul class="examples-nav">
          <li><a href="#wizard-form" class="example-link">Multi-Page Wizard</a></li>
          <li><a href="#conditional-logic" class="example-link">Conditional Logic</a></li>
          <li><a href="#file-upload" class="example-link">File Upload</a></li>
        </ul>
        
        <h3>Components</h3>
        <ul class="examples-nav">
          <li><a href="#address-maps" class="example-link">Address with Maps</a></li>
          <li><a href="#signature" class="example-link">Signature Pad</a></li>
          <li><a href="#data-grid" class="example-link">Data Grid</a></li>
          <li><a href="#turnstile-protection" class="example-link">\u{1F6E1}\uFE0F Turnstile Protection</a></li>
        </ul>
      </aside>

      <!-- Main Content Area -->
      <main class="examples-content">
        
        <!-- Kitchen Sink Example -->
        <section id="kitchen-sink" class="example-section active">
          <div class="example-header">
            <h2>\u{1F373} Kitchen Sink</h2>
            <p>A comprehensive form showcasing all major field types and configurations.</p>
          </div>
          
          <div class="example-demo">
            <div id="form-kitchen-sink"></div>
          </div>
          
          <div class="code-header">
            <h3>Form Schema (JSON)</h3>
            <button class="copy-btn" onclick="copyCode('kitchen-sink-code')">Copy Code</button>
          </div>
          <pre class="example-code" id="kitchen-sink-code">{
  "display": "form",
  "components": [
    // Basic Text Fields
    { "type": "textfield", "key": "firstName", "label": "First Name" },
    { "type": "email", "key": "email", "label": "Email" },
    { "type": "phoneNumber", "key": "phone", "label": "Phone" },
    { "type": "password", "key": "password", "label": "Password" },
    { "type": "url", "key": "website", "label": "Website" },
    { "type": "textarea", "key": "bio", "label": "Biography" },
    
    // Date & Time
    { "type": "datetime", "key": "appointmentDateTime", "label": "Appointment" },
    { "type": "day", "key": "birthDate", "label": "Birth Date" },
    { "type": "time", "key": "preferredTime", "label": "Time" },
    
    // Selections
    { "type": "select", "key": "country", "label": "Country", 
      "data": { "values": [{ "label": "USA", "value": "us" }] }},
    { "type": "selectboxes", "key": "interests", "label": "Interests",
      "values": [{ "label": "Sports", "value": "sports" }] },
    { "type": "radio", "key": "gender", "label": "Gender",
      "values": [{ "label": "Male", "value": "male" }] },
    { "type": "checkbox", "key": "newsletter", "label": "Newsletter" },
    
    // Advanced
    { "type": "currency", "key": "salary", "label": "Salary" },
    { "type": "tags", "key": "skills", "label": "Skills" },
    { "type": "survey", "key": "satisfaction", "label": "Satisfaction" },
    { "type": "signature", "key": "signature", "label": "Signature" },
    { "type": "file", "key": "resume", "label": "Resume", "storage": "base64" }
  ]
}</pre>
        </section>

        <!-- Simple Contact Form Example -->
        <section id="simple-contact" class="example-section">
          <div class="example-header">
            <h2>\u{1F4E7} Simple Contact Form</h2>
            <p>A minimal contact form with validation.</p>
          </div>
          
          <div class="example-demo">
            <div id="form-simple-contact"></div>
          </div>
          
          <div class="code-header">
            <h3>Form Schema (JSON)</h3>
            <button class="copy-btn" onclick="copyCode('contact-code')">Copy Code</button>
          </div>
          <pre class="example-code" id="contact-code">{
  "display": "form",
  "components": [
    {
      "type": "textfield",
      "key": "name",
      "label": "Full Name",
      "validate": { "required": true }
    },
    {
      "type": "email",
      "key": "email",
      "label": "Email Address",
      "validate": { "required": true }
    },
    {
      "type": "textarea",
      "key": "message",
      "label": "Message",
      "rows": 5,
      "validate": { "required": true }
    }
  ]
}</pre>
        </section>

        <!-- Thank You Page Example -->
        <section id="thank-you" class="example-section">
          <div class="example-header">
            <h2>\u{1F389} Thank You Page</h2>
            <p>Handle form submission and redirect to a thank you message.</p>
          </div>
          
          <div class="example-demo">
            <div id="form-thank-you"></div>
            <div id="thank-you-message" style="display: none; padding: 2rem; background: #10b981; color: white; border-radius: 8px; text-align: center;">
              <h3 style="font-size: 1.5rem; margin-bottom: 0.5rem;">\u2705 Thank You!</h3>
              <p>Your form has been submitted successfully.</p>
            </div>
          </div>
          
          <div class="code-header">
            <h3>Form Schema (JSON)</h3>
            <button class="copy-btn" onclick="copyCode('thankyou-schema-code')">Copy Code</button>
          </div>
          <pre class="example-code" id="thankyou-schema-code">{
  "display": "form",
  "components": [
    { "type": "textfield", "key": "firstName", "label": "First Name", 
      "validate": { "required": true }},
    { "type": "textfield", "key": "lastName", "label": "Last Name", 
      "validate": { "required": true }},
    { "type": "email", "key": "email", "label": "Email Address", 
      "validate": { "required": true }},
    { "type": "phoneNumber", "key": "phone", "label": "Phone Number" },
    { "type": "textarea", "key": "message", "label": "Message", 
      "validate": { "required": true }},
    { "type": "button", "action": "submit", "label": "Submit Form" }
  ]
}</pre>
          
          <div class="code-header">
            <h3>JavaScript Code</h3>
            <button class="copy-btn" onclick="copyCode('thankyou-code')">Copy Code</button>
          </div>
          <pre class="example-code" id="thankyou-code">Formio.createForm(document.getElementById('formio'), formSchema)
  .then(function(form) {
    // Handle successful submission
    form.on('submitDone', function(submission) {
      console.log('Form submitted:', submission);
      
      // Hide form and show thank you message
      form.element.style.display = 'none';
      document.getElementById('thank-you-message').style.display = 'block';
      
      // Or redirect to another page:
      // window.location = '/thank-you';
    });
  });</pre>
        </section>

        <!-- Wizard Form Example -->
        <section id="wizard-form" class="example-section">
          <div class="example-header">
            <h2>\u{1F9D9} Multi-Page Wizard</h2>
            <p>Step-by-step form with multiple pages and progress indicator.</p>
          </div>
          
          <div class="example-demo">
            <div id="form-wizard"></div>
          </div>
          
          <div class="code-header">
            <h3>Form Schema (JSON)</h3>
            <button class="copy-btn" onclick="copyCode('wizard-code')">Copy Code</button>
          </div>
          <pre class="example-code" id="wizard-code">{
  "display": "wizard",
  "components": [
    {
      "type": "panel",
      "key": "step1PersonalInfo",
      "title": "Step 1: Personal Information",
      "components": [
        { "type": "textfield", "key": "firstName", "label": "First Name" },
        { "type": "textfield", "key": "lastName", "label": "Last Name" },
        { "type": "datetime", "key": "birthDate", "label": "Date of Birth" },
        { "type": "select", "key": "gender", "label": "Gender" }
      ]
    },
    {
      "type": "panel",
      "key": "step2ContactInfo",
      "title": "Step 2: Contact Information",
      "components": [
        { "type": "email", "key": "email", "label": "Email" },
        { "type": "phoneNumber", "key": "phone", "label": "Phone" },
        { "type": "textfield", "key": "address", "label": "Address" },
        { "type": "select", "key": "country", "label": "Country" }
      ]
    },
    {
      "type": "panel",
      "key": "step3Preferences",
      "title": "Step 3: Preferences & Review",
      "components": [
        { "type": "selectboxes", "key": "interests", "label": "Interests" },
        { "type": "radio", "key": "contactMethod", "label": "Contact Method" },
        { "type": "textarea", "key": "comments", "label": "Comments" },
        { "type": "checkbox", "key": "terms", "label": "I agree to terms" }
      ]
    }
  ]
}</pre>
        </section>

        <!-- More examples... -->
        <section id="conditional-logic" class="example-section">
          <div class="example-header">
            <h2>\u{1F500} Conditional Logic</h2>
            <p>Show/hide fields based on user input.</p>
          </div>
          <div class="example-demo">
            <div id="form-conditional"></div>
          </div>
        </section>

        <section id="file-upload" class="example-section">
          <div class="example-header">
            <h2>\u{1F4C1} File Upload</h2>
            <p>Upload files to Cloudflare R2 storage.</p>
          </div>
          <div class="example-demo">
            <div id="form-file-upload"></div>
          </div>
        </section>

        <section id="address-maps" class="example-section">
          <div class="example-header">
            <h2>\u{1F4CD} Address with Maps</h2>
            <p>Google Maps autocomplete for address input.</p>
          </div>
          <div class="example-demo">
            <div id="form-address"></div>
          </div>
        </section>

        <section id="signature" class="example-section">
          <div class="example-header">
            <h2>\u270D\uFE0F Signature Pad</h2>
            <p>Capture digital signatures.</p>
          </div>
          <div class="example-demo">
            <div id="form-signature"></div>
          </div>
        </section>

        <section id="data-grid" class="example-section">
          <div class="example-header">
            <h2>\u{1F4CA} Data Grid</h2>
            <p>Repeatable data entry with add/remove rows.</p>
          </div>
          <div class="example-demo">
            <div id="form-data-grid"></div>
          </div>
        </section>

        <section id="turnstile-protection" class="example-section">
          <div class="example-header">
            <h2>\u{1F6E1}\uFE0F Turnstile Protection</h2>
            <p>CAPTCHA-free bot protection by Cloudflare - drag and drop from the Premium section in the form builder.</p>
          </div>
          
          <div class="info-box" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 10px 0; font-size: 18px;">\u2728 Key Features</h3>
            <ul style="margin: 0; padding-left: 20px;">
              <li><strong>No CAPTCHA puzzles</strong> - Seamless user experience</li>
              <li><strong>Invisible protection</strong> - Works in the background</li>
              <li><strong>Auto-validated</strong> - Server-side token verification</li>
              <li><strong>Privacy-first</strong> - Cloudflare's secure infrastructure</li>
            </ul>
          </div>
          
          <div class="example-demo">
            <div id="form-turnstile"></div>
          </div>
          
          <div class="info-box" style="margin-top: 20px;">
            <strong>\u{1F527} Setup Instructions:</strong>
            <ol style="margin: 10px 0 0 20px; padding: 0;">
              <li>Go to <strong>Settings \u2192 Plugins</strong> and enable Turnstile plugin</li>
              <li>Get free API keys from <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" style="color: #3b82f6;">Cloudflare Dashboard</a></li>
              <li>Configure site key and secret key in plugin settings</li>
              <li>Drag Turnstile component from <strong>Premium</strong> section in form builder</li>
            </ol>
          </div>
          
          <div class="info-box" style="margin-top: 15px; background: #fef3c7; border: 1px solid #fbbf24;">
            <strong>\u{1F4A1} Pro Tip:</strong> Use <code>"appearance": "interaction-only"</code> for invisible mode - the widget only appears when suspicious activity is detected!
          </div>
        </section>

      </main>
    </div>

    <!-- Load Form.io -->
    <script src="https://cdn.form.io/formiojs/formio.full.min.js"></script>
    
    <!-- Register Turnstile Component -->
    <script>
      // Register custom Turnstile component (same as public forms)
      (function() {
        // Will register when Form.io loads
        function registerTurnstile() {
          if (!window.Formio || !window.Formio.Components) {
            return false;
          }

          const FieldComponent = Formio.Components.components.field;

          class TurnstileComponent extends FieldComponent {
            static schema(...extend) {
              return FieldComponent.schema({
                type: 'turnstile',
                label: 'Turnstile Verification',
                key: 'turnstile',
                input: true,
                persistent: false,
                protected: true
              }, ...extend);
            }

            render() {
              return super.render(\`
                <div ref="turnstileContainer" class="formio-component-turnstile">
                  <div ref="turnstileWidget" style="margin: 15px 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px; text-align: center; color: white;">
                    <div style="font-size: 32px; margin-bottom: 10px;">\u{1F6E1}\uFE0F</div>
                    <div style="font-weight: 600; font-size: 16px; margin-bottom: 5px;">Turnstile Verification</div>
                    <div style="font-size: 13px; opacity: 0.9;">CAPTCHA-free bot protection by Cloudflare</div>
                    <div style="font-size: 12px; margin-top: 10px; opacity: 0.8;">Enable Turnstile plugin in Settings \u2192 Plugins to activate</div>
                  </div>
                </div>
              \`);
            }

            attach(element) {
              this.loadRefs(element, { turnstileContainer: 'single', turnstileWidget: 'single' });
              return super.attach(element);
            }
          }

          Formio.Components.addComponent('turnstile', TurnstileComponent);
          console.log('\u2705 Turnstile component registered on examples page');
          return true;
        }
        
        // Try to register immediately
        if (!registerTurnstile()) {
          // If Form.io not loaded yet, try again after a delay
          setTimeout(registerTurnstile, 100);
        }
      })();
    </script>
    
    <script>
      // Debug: Check if elements exist
      console.log('Script loaded');
      
      // Navigation function
      function setupNavigation() {
        console.log('Setting up navigation...');
        const links = document.querySelectorAll('.example-link');
        console.log('Found', links.length, 'navigation links');
        
        // Navigation
        links.forEach(link => {
          link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            console.log('Navigating to:', targetId);
            
            // Update active link
            document.querySelectorAll('.example-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            // Update active section
            document.querySelectorAll('.example-section').forEach(s => s.classList.remove('active'));
            const targetSection = document.getElementById(targetId);
            if (targetSection) {
              targetSection.classList.add('active');
              console.log('Activated section:', targetId);
            } else {
              console.error('Section not found:', targetId);
            }
            
            // Scroll to top
            const content = document.querySelector('.examples-content');
            if (content) {
              content.scrollTop = 0;
            }
            
            // Update URL hash
            window.location.hash = targetId;
          });
        });
        
        // Handle initial hash on page load
        function handleHash() {
          const hash = window.location.hash.substring(1);
          console.log('Handling hash:', hash);
          if (hash) {
            const link = document.querySelector('.example-link[href="#' + hash + '"]');
            if (link) {
              link.click();
            }
          }
        }
        
        // Call on load and hash change
        handleHash();
        window.addEventListener('hashchange', handleHash);
      }

      // Copy code function
      window.copyCode = function(elementId) {
        const code = document.getElementById(elementId).textContent;
        navigator.clipboard.writeText(code).then(() => {
          const btn = event.target;
          const originalText = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(() => btn.textContent = originalText, 2000);
        });
      };

      // Initialize forms
      function initForms() {
        const kitchenSinkSchema = {
          display: 'form',
          components: [
            { 
              type: 'htmlelement', 
              tag: 'h3', 
              content: 'Basic Fields',
              className: 'mb-3 text-lg font-semibold'
            },
            { type: 'textfield', key: 'firstName', label: 'First Name', placeholder: 'Enter your first name', validate: { required: true } },
            { type: 'textfield', key: 'lastName', label: 'Last Name', placeholder: 'Enter your last name', validate: { required: true } },
            { type: 'email', key: 'email', label: 'Email Address', placeholder: 'you@example.com', validate: { required: true } },
            { type: 'phoneNumber', key: 'phone', label: 'Phone Number', placeholder: '(555) 555-5555' },
            { type: 'number', key: 'age', label: 'Age', placeholder: '18', validate: { min: 18, max: 120 } },
            { type: 'password', key: 'password', label: 'Password', placeholder: 'Enter password', validate: { required: true } },
            { type: 'url', key: 'website', label: 'Website', placeholder: 'https://example.com' },
            { type: 'textarea', key: 'bio', label: 'Biography', rows: 4, placeholder: 'Tell us about yourself' },
            
            { 
              type: 'htmlelement', 
              tag: 'h3', 
              content: 'Date & Time Fields',
              className: 'mt-4 mb-3 text-lg font-semibold'
            },
            { type: 'datetime', key: 'appointmentDateTime', label: 'Appointment Date & Time', format: 'yyyy-MM-dd hh:mm a', enableTime: true },
            { type: 'day', key: 'birthDate', label: 'Birth Date (Day/Month/Year)' },
            { type: 'time', key: 'preferredTime', label: 'Preferred Contact Time' },
            
            { 
              type: 'htmlelement', 
              tag: 'h3', 
              content: 'Selection Fields',
              className: 'mt-4 mb-3 text-lg font-semibold'
            },
            { 
              type: 'select', 
              key: 'country', 
              label: 'Country', 
              placeholder: 'Select your country',
              data: { 
                values: [
                  { label: 'United States', value: 'us' },
                  { label: 'Canada', value: 'ca' },
                  { label: 'United Kingdom', value: 'uk' },
                  { label: 'Australia', value: 'au' },
                  { label: 'Germany', value: 'de' },
                  { label: 'France', value: 'fr' }
                ] 
              }
            },
            { 
              type: 'selectboxes', 
              key: 'interests', 
              label: 'Interests (Multiple Selection)', 
              values: [
                { label: 'Sports', value: 'sports' },
                { label: 'Music', value: 'music' },
                { label: 'Technology', value: 'tech' },
                { label: 'Travel', value: 'travel' },
                { label: 'Reading', value: 'reading' }
              ]
            },
            { 
              type: 'radio', 
              key: 'gender', 
              label: 'Gender', 
              values: [
                { label: 'Male', value: 'male' },
                { label: 'Female', value: 'female' },
                { label: 'Non-binary', value: 'nonbinary' },
                { label: 'Prefer not to say', value: 'prefer_not_to_say' }
              ]
            },
            { type: 'checkbox', key: 'newsletter', label: 'Subscribe to newsletter' },
            { type: 'checkbox', key: 'terms', label: 'I agree to the terms and conditions', validate: { required: true } },
            
            { 
              type: 'htmlelement', 
              tag: 'h3', 
              content: 'Advanced Fields',
              className: 'mt-4 mb-3 text-lg font-semibold'
            },
            { 
              type: 'currency', 
              key: 'salary', 
              label: 'Expected Salary', 
              currency: 'USD',
              placeholder: '$50,000'
            },
            { 
              type: 'tags', 
              key: 'skills', 
              label: 'Skills (Type and press Enter)', 
              placeholder: 'e.g. JavaScript, Python, React'
            },
            { 
              type: 'survey', 
              key: 'satisfaction', 
              label: 'Satisfaction Survey',
              questions: [
                { label: 'Product Quality', value: 'quality' },
                { label: 'Customer Service', value: 'service' },
                { label: 'Value for Money', value: 'value' }
              ],
              values: [
                { label: 'Poor', value: '1' },
                { label: 'Fair', value: '2' },
                { label: 'Good', value: '3' },
                { label: 'Excellent', value: '4' }
              ]
            },
            { 
              type: 'signature', 
              key: 'signature', 
              label: 'Signature', 
              footer: 'Sign above',
              width: '100%',
              height: '150px'
            },
            { 
              type: 'file', 
              key: 'resume', 
              label: 'Upload Resume (PDF, DOC)', 
              storage: 'base64',
              filePattern: '.pdf,.doc,.docx',
              fileMaxSize: '5MB'
            },
            
            { type: 'button', action: 'submit', label: 'Submit Kitchen Sink Form', theme: 'primary', className: 'mt-4' }
          ]
        };
        Formio.createForm(document.getElementById('form-kitchen-sink'), kitchenSinkSchema);

        // Simple Contact
        const contactSchema = {
          display: 'form',
          components: [
            { type: 'textfield', key: 'name', label: 'Full Name', validate: { required: true } },
            { type: 'email', key: 'email', label: 'Email Address', validate: { required: true } },
            { type: 'textarea', key: 'message', label: 'Message', rows: 5, validate: { required: true } },
            { type: 'button', action: 'submit', label: 'Send Message', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-simple-contact'), contactSchema);

        // Thank You Page - Match Form.io's official example
        const thankYouSchema = {
          display: 'form',
          components: [
            { 
              type: 'htmlelement', 
              tag: 'p', 
              content: 'Fill out this form and watch it redirect to a thank you page after submission.',
              className: 'mb-4 text-gray-600'
            },
            { type: 'textfield', key: 'firstName', label: 'First Name', placeholder: 'Enter your first name', validate: { required: true } },
            { type: 'textfield', key: 'lastName', label: 'Last Name', placeholder: 'Enter your last name', validate: { required: true } },
            { type: 'email', key: 'email', label: 'Email Address', placeholder: 'you@example.com', validate: { required: true } },
            { type: 'phoneNumber', key: 'phone', label: 'Phone Number', placeholder: '(555) 555-5555' },
            { type: 'textarea', key: 'message', label: 'Message', rows: 4, placeholder: 'Your message here...', validate: { required: true } },
            { type: 'button', action: 'submit', label: 'Submit Form', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-thank-you'), thankYouSchema)
          .then(function(form) {
            form.on('submitDone', function(submission) {
              console.log('Form submitted:', submission);
              form.element.style.display = 'none';
              const thankYouMsg = document.getElementById('thank-you-message');
              thankYouMsg.style.display = 'block';
              // In a real application, you would redirect:
              // window.location = '/thank-you-page';
            });
          });

        // Wizard - Proper 3-step multi-page wizard
        const wizardSchema = {
          display: 'wizard',
          components: [
            {
              type: 'panel',
              key: 'step1PersonalInfo',
              title: 'Step 1: Personal Information',
              components: [
                { 
                  type: 'htmlelement', 
                  tag: 'p', 
                  content: 'Please provide your personal information.',
                  className: 'mb-3 text-gray-600'
                },
                { type: 'textfield', key: 'firstName', label: 'First Name', placeholder: 'John', validate: { required: true } },
                { type: 'textfield', key: 'lastName', label: 'Last Name', placeholder: 'Doe', validate: { required: true } },
                { type: 'datetime', key: 'birthDate', label: 'Date of Birth', format: 'yyyy-MM-dd', validate: { required: true } },
                { 
                  type: 'select', 
                  key: 'gender', 
                  label: 'Gender',
                  data: { 
                    values: [
                      { label: 'Male', value: 'male' },
                      { label: 'Female', value: 'female' },
                      { label: 'Non-binary', value: 'nonbinary' },
                      { label: 'Prefer not to say', value: 'other' }
                    ]
                  }
                }
              ]
            },
            {
              type: 'panel',
              key: 'step2ContactInfo',
              title: 'Step 2: Contact Information',
              components: [
                { 
                  type: 'htmlelement', 
                  tag: 'p', 
                  content: 'How can we reach you?',
                  className: 'mb-3 text-gray-600'
                },
                { type: 'email', key: 'email', label: 'Email Address', placeholder: 'john.doe@example.com', validate: { required: true } },
                { type: 'phoneNumber', key: 'phone', label: 'Phone Number', placeholder: '(555) 555-5555', validate: { required: true } },
                { type: 'textfield', key: 'address', label: 'Street Address', placeholder: '123 Main St' },
                { type: 'textfield', key: 'city', label: 'City', placeholder: 'New York' },
                { 
                  type: 'select', 
                  key: 'country', 
                  label: 'Country',
                  data: { 
                    values: [
                      { label: 'United States', value: 'us' },
                      { label: 'Canada', value: 'ca' },
                      { label: 'United Kingdom', value: 'uk' },
                      { label: 'Australia', value: 'au' }
                    ]
                  },
                  validate: { required: true }
                }
              ]
            },
            {
              type: 'panel',
              key: 'step3Preferences',
              title: 'Step 3: Preferences & Review',
              components: [
                { 
                  type: 'htmlelement', 
                  tag: 'p', 
                  content: 'Almost done! Tell us your preferences.',
                  className: 'mb-3 text-gray-600'
                },
                { 
                  type: 'selectboxes', 
                  key: 'interests', 
                  label: 'Areas of Interest', 
                  values: [
                    { label: 'Product Updates', value: 'products' },
                    { label: 'Newsletter', value: 'newsletter' },
                    { label: 'Special Offers', value: 'offers' },
                    { label: 'Events & Webinars', value: 'events' }
                  ]
                },
                { 
                  type: 'radio', 
                  key: 'contactMethod', 
                  label: 'Preferred Contact Method',
                  values: [
                    { label: 'Email', value: 'email' },
                    { label: 'Phone', value: 'phone' },
                    { label: 'SMS', value: 'sms' }
                  ],
                  validate: { required: true }
                },
                { type: 'textarea', key: 'comments', label: 'Additional Comments', rows: 3, placeholder: 'Any other information you would like to share...' },
                { type: 'checkbox', key: 'terms', label: 'I agree to the terms and conditions', validate: { required: true } }
              ]
            }
          ]
        };
        Formio.createForm(document.getElementById('form-wizard'), wizardSchema);

        // Conditional Logic
        const conditionalSchema = {
          display: 'form',
          components: [
            { type: 'checkbox', key: 'hasCompany', label: 'I am registering on behalf of a company' },
            { type: 'textfield', key: 'companyName', label: 'Company Name', 
              conditional: { show: true, when: 'hasCompany', eq: true }
            },
            { type: 'button', action: 'submit', label: 'Submit', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-conditional'), conditionalSchema);

        // File Upload - Proper example with actual file field
        const fileSchema = {
          display: 'form',
          components: [
            { 
              type: 'htmlelement', 
              tag: 'p', 
              content: 'Upload files to Cloudflare R2 storage (or base64 encoding for demo).',
              className: 'mb-4 text-gray-600'
            },
            { type: 'textfield', key: 'name', label: 'Your Name', placeholder: 'John Doe', validate: { required: true } },
            { type: 'email', key: 'email', label: 'Email Address', placeholder: 'john@example.com', validate: { required: true } },
            { 
              type: 'file', 
              key: 'resume', 
              label: 'Upload Resume (PDF, DOC, DOCX)', 
              storage: 'base64',
              filePattern: '.pdf,.doc,.docx',
              fileMaxSize: '5MB',
              validate: { required: true }
            },
            { 
              type: 'file', 
              key: 'portfolio', 
              label: 'Portfolio/Work Samples (Optional)', 
              storage: 'base64',
              filePattern: '.pdf,.zip,.jpg,.png',
              fileMaxSize: '10MB',
              multiple: false
            },
            { 
              type: 'file', 
              key: 'attachments', 
              label: 'Additional Attachments (Multiple files allowed)', 
              storage: 'base64',
              multiple: true,
              fileMaxSize: '5MB'
            },
            { type: 'textarea', key: 'coverLetter', label: 'Cover Letter', rows: 5, placeholder: 'Tell us why you are a great fit...' },
            { type: 'button', action: 'submit', label: 'Upload & Submit', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-file-upload'), fileSchema);

        // Address (without API key for demo)
        const addressSchema = {
          display: 'form',
          components: [
            { type: 'textfield', key: 'street', label: 'Street Address' },
            { type: 'textfield', key: 'city', label: 'City' },
            { type: 'textfield', key: 'state', label: 'State' },
            { type: 'textfield', key: 'zip', label: 'ZIP Code' },
            { type: 'button', action: 'submit', label: 'Submit', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-address'), addressSchema);

        // Signature
        const signatureSchema = {
          display: 'form',
          components: [
            { type: 'textfield', key: 'name', label: 'Your Name' },
            { type: 'signature', key: 'signature', label: 'Sign Here', width: '100%', height: '150px' },
            { type: 'button', action: 'submit', label: 'Submit', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-signature'), signatureSchema);

        // Data Grid
        const dataGridSchema = {
          display: 'form',
          components: [
            { 
              type: 'datagrid', 
              key: 'items', 
              label: 'Items',
              components: [
                { type: 'textfield', key: 'item', label: 'Item' },
                { type: 'number', key: 'quantity', label: 'Quantity' }
              ]
            },
            { type: 'button', action: 'submit', label: 'Submit', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-data-grid'), dataGridSchema);
        
        // Turnstile Protection Form
        const turnstileSchema = {
          components: [
            { 
              type: 'textfield', 
              key: 'fullName', 
              label: 'Full Name',
              placeholder: 'Enter your full name',
              validate: { required: true }
            },
            { 
              type: 'email', 
              key: 'email', 
              label: 'Email Address',
              placeholder: 'you@example.com',
              validate: { required: true }
            },
            { 
              type: 'textarea', 
              key: 'message', 
              label: 'Message',
              placeholder: 'Tell us what you are thinking...',
              rows: 4,
              validate: { required: true }
            },
            {
              type: 'turnstile',
              key: 'turnstile',
              label: 'Security Verification',
              theme: 'auto',
              size: 'normal',
              appearance: 'always',
              persistent: false,
              protected: true
            },
            { 
              type: 'button', 
              action: 'submit', 
              label: 'Send Secure Message', 
              theme: 'primary',
              block: true
            }
          ]
        };
        Formio.createForm(document.getElementById('form-turnstile'), turnstileSchema);
      }

      // Wait for Form.io to load
      if (typeof Formio !== 'undefined') {
        initForms();
        setupNavigation();
      } else {
        setTimeout(function checkFormio() {
          if (typeof Formio !== 'undefined') {
            initForms();
            setupNavigation();
          } else {
            setTimeout(checkFormio, 100);
          }
        }, 100);
      }
    </script>
  `;
  const layoutData = {
    title: "Forms Examples",
    pageTitle: "Forms Examples",
    content: pageContent,
    user: data.user,
    version: data.version
  };
  return chunkSHCYIZAN_cjs.renderAdminLayoutCatalyst(layoutData);
}

exports.renderFilterBar = renderFilterBar;
exports.renderFormsDocsPage = renderFormsDocsPage;
exports.renderFormsExamplesPage = renderFormsExamplesPage;
//# sourceMappingURL=chunk-S6K2H2TS.cjs.map
//# sourceMappingURL=chunk-S6K2H2TS.cjs.map