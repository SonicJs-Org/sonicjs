import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'

export interface FormsExamplesPageData {
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

export function renderFormsExamplesPage(data: FormsExamplesPageData): string {
  const pageContent = `
    <link rel="stylesheet" href="https://cdn.form.io/formiojs/formio.full.min.css">
    <style>
      /* ── Bento Grid ── */
      .bento-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1.25rem;
        padding: 0.5rem 0;
      }
      @media (max-width: 1024px) {
        .bento-grid { grid-template-columns: repeat(2, 1fr); }
      }
      @media (max-width: 640px) {
        .bento-grid { grid-template-columns: 1fr; }
        .bento-card.featured { grid-column: span 1; }
      }
      .bento-card {
        position: relative;
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 1.5rem 1.5rem 1.25rem;
        cursor: pointer;
        transition: transform 0.2s, box-shadow 0.2s;
        overflow: hidden;
      }
      .bento-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 4px;
        background: var(--accent);
        transition: height 0.2s;
      }
      .bento-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.1);
      }
      .bento-card:hover::before { height: 6px; }
      .bento-card.featured {
        grid-column: span 2;
      }
      .bento-card .card-badge {
        display: inline-block;
        font-size: 0.6875rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        padding: 0.2rem 0.55rem;
        border-radius: 4px;
        margin-bottom: 0.75rem;
        background: var(--badge-bg);
        color: var(--badge-text);
      }
      .bento-card .card-icon {
        font-size: 1.75rem;
        margin-bottom: 0.5rem;
      }
      .bento-card .card-title {
        font-size: 1.125rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 0.35rem;
      }
      .bento-card .card-desc {
        font-size: 0.8125rem;
        color: #6b7280;
        line-height: 1.45;
      }

      /* ── Detail View ── */
      .examples-detail {
        background: #ffffff;
        border-radius: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        overflow: hidden;
      }
      .detail-inner {
        padding: 2rem;
      }
      .back-link {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        font-size: 0.875rem;
        font-weight: 500;
        color: #3b82f6;
        text-decoration: none;
        margin-bottom: 1.5rem;
        cursor: pointer;
        transition: color 0.15s;
      }
      .back-link:hover { color: #2563eb; }

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

      /* ── Code Accordion ── */
      .code-toggle-btn {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 0.875rem;
        font-size: 0.8125rem;
        font-weight: 500;
        color: #374151;
        background: #f3f4f6;
        border: 1px solid #d1d5db;
        border-radius: 6px;
        cursor: pointer;
        transition: background 0.15s;
      }
      .code-toggle-btn:hover { background: #e5e7eb; }
      .code-toggle-btn .chevron {
        display: inline-block;
        transition: transform 0.2s;
        font-size: 0.75rem;
      }
      .code-toggle-btn.open .chevron { transform: rotate(90deg); }
      .code-accordion {
        margin-bottom: 2rem;
      }
      .code-accordion-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 0.5rem;
      }
      .code-accordion-body {
        display: none;
        margin-top: 0.75rem;
      }
      .code-accordion-body.open { display: block; }

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
      .copy-btn {
        padding: 0.375rem 0.75rem;
        font-size: 0.75rem;
        background: #f3f4f6;
        border: 1px solid #d1d5db;
        border-radius: 4px;
        cursor: pointer;
        transition: all 0.2s;
      }
      .copy-btn:hover { background: #e5e7eb; }

      /* ── Wizard Step Navigation (Bootstrap pagination restored) ── */
      .example-demo .pagination {
        display: flex !important;
        flex-wrap: wrap !important;
        padding-left: 0 !important;
        list-style: none !important;
        border-radius: 0.375rem !important;
        margin-bottom: 1.5rem !important;
        gap: 0 !important;
      }
      .example-demo .page-item {
        margin: 0 !important;
      }
      .example-demo .page-link {
        position: relative !important;
        display: block !important;
        padding: 0.5rem 1rem !important;
        margin-left: -1px !important;
        line-height: 1.25 !important;
        color: #3b82f6 !important;
        background-color: #ffffff !important;
        border: 1px solid #d1d5db !important;
        cursor: pointer !important;
        font-size: 0.875rem !important;
        font-weight: 500 !important;
        text-decoration: none !important;
        transition: all 0.15s ease-in-out !important;
      }
      .example-demo .page-link:hover {
        color: #2563eb !important;
        background-color: #eff6ff !important;
        border-color: #93c5fd !important;
      }
      .example-demo .page-item.active .page-link {
        color: #ffffff !important;
        background-color: #3b82f6 !important;
        border-color: #3b82f6 !important;
      }
      .example-demo .page-item:first-child .page-link {
        border-top-left-radius: 0.375rem !important;
        border-bottom-left-radius: 0.375rem !important;
      }
      .example-demo .page-item:last-child .page-link {
        border-top-right-radius: 0.375rem !important;
        border-bottom-right-radius: 0.375rem !important;
      }
      /* Wizard bottom nav buttons container */
      .example-demo .formio-wizard-nav-container {
        display: flex !important;
        gap: 0.5rem !important;
        margin-top: 1.5rem !important;
        padding-top: 1rem !important;
        border-top: 1px solid #e5e7eb !important;
      }

      /* ── Bootstrap Grid Restoration (for Form.io columns) ── */
      .example-demo .row {
        display: flex !important;
        flex-wrap: wrap !important;
        margin-right: -0.75rem !important;
        margin-left: -0.75rem !important;
      }
      .example-demo .col,
      .example-demo [class*="col-"] {
        position: relative !important;
        width: 100% !important;
        padding-right: 0.75rem !important;
        padding-left: 0.75rem !important;
      }
      .example-demo .col-xs-6, .example-demo .col-sm-6, .example-demo .col-md-6 {
        flex: 0 0 50% !important;
        max-width: 50% !important;
      }
      .example-demo .col-xs-3, .example-demo .col-sm-3, .example-demo .col-md-3 {
        flex: 0 0 25% !important;
        max-width: 25% !important;
      }
      .example-demo .col-xs-4, .example-demo .col-sm-4, .example-demo .col-md-4 {
        flex: 0 0 33.333333% !important;
        max-width: 33.333333% !important;
      }
      .example-demo .col-xs-8, .example-demo .col-sm-8, .example-demo .col-md-8 {
        flex: 0 0 66.666667% !important;
        max-width: 66.666667% !important;
      }
      .example-demo .col-xs-9, .example-demo .col-sm-9, .example-demo .col-md-9 {
        flex: 0 0 75% !important;
        max-width: 75% !important;
      }
      .example-demo .col-xs-12, .example-demo .col-sm-12, .example-demo .col-md-12 {
        flex: 0 0 100% !important;
        max-width: 100% !important;
      }
      @media (max-width: 640px) {
        .example-demo [class*="col-"] {
          flex: 0 0 100% !important;
          max-width: 100% !important;
        }
      }

      /* ── Form.io overrides (matching builder page patterns) ── */
      .example-demo .formio-form {
        background: #ffffff !important;
      }
      .example-demo .form-group {
        margin-bottom: 1.5rem;
      }
      .example-demo .formio-component {
        margin-bottom: 1.25rem;
      }
      .example-demo label {
        display: block !important;
        margin-bottom: 0.5rem !important;
        font-weight: 500 !important;
        color: #374151 !important;
        font-size: 0.875rem !important;
      }
      .example-demo input[type="text"],
      .example-demo input[type="number"],
      .example-demo input[type="email"],
      .example-demo input[type="tel"],
      .example-demo input[type="password"],
      .example-demo input[type="url"],
      .example-demo select,
      .example-demo textarea {
        display: block !important;
        width: 100% !important;
        padding: 0.5rem 0.75rem !important;
        font-size: 1rem !important;
        line-height: 1.5 !important;
        color: #1f2937 !important;
        background-color: #ffffff !important;
        background-clip: padding-box !important;
        border: 1px solid #d1d5db !important;
        border-radius: 0.375rem !important;
        transition: border-color 0.15s ease-in-out !important;
      }
      .example-demo input:focus,
      .example-demo select:focus,
      .example-demo textarea:focus {
        outline: none !important;
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
      }
      .example-demo .form-control {
        display: block !important;
        width: 100% !important;
        padding: 0.5rem 0.75rem !important;
        font-size: 1rem !important;
        line-height: 1.5 !important;
        color: #1f2937 !important;
        background-color: #ffffff !important;
        border: 1px solid #d1d5db !important;
        border-radius: 0.375rem !important;
      }
      .example-demo .btn {
        display: inline-block !important;
        padding: 0.5rem 1rem !important;
        font-size: 1rem !important;
        font-weight: 500 !important;
        line-height: 1.5 !important;
        text-align: center !important;
        border-radius: 0.375rem !important;
        border: 1px solid transparent !important;
        cursor: pointer !important;
      }
      .example-demo .btn-primary {
        color: #ffffff !important;
        background-color: #3b82f6 !important;
        border-color: #3b82f6 !important;
        padding: 0.625rem 1.25rem !important;
        border-radius: 6px !important;
      }
      .example-demo .btn-primary:hover {
        background-color: #2563eb !important;
        border-color: #2563eb !important;
      }
      /* Wizard-specific: step navigation buttons */
      .example-demo .btn-wizard-nav-previous,
      .example-demo .btn-wizard-nav-next,
      .example-demo .btn-wizard-nav-submit {
        padding: 0.5rem 1.5rem !important;
        border-radius: 6px !important;
        font-weight: 500 !important;
      }
      .example-demo .btn-wizard-nav-next {
        background-color: #3b82f6 !important;
        border-color: #3b82f6 !important;
        color: #ffffff !important;
      }
      .example-demo .btn-wizard-nav-submit {
        background-color: #10b981 !important;
        border-color: #10b981 !important;
        color: #ffffff !important;
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

    <!-- ── Bento Card Grid ── -->
    <div id="bento-grid" class="bento-grid">
      <!-- Getting Started -->
      <div class="bento-card featured" style="--accent:#3b82f6;--badge-bg:#eff6ff;--badge-text:#1d4ed8" data-target="kitchen-sink">
        <span class="card-badge">Getting Started</span>
        <div class="card-icon">&#x1F373;</div>
        <div class="card-title">Kitchen Sink</div>
        <div class="card-desc">Every major field type in one comprehensive form — text, date, select, survey, signature, file upload, and more.</div>
      </div>

      <div class="bento-card" style="--accent:#06b6d4;--badge-bg:#ecfeff;--badge-text:#0e7490" data-target="simple-contact">
        <span class="card-badge">Getting Started</span>
        <div class="card-icon">&#x1F4E7;</div>
        <div class="card-title">Simple Contact</div>
        <div class="card-desc">Minimal contact form with validation.</div>
      </div>

      <div class="bento-card" style="--accent:#14b8a6;--badge-bg:#f0fdfa;--badge-text:#0f766e" data-target="thank-you">
        <span class="card-badge">Getting Started</span>
        <div class="card-icon">&#x1F389;</div>
        <div class="card-title">Thank You Page</div>
        <div class="card-desc">Submit handler that shows a thank-you message.</div>
      </div>

      <!-- Advanced Forms -->
      <div class="bento-card featured" style="--accent:#8b5cf6;--badge-bg:#f5f3ff;--badge-text:#6d28d9" data-target="wizard-form">
        <span class="card-badge">Advanced</span>
        <div class="card-icon">&#x1F3DB;&#xFE0F;</div>
        <div class="card-title">Venue Booking Wizard</div>
        <div class="card-desc">Six-step wizard with side-by-side column layouts, radio groups, and conditional fields for event venue booking.</div>
      </div>

      <div class="bento-card" style="--accent:#7c3aed;--badge-bg:#ede9fe;--badge-text:#5b21b6" data-target="multi-page-wizard">
        <span class="card-badge">Advanced</span>
        <div class="card-icon">&#x1F9D9;</div>
        <div class="card-title">Multi-Page Wizard</div>
        <div class="card-desc">Classic three-step registration wizard with progress indicator and column layouts.</div>
      </div>

      <div class="bento-card" style="--accent:#a855f7;--badge-bg:#faf5ff;--badge-text:#7e22ce" data-target="conditional-logic">
        <span class="card-badge">Advanced</span>
        <div class="card-icon">&#x1F500;</div>
        <div class="card-title">Conditional Logic</div>
        <div class="card-desc">Show/hide fields based on user input.</div>
      </div>

      <div class="bento-card" style="--accent:#6366f1;--badge-bg:#eef2ff;--badge-text:#4338ca" data-target="file-upload">
        <span class="card-badge">Advanced</span>
        <div class="card-icon">&#x1F4C1;</div>
        <div class="card-title">File Upload</div>
        <div class="card-desc">Upload files with type and size validation.</div>
      </div>

      <!-- Components -->
      <div class="bento-card" style="--accent:#22c55e;--badge-bg:#f0fdf4;--badge-text:#15803d" data-target="address-maps">
        <span class="card-badge">Components</span>
        <div class="card-icon">&#x1F4CD;</div>
        <div class="card-title">Address</div>
        <div class="card-desc">Street, city, state, and ZIP fields.</div>
      </div>

      <div class="bento-card" style="--accent:#f59e0b;--badge-bg:#fffbeb;--badge-text:#b45309" data-target="signature">
        <span class="card-badge">Components</span>
        <div class="card-icon">&#x270D;&#xFE0F;</div>
        <div class="card-title">Signature Pad</div>
        <div class="card-desc">Capture digital signatures on a canvas.</div>
      </div>

      <div class="bento-card" style="--accent:#10b981;--badge-bg:#ecfdf5;--badge-text:#047857" data-target="data-grid">
        <span class="card-badge">Components</span>
        <div class="card-icon">&#x1F4CA;</div>
        <div class="card-title">Data Grid</div>
        <div class="card-desc">Repeatable rows with add/remove.</div>
      </div>

      <div class="bento-card" style="--accent:#ef4444;--badge-bg:#fef2f2;--badge-text:#b91c1c" data-target="turnstile-protection">
        <span class="card-badge">Components</span>
        <div class="card-icon">&#x1F6E1;&#xFE0F;</div>
        <div class="card-title">Turnstile Protection</div>
        <div class="card-desc">CAPTCHA-free bot protection by Cloudflare.</div>
      </div>
    </div>

    <!-- ── Detail View ── -->
    <div id="examples-detail" class="examples-detail" style="display:none">
      <div class="detail-inner">
        <a class="back-link" id="back-to-grid">
          <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
          Back to Examples
        </a>

        <!-- Kitchen Sink -->
        <section id="kitchen-sink" class="example-section">
          <div class="example-header">
            <h2>Kitchen Sink</h2>
            <p>A comprehensive form showcasing all major field types and configurations.</p>
          </div>
          <div class="example-demo">
            <div id="form-kitchen-sink"></div>
          </div>
          <div class="code-accordion">
            <div class="code-accordion-header">
              <button class="code-toggle-btn" onclick="toggleCode(this)"><span class="chevron">&#x25B6;</span> View Schema (JSON)</button>
              <button class="copy-btn" onclick="copyCode('kitchen-sink-code')">Copy</button>
            </div>
            <div class="code-accordion-body">
              <pre class="example-code" id="kitchen-sink-code">{
  "display": "form",
  "components": [
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "textfield", "key": "firstName", "label": "First Name" }
      ]},
      { "width": 6, "components": [
        { "type": "textfield", "key": "lastName", "label": "Last Name" }
      ]}
    ]},
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "email", "key": "email", "label": "Email" }
      ]},
      { "width": 6, "components": [
        { "type": "phoneNumber", "key": "phone", "label": "Phone" }
      ]}
    ]},
    { "type": "password", "key": "password", "label": "Password" },
    { "type": "textarea", "key": "bio", "label": "Biography" },
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "datetime", "key": "appointmentDateTime", "label": "Appointment" }
      ]},
      { "width": 6, "components": [
        { "type": "day", "key": "birthDate", "label": "Birth Date" }
      ]}
    ]},
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "select", "key": "country", "label": "Country",
          "data": { "values": [{ "label": "USA", "value": "us" }] }}
      ]},
      { "width": 6, "components": [
        { "type": "selectboxes", "key": "interests", "label": "Interests",
          "values": [{ "label": "Sports", "value": "sports" }] }
      ]}
    ]},
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "checkbox", "key": "newsletter", "label": "Newsletter" }
      ]},
      { "width": 6, "components": [
        { "type": "checkbox", "key": "terms", "label": "Terms" }
      ]}
    ]},
    { "type": "currency", "key": "salary", "label": "Salary" },
    { "type": "signature", "key": "signature", "label": "Signature" },
    { "type": "file", "key": "resume", "label": "Resume", "storage": "base64" }
  ]
}</pre>
            </div>
          </div>
        </section>

        <!-- Simple Contact -->
        <section id="simple-contact" class="example-section">
          <div class="example-header">
            <h2>Simple Contact Form</h2>
            <p>A minimal contact form with validation.</p>
          </div>
          <div class="example-demo">
            <div id="form-simple-contact"></div>
          </div>
          <div class="code-accordion">
            <div class="code-accordion-header">
              <button class="code-toggle-btn" onclick="toggleCode(this)"><span class="chevron">&#x25B6;</span> View Schema (JSON)</button>
              <button class="copy-btn" onclick="copyCode('contact-code')">Copy</button>
            </div>
            <div class="code-accordion-body">
              <pre class="example-code" id="contact-code">{
  "display": "form",
  "components": [
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "textfield", "key": "name", "label": "Full Name",
          "validate": { "required": true } }
      ]},
      { "width": 6, "components": [
        { "type": "email", "key": "email", "label": "Email Address",
          "validate": { "required": true } }
      ]}
    ]},
    {
      "type": "textarea", "key": "message", "label": "Message",
      "rows": 5, "validate": { "required": true }
    }
  ]
}</pre>
            </div>
          </div>
        </section>

        <!-- Thank You Page -->
        <section id="thank-you" class="example-section">
          <div class="example-header">
            <h2>Thank You Page</h2>
            <p>Handle form submission and redirect to a thank you message.</p>
          </div>
          <div class="example-demo">
            <div id="form-thank-you"></div>
            <div id="thank-you-message" style="display: none; padding: 2rem; background: #10b981; color: white; border-radius: 8px; text-align: center;">
              <h3 style="font-size: 1.5rem; margin-bottom: 0.5rem;">Thank You!</h3>
              <p>Your form has been submitted successfully.</p>
            </div>
          </div>
          <div class="code-accordion">
            <div class="code-accordion-header">
              <button class="code-toggle-btn" onclick="toggleCode(this)"><span class="chevron">&#x25B6;</span> View Schema (JSON)</button>
              <button class="copy-btn" onclick="copyCode('thankyou-schema-code')">Copy</button>
            </div>
            <div class="code-accordion-body">
              <pre class="example-code" id="thankyou-schema-code">{
  "display": "form",
  "components": [
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "textfield", "key": "firstName", "label": "First Name",
          "validate": { "required": true } }
      ]},
      { "width": 6, "components": [
        { "type": "textfield", "key": "lastName", "label": "Last Name",
          "validate": { "required": true } }
      ]}
    ]},
    { "type": "columns", "columns": [
      { "width": 6, "components": [
        { "type": "email", "key": "email", "label": "Email Address",
          "validate": { "required": true } }
      ]},
      { "width": 6, "components": [
        { "type": "phoneNumber", "key": "phone", "label": "Phone Number" }
      ]}
    ]},
    { "type": "textarea", "key": "message", "label": "Message",
      "validate": { "required": true }},
    { "type": "button", "action": "submit", "label": "Submit Form" }
  ]
}</pre>
            </div>
          </div>
          <div class="code-accordion">
            <div class="code-accordion-header">
              <button class="code-toggle-btn" onclick="toggleCode(this)"><span class="chevron">&#x25B6;</span> View JavaScript Code</button>
              <button class="copy-btn" onclick="copyCode('thankyou-code')">Copy</button>
            </div>
            <div class="code-accordion-body">
              <pre class="example-code" id="thankyou-code">Formio.createForm(document.getElementById('formio'), formSchema)
  .then(function(form) {
    form.on('submitDone', function(submission) {
      console.log('Form submitted:', submission);
      form.element.style.display = 'none';
      document.getElementById('thank-you-message').style.display = 'block';
    });
  });</pre>
            </div>
          </div>
        </section>

        <!-- Venue Booking Wizard -->
        <section id="wizard-form" class="example-section">
          <div class="example-header">
            <h2>Venue Booking Wizard</h2>
            <p>Six-step wizard with side-by-side column layouts for event venue booking.</p>
          </div>
          <div class="example-demo">
            <div id="form-wizard"></div>
          </div>
          <div class="code-accordion">
            <div class="code-accordion-header">
              <button class="code-toggle-btn" onclick="toggleCode(this)"><span class="chevron">&#x25B6;</span> View Schema (JSON)</button>
              <button class="copy-btn" onclick="copyCode('wizard-code')">Copy</button>
            </div>
            <div class="code-accordion-body">
              <pre class="example-code" id="wizard-code">{
  "display": "wizard",
  "components": [
    {
      "type": "panel", "key": "eventDetails", "title": "Event Details",
      "components": [
        { "type": "textfield", "key": "eventName", "label": "Event Name",
          "validate": { "required": true } },
        { "type": "select", "key": "eventType", "label": "Event Type",
          "data": { "values": [
            { "label": "Birthday Party", "value": "birthday" },
            { "label": "Corporate Event", "value": "corporate" },
            { "label": "Family Reunion", "value": "reunion" },
            { "label": "Community Gathering", "value": "community" }
          ]}, "validate": { "required": true } },
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "number", "key": "adultCount", "label": "Number of Adults",
              "validate": { "required": true, "min": 1 } }
          ]},
          { "width": 6, "components": [
            { "type": "number", "key": "childCount", "label": "Number of Children" }
          ]}
        ]}
      ]
    },
    {
      "type": "panel", "key": "requirements", "title": "Requirements",
      "components": [
        { "type": "radio", "key": "duration", "label": "Event Duration",
          "values": [
            { "label": "2 Hours", "value": "2h" },
            { "label": "4 Hours (Half Day)", "value": "4h" },
            { "label": "8 Hours (Full Day)", "value": "8h" }
          ], "validate": { "required": true } },
        { "type": "select", "key": "alcoholPolicy", "label": "Alcohol Policy",
          "data": { "values": [
            { "label": "No Alcohol", "value": "none" },
            { "label": "BYOB", "value": "byob" },
            { "label": "Licensed Bar", "value": "bar" }
          ]} },
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "checkbox", "key": "needsKitchen",
              "label": "Kitchen Access Required" }
          ]},
          { "width": 6, "components": [
            { "type": "checkbox", "key": "needsGymnasium",
              "label": "Gymnasium / Large Hall" }
          ]}
        ]},
        { "type": "textarea", "key": "specialRequests",
          "label": "Special Requests", "rows": 3 }
      ]
    },
    {
      "type": "panel", "key": "venueSelection", "title": "Venue Selection",
      "components": [
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "textfield", "key": "venueName",
              "label": "Preferred Venue Name" }
          ]},
          { "width": 6, "components": [
            { "type": "select", "key": "venueType", "label": "Venue Type",
              "data": { "values": [
                { "label": "Community Center", "value": "community" },
                { "label": "Park Pavilion", "value": "park" },
                { "label": "Banquet Hall", "value": "banquet" },
                { "label": "Rooftop", "value": "rooftop" }
              ]} }
          ]}
        ]}
      ]
    },
    {
      "type": "panel", "key": "dateTime", "title": "Date & Time",
      "components": [
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "datetime", "key": "eventDate", "label": "Event Date",
              "format": "yyyy-MM-dd", "enableTime": false,
              "validate": { "required": true } }
          ]},
          { "width": 6, "components": [
            { "type": "time", "key": "startTime", "label": "Start Time",
              "validate": { "required": true } }
          ]}
        ]}
      ]
    },
    {
      "type": "panel", "key": "contactInfo", "title": "Contact Information",
      "components": [
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "textfield", "key": "contactName",
              "label": "Contact Name",
              "validate": { "required": true } }
          ]},
          { "width": 6, "components": [
            { "type": "textfield", "key": "organization",
              "label": "Organization (optional)" }
          ]}
        ]},
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "email", "key": "contactEmail",
              "label": "Email",
              "validate": { "required": true } }
          ]},
          { "width": 6, "components": [
            { "type": "phoneNumber", "key": "contactPhone",
              "label": "Phone",
              "validate": { "required": true } }
          ]}
        ]}
      ]
    },
    {
      "type": "panel", "key": "reviewConfirm",
      "title": "Review & Confirm",
      "components": [
        { "type": "checkbox", "key": "termsAccepted",
          "label": "I agree to the venue rental terms and conditions",
          "validate": { "required": true } },
        { "type": "textarea", "key": "additionalNotes",
          "label": "Additional Notes", "rows": 3 }
      ]
    }
  ]
}</pre>
            </div>
          </div>
        </section>

        <!-- Multi-Page Wizard -->
        <section id="multi-page-wizard" class="example-section">
          <div class="example-header">
            <h2>Multi-Page Wizard</h2>
            <p>A classic three-step registration wizard with progress indicator and side-by-side column layouts.</p>
          </div>
          <div class="example-demo">
            <div id="form-multi-wizard"></div>
          </div>
          <div class="code-accordion">
            <div class="code-accordion-header">
              <button class="code-toggle-btn" onclick="toggleCode(this)"><span class="chevron">&#x25B6;</span> View Schema (JSON)</button>
              <button class="copy-btn" onclick="copyCode('multi-wizard-code')">Copy</button>
            </div>
            <div class="code-accordion-body">
              <pre class="example-code" id="multi-wizard-code">{
  "display": "wizard",
  "components": [
    {
      "type": "panel", "key": "personalInfo", "title": "Personal Information",
      "components": [
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "textfield", "key": "firstName", "label": "First Name",
              "validate": { "required": true } }
          ]},
          { "width": 6, "components": [
            { "type": "textfield", "key": "lastName", "label": "Last Name",
              "validate": { "required": true } }
          ]}
        ]},
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "datetime", "key": "birthDate", "label": "Date of Birth",
              "format": "yyyy-MM-dd", "enableTime": false }
          ]},
          { "width": 6, "components": [
            { "type": "select", "key": "gender", "label": "Gender",
              "data": { "values": [
                { "label": "Male", "value": "male" },
                { "label": "Female", "value": "female" },
                { "label": "Non-binary", "value": "nonbinary" },
                { "label": "Prefer not to say", "value": "other" }
              ]} }
          ]}
        ]}
      ]
    },
    {
      "type": "panel", "key": "contactInfo", "title": "Contact Information",
      "components": [
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "email", "key": "email", "label": "Email",
              "validate": { "required": true } }
          ]},
          { "width": 6, "components": [
            { "type": "phoneNumber", "key": "phone", "label": "Phone",
              "validate": { "required": true } }
          ]}
        ]},
        { "type": "textfield", "key": "address", "label": "Street Address" },
        { "type": "columns", "columns": [
          { "width": 6, "components": [
            { "type": "textfield", "key": "city", "label": "City" }
          ]},
          { "width": 6, "components": [
            { "type": "select", "key": "country", "label": "Country",
              "data": { "values": [
                { "label": "United States", "value": "us" },
                { "label": "Canada", "value": "ca" },
                { "label": "United Kingdom", "value": "uk" },
                { "label": "Australia", "value": "au" }
              ]},
              "validate": { "required": true } }
          ]}
        ]}
      ]
    },
    {
      "type": "panel", "key": "preferences", "title": "Preferences & Review",
      "components": [
        { "type": "selectboxes", "key": "interests", "label": "Areas of Interest",
          "values": [
            { "label": "Product Updates", "value": "products" },
            { "label": "Newsletter", "value": "newsletter" },
            { "label": "Special Offers", "value": "offers" },
            { "label": "Events & Webinars", "value": "events" }
          ]},
        { "type": "radio", "key": "contactMethod", "label": "Preferred Contact Method",
          "values": [
            { "label": "Email", "value": "email" },
            { "label": "Phone", "value": "phone" },
            { "label": "SMS", "value": "sms" }
          ],
          "validate": { "required": true } },
        { "type": "textarea", "key": "comments", "label": "Additional Comments", "rows": 3 },
        { "type": "checkbox", "key": "terms", "label": "I agree to the terms and conditions",
          "validate": { "required": true } }
      ]
    }
  ]
}</pre>
            </div>
          </div>
        </section>

        <!-- Conditional Logic -->
        <section id="conditional-logic" class="example-section">
          <div class="example-header">
            <h2>Conditional Logic</h2>
            <p>Show/hide fields based on user input.</p>
          </div>
          <div class="example-demo">
            <div id="form-conditional"></div>
          </div>
        </section>

        <!-- File Upload -->
        <section id="file-upload" class="example-section">
          <div class="example-header">
            <h2>File Upload</h2>
            <p>Upload files to Cloudflare R2 storage.</p>
          </div>
          <div class="example-demo">
            <div id="form-file-upload"></div>
          </div>
        </section>

        <!-- Address -->
        <section id="address-maps" class="example-section">
          <div class="example-header">
            <h2>Address</h2>
            <p>Street, city, state, and ZIP code fields.</p>
          </div>
          <div class="example-demo">
            <div id="form-address"></div>
          </div>
        </section>

        <!-- Signature -->
        <section id="signature" class="example-section">
          <div class="example-header">
            <h2>Signature Pad</h2>
            <p>Capture digital signatures.</p>
          </div>
          <div class="example-demo">
            <div id="form-signature"></div>
          </div>
        </section>

        <!-- Data Grid -->
        <section id="data-grid" class="example-section">
          <div class="example-header">
            <h2>Data Grid</h2>
            <p>Repeatable data entry with add/remove rows.</p>
          </div>
          <div class="example-demo">
            <div id="form-data-grid"></div>
          </div>
        </section>

        <!-- Turnstile -->
        <section id="turnstile-protection" class="example-section">
          <div class="example-header">
            <h2>Turnstile Protection</h2>
            <p>CAPTCHA-free bot protection by Cloudflare - drag and drop from the Premium section in the form builder.</p>
          </div>
          <div class="info-box" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 10px 0; font-size: 18px;">Key Features</h3>
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
            <strong>Setup Instructions:</strong>
            <ol style="margin: 10px 0 0 20px; padding: 0;">
              <li>Go to <strong>Settings &rarr; Plugins</strong> and enable Turnstile plugin</li>
              <li>Get free API keys from <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" style="color: #3b82f6;">Cloudflare Dashboard</a></li>
              <li>Configure site key and secret key in plugin settings</li>
              <li>Drag Turnstile component from <strong>Premium</strong> section in form builder</li>
            </ol>
          </div>
          <div class="info-box" style="margin-top: 15px; background: #fef3c7; border: 1px solid #fbbf24;">
            <strong>Pro Tip:</strong> Use <code>"appearance": "interaction-only"</code> for invisible mode - the widget only appears when suspicious activity is detected!
          </div>
        </section>

      </div><!-- .detail-inner -->
    </div><!-- #examples-detail -->

    <!-- Load Form.io -->
    <script src="https://cdn.form.io/formiojs/formio.full.min.js"></script>

    <!-- Register Turnstile Component -->
    <script>
      (function() {
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
                    <div style="font-size: 32px; margin-bottom: 10px;">&#x1F6E1;&#xFE0F;</div>
                    <div style="font-weight: 600; font-size: 16px; margin-bottom: 5px;">Turnstile Verification</div>
                    <div style="font-size: 13px; opacity: 0.9;">CAPTCHA-free bot protection by Cloudflare</div>
                    <div style="font-size: 12px; margin-top: 10px; opacity: 0.8;">Enable Turnstile plugin in Settings to activate</div>
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
          return true;
        }

        if (!registerTurnstile()) {
          setTimeout(registerTurnstile, 100);
        }
      })();
    </script>

    <script>
      /* ── Navigation ── */
      function showExample(id) {
        document.getElementById('bento-grid').style.display = 'none';
        document.getElementById('examples-detail').style.display = '';
        document.querySelectorAll('.example-section').forEach(function(s) { s.classList.remove('active'); });
        var sec = document.getElementById(id);
        if (sec) sec.classList.add('active');
        window.location.hash = id;
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }

      function showGrid() {
        document.getElementById('bento-grid').style.display = '';
        document.getElementById('examples-detail').style.display = 'none';
        document.querySelectorAll('.example-section').forEach(function(s) { s.classList.remove('active'); });
        history.replaceState(null, '', window.location.pathname);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }

      function setupNavigation() {
        // Card clicks
        document.querySelectorAll('.bento-card[data-target]').forEach(function(card) {
          card.addEventListener('click', function() {
            showExample(this.getAttribute('data-target'));
          });
        });

        // Back link
        var backLink = document.getElementById('back-to-grid');
        if (backLink) {
          backLink.addEventListener('click', function(e) {
            e.preventDefault();
            showGrid();
          });
        }

        // Handle initial hash
        var hash = window.location.hash.substring(1);
        if (hash) {
          showExample(hash);
        }

        // Hash change
        window.addEventListener('hashchange', function() {
          var h = window.location.hash.substring(1);
          if (h) {
            showExample(h);
          } else {
            showGrid();
          }
        });
      }

      /* ── Code accordion toggle ── */
      window.toggleCode = function(btn) {
        btn.classList.toggle('open');
        var body = btn.closest('.code-accordion').querySelector('.code-accordion-body');
        if (body) body.classList.toggle('open');
      };

      /* ── Copy code ── */
      window.copyCode = function(elementId) {
        var code = document.getElementById(elementId).textContent;
        navigator.clipboard.writeText(code).then(function() {
          var btn = event.target;
          var orig = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(function() { btn.textContent = orig; }, 2000);
        });
      };

      /* ── Form schemas & init ── */
      function initForms() {
        var kitchenSinkSchema = {
          display: 'form',
          components: [
            {
              type: 'htmlelement',
              tag: 'h3',
              content: 'Basic Fields',
              className: 'mb-3 text-lg font-semibold'
            },
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'textfield', key: 'firstName', label: 'First Name', placeholder: 'Enter your first name', validate: { required: true } }
                ]},
                { width: 6, components: [
                  { type: 'textfield', key: 'lastName', label: 'Last Name', placeholder: 'Enter your last name', validate: { required: true } }
                ]}
              ]
            },
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'email', key: 'email', label: 'Email Address', placeholder: 'you@example.com', validate: { required: true } }
                ]},
                { width: 6, components: [
                  { type: 'phoneNumber', key: 'phone', label: 'Phone Number', placeholder: '(555) 555-5555' }
                ]}
              ]
            },
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
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'datetime', key: 'appointmentDateTime', label: 'Appointment Date & Time', format: 'yyyy-MM-dd hh:mm a', enableTime: true }
                ]},
                { width: 6, components: [
                  { type: 'day', key: 'birthDate', label: 'Birth Date (Day/Month/Year)' }
                ]}
              ]
            },
            { type: 'time', key: 'preferredTime', label: 'Preferred Contact Time' },

            {
              type: 'htmlelement',
              tag: 'h3',
              content: 'Selection Fields',
              className: 'mt-4 mb-3 text-lg font-semibold'
            },
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
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
                  }
                ]},
                { width: 6, components: [
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
                  }
                ]}
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
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'checkbox', key: 'newsletter', label: 'Subscribe to newsletter' }
                ]},
                { width: 6, components: [
                  { type: 'checkbox', key: 'terms', label: 'I agree to the terms and conditions', validate: { required: true } }
                ]}
              ]
            },

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
        var contactSchema = {
          display: 'form',
          components: [
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'textfield', key: 'name', label: 'Full Name', validate: { required: true } }
                ]},
                { width: 6, components: [
                  { type: 'email', key: 'email', label: 'Email Address', validate: { required: true } }
                ]}
              ]
            },
            { type: 'textarea', key: 'message', label: 'Message', rows: 5, validate: { required: true } },
            { type: 'button', action: 'submit', label: 'Send Message', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-simple-contact'), contactSchema);

        // Thank You Page
        var thankYouSchema = {
          display: 'form',
          components: [
            {
              type: 'htmlelement',
              tag: 'p',
              content: 'Fill out this form and watch it redirect to a thank you page after submission.',
              className: 'mb-4 text-gray-600'
            },
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'textfield', key: 'firstName', label: 'First Name', placeholder: 'Enter your first name', validate: { required: true } }
                ]},
                { width: 6, components: [
                  { type: 'textfield', key: 'lastName', label: 'Last Name', placeholder: 'Enter your last name', validate: { required: true } }
                ]}
              ]
            },
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'email', key: 'email', label: 'Email Address', placeholder: 'you@example.com', validate: { required: true } }
                ]},
                { width: 6, components: [
                  { type: 'phoneNumber', key: 'phone', label: 'Phone Number', placeholder: '(555) 555-5555' }
                ]}
              ]
            },
            { type: 'textarea', key: 'message', label: 'Message', rows: 4, placeholder: 'Your message here...', validate: { required: true } },
            { type: 'button', action: 'submit', label: 'Submit Form', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-thank-you'), thankYouSchema)
          .then(function(form) {
            form.on('submitDone', function(submission) {
              form.element.style.display = 'none';
              document.getElementById('thank-you-message').style.display = 'block';
            });
          });

        // Venue Booking Wizard
        var wizardSchema = {
          display: 'wizard',
          components: [
            {
              type: 'panel',
              key: 'eventDetails',
              title: 'Event Details',
              components: [
                { type: 'textfield', key: 'eventName', label: 'Event Name', placeholder: 'e.g. Annual Family Reunion', validate: { required: true } },
                {
                  type: 'select', key: 'eventType', label: 'Event Type',
                  data: { values: [
                    { label: 'Birthday Party', value: 'birthday' },
                    { label: 'Corporate Event', value: 'corporate' },
                    { label: 'Family Reunion', value: 'reunion' },
                    { label: 'Community Gathering', value: 'community' },
                    { label: 'Wedding Reception', value: 'wedding' },
                    { label: 'Other', value: 'other' }
                  ]},
                  validate: { required: true }
                },
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'number', key: 'adultCount', label: 'Number of Adults', placeholder: '0', validate: { required: true, min: 1 } }
                    ]},
                    { width: 6, components: [
                      { type: 'number', key: 'childCount', label: 'Number of Children', placeholder: '0' }
                    ]}
                  ]
                }
              ]
            },
            {
              type: 'panel',
              key: 'requirements',
              title: 'Requirements',
              components: [
                {
                  type: 'radio', key: 'duration', label: 'Event Duration',
                  values: [
                    { label: '2 Hours', value: '2h' },
                    { label: '4 Hours (Half Day)', value: '4h' },
                    { label: '8 Hours (Full Day)', value: '8h' }
                  ],
                  validate: { required: true }
                },
                {
                  type: 'select', key: 'alcoholPolicy', label: 'Alcohol Policy',
                  data: { values: [
                    { label: 'No Alcohol', value: 'none' },
                    { label: 'BYOB', value: 'byob' },
                    { label: 'Licensed Bar', value: 'bar' }
                  ]}
                },
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'checkbox', key: 'needsKitchen', label: 'Kitchen Access Required' }
                    ]},
                    { width: 6, components: [
                      { type: 'checkbox', key: 'needsGymnasium', label: 'Gymnasium / Large Hall' }
                    ]}
                  ]
                },
                { type: 'textarea', key: 'specialRequests', label: 'Special Requests', rows: 3, placeholder: 'Anything else we should know...' }
              ]
            },
            {
              type: 'panel',
              key: 'venueSelection',
              title: 'Venue Selection',
              components: [
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'textfield', key: 'venueName', label: 'Preferred Venue Name', placeholder: 'e.g. Riverside Pavilion' }
                    ]},
                    { width: 6, components: [
                      { type: 'select', key: 'venueType', label: 'Venue Type',
                        data: { values: [
                          { label: 'Community Center', value: 'community' },
                          { label: 'Park Pavilion', value: 'park' },
                          { label: 'Banquet Hall', value: 'banquet' },
                          { label: 'Rooftop', value: 'rooftop' },
                          { label: 'Indoor Arena', value: 'arena' }
                        ]}
                      }
                    ]}
                  ]
                }
              ]
            },
            {
              type: 'panel',
              key: 'dateTime',
              title: 'Date & Time',
              components: [
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'datetime', key: 'eventDate', label: 'Event Date', format: 'yyyy-MM-dd', enableTime: false, validate: { required: true } }
                    ]},
                    { width: 6, components: [
                      { type: 'time', key: 'startTime', label: 'Start Time', validate: { required: true } }
                    ]}
                  ]
                }
              ]
            },
            {
              type: 'panel',
              key: 'contactInfo',
              title: 'Contact Information',
              components: [
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'textfield', key: 'contactName', label: 'Contact Name', validate: { required: true } }
                    ]},
                    { width: 6, components: [
                      { type: 'textfield', key: 'organization', label: 'Organization (optional)' }
                    ]}
                  ]
                },
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'email', key: 'contactEmail', label: 'Email', validate: { required: true } }
                    ]},
                    { width: 6, components: [
                      { type: 'phoneNumber', key: 'contactPhone', label: 'Phone', validate: { required: true } }
                    ]}
                  ]
                }
              ]
            },
            {
              type: 'panel',
              key: 'reviewConfirm',
              title: 'Review & Confirm',
              components: [
                { type: 'checkbox', key: 'termsAccepted', label: 'I agree to the venue rental terms and conditions', validate: { required: true } },
                { type: 'textarea', key: 'additionalNotes', label: 'Additional Notes', rows: 3, placeholder: 'Final notes or questions...' }
              ]
            }
          ]
        };
        Formio.createForm(document.getElementById('form-wizard'), wizardSchema);

        // Multi-Page Wizard (classic 3-step registration)
        var multiWizardSchema = {
          display: 'wizard',
          components: [
            {
              type: 'panel',
              key: 'personalInfo',
              title: 'Personal Information',
              components: [
                {
                  type: 'htmlelement',
                  tag: 'p',
                  content: 'Please provide your personal information.',
                  className: 'mb-3 text-gray-600'
                },
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'textfield', key: 'firstName', label: 'First Name', placeholder: 'John', validate: { required: true } }
                    ]},
                    { width: 6, components: [
                      { type: 'textfield', key: 'lastName', label: 'Last Name', placeholder: 'Doe', validate: { required: true } }
                    ]}
                  ]
                },
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'datetime', key: 'birthDate', label: 'Date of Birth', format: 'yyyy-MM-dd', enableTime: false, validate: { required: true } }
                    ]},
                    { width: 6, components: [
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
                    ]}
                  ]
                }
              ]
            },
            {
              type: 'panel',
              key: 'contactInfo',
              title: 'Contact Information',
              components: [
                {
                  type: 'htmlelement',
                  tag: 'p',
                  content: 'How can we reach you?',
                  className: 'mb-3 text-gray-600'
                },
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'email', key: 'email', label: 'Email Address', placeholder: 'john.doe@example.com', validate: { required: true } }
                    ]},
                    { width: 6, components: [
                      { type: 'phoneNumber', key: 'phone', label: 'Phone Number', placeholder: '(555) 555-5555', validate: { required: true } }
                    ]}
                  ]
                },
                { type: 'textfield', key: 'address', label: 'Street Address', placeholder: '123 Main St' },
                {
                  type: 'columns',
                  columns: [
                    { width: 6, components: [
                      { type: 'textfield', key: 'city', label: 'City', placeholder: 'New York' }
                    ]},
                    { width: 6, components: [
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
                    ]}
                  ]
                }
              ]
            },
            {
              type: 'panel',
              key: 'preferences',
              title: 'Preferences & Review',
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
        Formio.createForm(document.getElementById('form-multi-wizard'), multiWizardSchema);

        // Conditional Logic
        var conditionalSchema = {
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

        // File Upload
        var fileSchema = {
          display: 'form',
          components: [
            {
              type: 'htmlelement',
              tag: 'p',
              content: 'Upload files to Cloudflare R2 storage (or base64 encoding for demo).',
              className: 'mb-4 text-gray-600'
            },
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'textfield', key: 'name', label: 'Your Name', placeholder: 'John Doe', validate: { required: true } }
                ]},
                { width: 6, components: [
                  { type: 'email', key: 'email', label: 'Email Address', placeholder: 'john@example.com', validate: { required: true } }
                ]}
              ]
            },
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

        // Address
        var addressSchema = {
          display: 'form',
          components: [
            { type: 'textfield', key: 'street', label: 'Street Address' },
            {
              type: 'columns',
              columns: [
                { width: 6, components: [
                  { type: 'textfield', key: 'city', label: 'City' }
                ]},
                { width: 6, components: [
                  { type: 'textfield', key: 'state', label: 'State' }
                ]}
              ]
            },
            { type: 'textfield', key: 'zip', label: 'ZIP Code' },
            { type: 'button', action: 'submit', label: 'Submit', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-address'), addressSchema);

        // Signature
        var signatureSchema = {
          display: 'form',
          components: [
            { type: 'textfield', key: 'name', label: 'Your Name' },
            { type: 'signature', key: 'signature', label: 'Sign Here', width: '100%', height: '150px' },
            { type: 'button', action: 'submit', label: 'Submit', theme: 'primary' }
          ]
        };
        Formio.createForm(document.getElementById('form-signature'), signatureSchema);

        // Data Grid
        var dataGridSchema = {
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
        var turnstileSchema = {
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
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Forms Examples',
    pageTitle: 'Forms Examples',
    content: pageContent,
    user: data.user,
    version: data.version
  }

  return renderAdminLayoutCatalyst(layoutData)
}
