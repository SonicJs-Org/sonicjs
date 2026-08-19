import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { escapeHtml, jsonForScript } from '../../utils/sanitize'

export interface FormBuilderPageData {
  id: string
  name: string
  display_name: string
  description?: string
  category?: string
  formio_schema: any
  settings?: any
  is_active?: boolean
  is_public?: boolean
  google_maps_api_key?: string
  turnstile_site_key?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

// Inline Turnstile component for Form.io builder
function getTurnstileComponentScript(): string {
  return `
    (function() {
      'use strict';

      if (!window.Formio || !window.Formio.Components) {
        console.error('Form.io library not loaded');
        return;
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
            protected: true,
            unique: false,
            hidden: false,
            clearOnHide: true,
            tableView: false,
            validate: {
              required: false
            },
            siteKey: '',
            theme: 'auto',
            size: 'normal',
            action: '',
            appearance: 'always',
            errorMessage: 'Please complete the security verification'
          }, ...extend);
        }

        static get builderInfo() {
          return {
            title: 'Turnstile',
            group: 'premium',
            icon: 'fa fa-shield-alt',
            weight: 120,
            documentation: '/admin/forms/docs#turnstile',
            schema: TurnstileComponent.schema()
          };
        }

        constructor(component, options, data) {
          super(component, options, data);
          this.widgetId = null;
          this.scriptLoaded = false;
        }

        init() {
          super.init();
          // Only load script if NOT in builder/edit mode
          if (!this.options.editMode && !this.options.builder && !this.builderMode) {
            this.loadTurnstileScript();
          }
        }

        loadTurnstileScript() {
          // Extra safety: never load in builder
          if (this.options.editMode || this.options.builder || this.builderMode) {
            console.log('Turnstile: Skipping script load in builder mode');
            return Promise.resolve();
          }

          if (window.turnstile) {
            this.scriptLoaded = true;
            return Promise.resolve();
          }

          if (this.scriptPromise) {
            return this.scriptPromise;
          }

          console.log('Turnstile: Loading script for form mode');
          this.scriptPromise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
            script.async = true;
            script.defer = true;
            script.onload = () => {
              this.scriptLoaded = true;
              resolve();
            };
            script.onerror = () => reject(new Error('Failed to load Turnstile'));
            document.head.appendChild(script);
          });

          return this.scriptPromise;
        }

        render() {
          return super.render(\`
            <div ref="turnstileContainer" class="formio-component-turnstile">
              <div ref="turnstileWidget" style="margin: 10px 0;"></div>
              \${this.component.description ? \`<div class="help-block">\${this.component.description}</div>\` : ''}
            </div>
          \`);
        }

        attach(element) {
          this.loadRefs(element, {
            turnstileContainer: 'single',
            turnstileWidget: 'single'
          });

          const superAttach = super.attach(element);

          // Check if we're in builder mode or form mode
          if (this.options.editMode || this.options.builder) {
            // Builder mode - show placeholder only
            this.renderPlaceholder();
          } else {
            // Form mode - render actual widget
            this.loadTurnstileScript()
              .then(() => this.renderWidget())
              .catch(err => {
                console.error('Failed to load Turnstile:', err);
                if (this.refs.turnstileWidget) {
                  this.refs.turnstileWidget.innerHTML = \`
                    <div class="alert alert-danger" style="padding: 10px; background: #fee; border: 1px solid #fcc; border-radius: 4px;">
                      <strong>Error:</strong> Failed to load security verification
                    </div>
                  \`;
                }
              });
          }

          return superAttach;
        }

        renderPlaceholder() {
          if (!this.refs.turnstileWidget) {
            return;
          }
          
          this.refs.turnstileWidget.innerHTML = \`
            <div style="
              padding: 20px;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              border-radius: 8px;
              color: white;
              text-align: center;
              border: 2px dashed rgba(255,255,255,0.3);
            ">
              <div style="font-size: 24px; margin-bottom: 8px;">🛡️</div>
              <div style="font-weight: 600; margin-bottom: 4px;">Turnstile Verification</div>
              <div style="font-size: 12px; opacity: 0.9;">CAPTCHA-free bot protection by Cloudflare</div>
              <div style="font-size: 11px; margin-top: 8px; opacity: 0.7;">Widget will appear here on the live form</div>
            </div>
          \`;
        }

        renderWidget() {
          if (!this.refs.turnstileWidget || !window.turnstile) {
            return;
          }

          this.refs.turnstileWidget.innerHTML = '';

          const siteKey = this.component.siteKey || 
                          (this.root && this.root.options && this.root.options.turnstileSiteKey) || 
                          '';
          
          if (!siteKey) {
            this.refs.turnstileWidget.innerHTML = \`
              <div class="alert alert-warning" style="padding: 10px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px;">
                <strong>⚠️ Configuration Required:</strong> Turnstile site key not configured. 
                Please enable the Turnstile plugin in Settings → Plugins.
              </div>
            \`;
            return;
          }

          try {
            const self = this;
            this.widgetId = window.turnstile.render(this.refs.turnstileWidget, {
              sitekey: siteKey,
              theme: this.component.theme || 'auto',
              size: this.component.size || 'normal',
              action: this.component.action || '',
              appearance: this.component.appearance || 'always',
              callback: function(token) {
                self.updateValue(token);
                self.triggerChange();
              },
              'error-callback': function() {
                self.updateValue(null);
                self.setCustomValidity(self.component.errorMessage || 'Security verification failed');
              },
              'expired-callback': function() {
                self.updateValue(null);
                self.setCustomValidity('Security verification expired. Please verify again.');
              },
              'timeout-callback': function() {
                self.updateValue(null);
                self.setCustomValidity('Security verification timed out. Please try again.');
              }
            });
          } catch (err) {
            console.error('Failed to render Turnstile widget:', err);
            this.refs.turnstileWidget.innerHTML = \`
              <div class="alert alert-danger" style="padding: 10px; background: #fee; border: 1px solid #fcc; border-radius: 4px;">
                <strong>Error:</strong> Failed to render security verification
              </div>
            \`;
          }
        }

        detach() {
          if (this.widgetId !== null && window.turnstile) {
            try {
              window.turnstile.remove(this.widgetId);
              this.widgetId = null;
            } catch (err) {
              console.error('Failed to remove Turnstile widget:', err);
            }
          }
          return super.detach();
        }

        getValue() {
          if (this.widgetId !== null && window.turnstile) {
            return window.turnstile.getResponse(this.widgetId);
          }
          return this.dataValue;
        }

        setValue(value, flags) {
          const changed = super.setValue(value, flags);
          return changed;
        }

        getValueAsString(value) {
          return value ? '✅ Verified' : '❌ Not Verified';
        }

        isEmpty(value) {
          return !value;
        }

        updateValue(value, flags) {
          const changed = super.updateValue(value, flags);
          
          if (value) {
            this.setCustomValidity('');
          }
          
          return changed;
        }

        checkValidity(data, dirty, row) {
          const result = super.checkValidity(data, dirty, row);
          
          if (this.component.validate && this.component.validate.required) {
            const value = this.getValue();
            if (!value) {
              this.setCustomValidity(this.component.errorMessage || 'Please complete the security verification');
              return false;
            }
          }
          
          return result;
        }
      }

      Formio.Components.addComponent('turnstile', TurnstileComponent);
      console.log('✅ Turnstile component registered with Form.io');
      window.TurnstileComponent = TurnstileComponent;
    })();
  `;
}

export function renderFormBuilderPage(data: FormBuilderPageData): string {
  const formioSchema = data.formio_schema || { components: [] }
  const settings = data.settings || {}
  const googleMapsApiKey = data.google_maps_api_key || ''
  const turnstileSiteKey = data.turnstile_site_key || ''

  const pageContent = `
    <style>
      /* Form.io Builder Styling to match SonicJS theme */
      .formio-builder {
        background: transparent !important;
        border: none !important;
      }

      .formio-builder .formio-component {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 0.5rem !important;
      }

      .formio-builder-sidebar {
        background: rgba(255, 255, 255, 0.02) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.1) !important;
      }

      /* Hide loading spinner after Form.io loads */
      #builder-loading.hidden {
        display: none;
      }

      /* Builder container - Darker gray for better contrast */
      #builder-container {
        min-height: 600px;
        width: 100%;
        background: #e8e8e8;
        border-radius: 0.75rem;
        border: 2px solid #d0d0d0;
        padding: 20px;
      }

      @media (prefers-color-scheme: dark) {
        #builder-container {
          background: #1f2937;
          border-color: rgba(255, 255, 255, 0.2);
        }
      }

      /* Display type toggle buttons */
      .display-type-btn {
        background: #f3f4f6;
        color: #4b5563;
        border: 2px solid transparent;
      }
      
      .display-type-btn:hover {
        background: #e5e7eb;
      }
      
      .display-type-btn.active {
        background: #3b82f6;
        color: white;
        border-color: #2563eb;
      }
      
      @media (prefers-color-scheme: dark) {
        .display-type-btn {
          background: #374151;
          color: #d1d5db;
        }
        
        .display-type-btn:hover {
          background: #4b5563;
        }
        
        .display-type-btn.active {
          background: #3b82f6;
          color: white;
        }
      }

      /* Force Bootstrap grid to work - restore Bootstrap's grid system */
      .formio.builder.row {
        display: flex !important;
        flex-wrap: wrap !important;
        margin-right: -15px !important;
        margin-left: -15px !important;
        min-height: 600px;
      }
      
      /* Sidebar column - Bootstrap grid */
      .formio.builder.row > .formcomponents {
        position: relative !important;
        width: 100% !important;
        padding-right: 15px !important;
        padding-left: 15px !important;
        flex: 0 0 16.666667% !important; /* col-md-2 */
        max-width: 16.666667% !important;
        background: white;
        border-right: 2px solid #e5e7eb;
        max-height: 600px;
        overflow-y: auto;
      }
      
      /* Canvas column - Bootstrap grid */
      .formio.builder.row > .formarea {
        position: relative !important;
        width: 100% !important;
        padding-right: 15px !important;
        padding-left: 15px !important;
        flex: 0 0 83.333333% !important; /* col-md-10 */
        max-width: 83.333333% !important;
        background: white !important;
        border: 3px dashed #94a3b8 !important;
        border-radius: 8px !important;
        min-height: 600px !important;
      }
      
      /* Responsive: tablet */
      @media (max-width: 992px) {
        .formio.builder.row > .formcomponents {
          flex: 0 0 25% !important; /* col-sm-3 */
          max-width: 25% !important;
        }
        .formio.builder.row > .formarea {
          flex: 0 0 75% !important; /* col-sm-9 */
          max-width: 75% !important;
        }
      }
      
      /* Responsive: mobile */
      @media (max-width: 768px) {
        .formio.builder.row > .formcomponents {
          flex: 0 0 33.333333% !important; /* col-xs-4 */
          max-width: 33.333333% !important;
        }
        .formio.builder.row > .formarea {
          flex: 0 0 66.666667% !important; /* col-xs-8 */
          max-width: 66.666667% !important;
        }
      }
      
      @media (prefers-color-scheme: dark) {
        .formcomponents {
          background: #374151 !important;
          border-right-color: rgba(255, 255, 255, 0.2);
        }
        
        .formarea {
          background: #0f172a !important;
          border-color: rgba(255, 255, 255, 0.3) !important;
        }
      }
      
      /* ===================================
       * Preview Modal Styling - Light Theme
       * =================================== */
      
      /* Force light theme in preview */
      #preview-container {
        background: #ffffff !important;
        color: #1f2937 !important;
      }
      
      #preview-container .formio-form {
        background: #ffffff !important;
      }
      
      #preview-container .form-group {
        margin-bottom: 1.5rem;
      }
      
      #preview-container label {
        display: block !important;
        margin-bottom: 0.5rem !important;
        font-weight: 500 !important;
        color: #374151 !important;
        font-size: 0.875rem !important;
      }
      
      #preview-container input[type="text"],
      #preview-container input[type="number"],
      #preview-container input[type="email"],
      #preview-container input[type="tel"],
      #preview-container select,
      #preview-container textarea {
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
      
      #preview-container input:focus,
      #preview-container select:focus,
      #preview-container textarea:focus {
        outline: none !important;
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
      }
      
      #preview-container .btn {
        display: inline-block !important;
        padding: 0.5rem 1rem !important;
        font-size: 1rem !important;
        font-weight: 500 !important;
        line-height: 1.5 !important;
        text-align: center !important;
        border-radius: 0.375rem !important;
        border: 1px solid transparent !important;
        cursor: pointer !important;
        transition: all 0.15s ease-in-out !important;
      }
      
      #preview-container .btn-primary {
        color: #ffffff !important;
        background-color: #3b82f6 !important;
        border-color: #3b82f6 !important;
      }
      
      #preview-container .btn-primary:hover {
        background-color: #2563eb !important;
        border-color: #2563eb !important;
      }
      
      #preview-container .row {
        display: flex !important;
        flex-wrap: wrap !important;
        margin-right: -0.75rem !important;
        margin-left: -0.75rem !important;
      }
      
      #preview-container .col,
      #preview-container [class*="col-"] {
        position: relative !important;
        width: 100% !important;
        padding-right: 0.75rem !important;
        padding-left: 0.75rem !important;
      }
      
      #preview-container .col-xs-3 { flex: 0 0 25% !important; max-width: 25% !important; }
      #preview-container .col-xs-4 { flex: 0 0 33.333333% !important; max-width: 33.333333% !important; }
      #preview-container .col-xs-5 { flex: 0 0 41.666667% !important; max-width: 41.666667% !important; }
      
      /* Bootstrap collapse - force override inline styles */
      #builder-container .collapse {
        display: none !important;
      }
      
      #builder-container .collapse.show {
        display: block !important;
      }
      
      #builder-container .collapsing {
        display: block !important;
        height: 0;
        overflow: hidden;
        transition: height 0.35s ease;
      }
      
      /* Sidebar component items - Darker for better contrast */
      .formcomponent {
        background: #e9ecef !important;
        border: 2px solid #ced4da !important;
        border-radius: 6px !important;
        padding: 10px !important;
        margin: 8px 0 !important;
        font-weight: 500 !important;
        color: #212529 !important;
        display: block !important;
        visibility: visible !important;
      }
      
      .formcomponent:hover {
        background: #dee2e6 !important;
        border-color: #adb5bd !important;
        box-shadow: 0 2px 4px rgba(0,0,0,0.15) !important;
      }
      
      @media (prefers-color-scheme: dark) {
        .formcomponent {
          background: #1e3a8a !important;
          border-color: #3b82f6 !important;
          color: #dbeafe !important;
        }
        
        .formcomponent:hover {
          background: #1e40af !important;
          border-color: #60a5fa !important;
        }
      }
      
      /* Dropped components in canvas - White with darker borders */
      .builder-component {
        background: #ffffff !important;
        padding: 15px !important;
        margin: 15px 0 !important;
        border: 2px solid #c0c0c0 !important;
        border-radius: 8px !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.12) !important;
      }
      
      .builder-component:hover {
        border-color: #9e9e9e !important;
        box-shadow: 0 2px 6px rgba(0,0,0,0.18) !important;
      }
      
      /* Component labels */
      .builder-component label,
      .formio-component label {
        color: #0f172a !important;
        font-weight: 600 !important;
      }
      
      /* Edit buttons */
      .component-btn-group {
        background: #64748b !important;
        padding: 4px !important;
        border-radius: 4px !important;
      }
      
      .component-btn-group .btn {
        color: white !important;
      }
      
      @media (prefers-color-scheme: dark) {
        .builder-component {
          background: #1e40af !important;
          border-color: #3b82f6 !important;
        }
        
        .builder-component label,
        .formio-component label {
          color: #f1f5f9 !important;
        }
      }
    </style>

    <div>
      <!-- Header -->
      <div class="mb-6">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-4">
            <a href="/admin/forms" class="text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
              </svg>
            </a>
            <div>
              <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">
                Form Builder: ${escapeHtml(data.display_name)}
              </h1>
              <p class="mt-1 text-sm/6 text-zinc-500 dark:text-zinc-400">
                <span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-500/10 px-2 py-1 text-xs font-medium text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-700/10 dark:ring-cyan-400/20">
                  ${escapeHtml(data.name)}
                </span>
              </p>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center gap-3">
            <button
              id="preview-btn"
              type="button"
              class="inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors"
            >
              <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
              </svg>
              Preview
            </button>

            <button
              id="save-btn"
              type="button"
              class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-4 py-2 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm"
            >
              <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              Save Form
            </button>

            <a
              href="/forms/${escapeHtml(data.name)}"
              target="_blank"
              class="inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg bg-purple-600 text-white hover:bg-purple-700 transition-colors"
              title="Open public form in new tab"
            >
              <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
              </svg>
              View Public Form
            </a>

            <a
              href="/admin/forms/${data.id}/submissions"
              class="inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg bg-green-600 text-white hover:bg-green-700 transition-colors"
            >
              <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
              </svg>
              View Submissions
            </a>
          </div>
        </div>
      </div>

      <!-- Display Type Toggle -->
      <div class="mb-6 flex items-center gap-4">
        <label class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Display Type:</label>
        <div class="flex gap-2">
          <button
            id="display-form-btn"
            class="display-type-btn active inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg transition-colors"
            data-display="form"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
            Single Page
          </button>
          <button
            id="display-wizard-btn"
            class="display-type-btn inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg transition-colors"
            data-display="wizard"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
            </svg>
            Multi-Page Wizard
          </button>
        </div>
        <span class="text-xs text-zinc-500 dark:text-zinc-400 italic" id="wizard-hint" style="display: none;">
          💡 Use <strong>Panel</strong> components (Layout tab) for each page
        </span>
      </div>

      <!-- Success/Error Messages -->
      <div id="notification-container"></div>

      <!-- Loading State -->
      <div id="builder-loading" class="flex items-center justify-center py-20">
        <div class="text-center">
          <svg class="animate-spin h-12 w-12 mx-auto text-blue-600" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p class="mt-4 text-zinc-500 dark:text-zinc-400">Loading Form Builder...</p>
        </div>
      </div>

      <!-- Form.io Builder Container -->
      <div id="builder-container" style="display: none;"></div>

      <!-- Preview Modal -->
      <div id="preview-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-zinc-900 rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
          <div class="flex items-center justify-between p-6 border-b border-zinc-200 dark:border-zinc-700">
            <h2 class="text-xl font-semibold text-zinc-900 dark:text-white">Form Preview</h2>
            <button
              id="close-preview-btn"
              type="button"
              class="text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
            >
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <div class="flex-1 overflow-auto p-6 bg-gray-50 dark:bg-zinc-800">
            <div id="preview-container" class="bg-white rounded-lg p-6 shadow-sm"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Form.io CSS -->
    <link rel="stylesheet" href="https://cdn.form.io/formiojs/formio.full.min.css">

    <!-- Google Maps API will be loaded dynamically based on component configuration -->

    <!-- Form.io JS -->
    <script src="https://cdn.form.io/formiojs/formio.full.min.js"></script>
    
    <!-- Turnstile Component Registration -->
    <script>
${getTurnstileComponentScript()}
    </script>

    <!-- Builder Integration Script -->
    <script>
      (function() {
        const formId = '${data.id}';
        const existingSchema = ${jsonForScript(formioSchema)};
        const GOOGLE_MAPS_API_KEY = '${googleMapsApiKey}'; // Global fallback
        let builder;
        let hasUnsavedChanges = false;

        // Configure Form.io
        Formio.setBaseUrl('https://api.form.io');

        // Show notification helper
        function showNotification(message, type = 'info') {
          const container = document.getElementById('notification-container');
          const colors = {
            success: 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300',
            error: 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300',
            info: 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300'
          };

          const notification = document.createElement('div');
          notification.className = \`mb-4 rounded-lg p-4 border \${colors[type] || colors.info}\`;
          notification.innerHTML = \`
            <div class="flex items-center">
              <svg class="h-5 w-5 mr-3" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/>
              </svg>
              <p class="text-sm">\${message}</p>
            </div>
          \`;

          container.appendChild(notification);

          // Auto-remove after 5 seconds
          setTimeout(() => {
            notification.remove();
          }, 5000);
        }

        // Initialize Form.io Builder
        async function initBuilder() {
          try {
            // Show builder container, hide loading
            document.getElementById('builder-loading').classList.add('hidden');
            document.getElementById('builder-container').style.display = 'block';

            // Get display type from schema or default to 'form'
            const currentDisplay = existingSchema.display || 'form';
            
            // Update toggle buttons
            updateDisplayToggle(currentDisplay);

            // Builder options - Configure component groups
            const builderOptions = {
              display: currentDisplay, // Set display type (form or wizard)
              builder: {
                // Layout components - explicitly configure
                layout: {
                  title: 'Layout',
                  weight: 0,
                  components: {
                    panel: true,
                    table: true,
                    tabs: true,
                    well: true,
                    columns: true,
                    fieldset: true,
                    content: true,
                    htmlelement: true
                  }
                },
                // Remove premium/licensed components
                premium: {
                  title: 'Premium',
                  default: false,
                  weight: 50,
                  components: {
                    // Keep open-source components
                    file: true,        // Open source, just needs storage
                    signature: true,   // Open source
                    // Hide premium components that require license
                    form: false,       // Nested forms - requires license
                    custom: false,     // Custom components - requires license
                    resource: false    // Resource - requires Form.io backend
                  }
                },
                advanced: {
                  // Customize advanced components
                  title: 'Advanced',
                  weight: 20,
                  components: {
                    // Keep all open-source advanced components
                    email: true,
                    url: true,
                    phoneNumber: true,
                    tags: true,
                    address: {
                      schema: {
                        map: {
                          key: GOOGLE_MAPS_API_KEY || '' // Default API key if available
                        }
                      }
                    },
                    datetime: true,
                    day: true,
                    time: true,
                    currency: true,
                    survey: true,
                    signature: true,
                    // Remove reCAPTCHA - you have Turnstile
                    recaptcha: false
                  }
                }
              }
            };

            // Create builder with Turnstile configuration
            Formio.builder(
              document.getElementById('builder-container'),
              existingSchema,
              {
                ...builderOptions,
                turnstileSiteKey: '${turnstileSiteKey}'
              }
            ).then(function(form) {
              builder = form;
              console.log('Form.io Builder initialized successfully');

              // Listen for changes
              builder.on('change', function(schema) {
                hasUnsavedChanges = true;
                console.log('Form schema changed');
                
                // Update save button text
                const saveBtn = document.getElementById('save-btn');
                if (saveBtn && !saveBtn.textContent.includes('*')) {
                  saveBtn.innerHTML = '<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Save Form *';
                }
              });

              console.log('Form.io Builder ready for use');
            }).catch(function(error) {
              console.error('Error initializing Form.io Builder:', error);
              showNotification('Failed to initialize form builder: ' + error.message, 'error');
            });
          } catch (error) {
            console.error('Error initializing Form.io Builder:', error);
            showNotification('Failed to initialize form builder: ' + error.message, 'error');
          }
        }

        // Display type toggle functionality
        function updateDisplayToggle(displayType) {
          const formBtn = document.getElementById('display-form-btn');
          const wizardBtn = document.getElementById('display-wizard-btn');
          const wizardHint = document.getElementById('wizard-hint');
          
          if (!formBtn || !wizardBtn || !wizardHint) return; // Safety check
          
          if (displayType === 'wizard') {
            formBtn.classList.remove('active');
            wizardBtn.classList.add('active');
            wizardHint.style.display = 'inline';
          } else {
            formBtn.classList.add('active');
            wizardBtn.classList.remove('active');
            wizardHint.style.display = 'none';
          }
        }

        // Setup event listeners
        function setupEventListeners() {
          // Display type toggle handlers
          const formBtn = document.getElementById('display-form-btn');
          const wizardBtn = document.getElementById('display-wizard-btn');
          
          if (formBtn) {
            formBtn.addEventListener('click', async () => {
              if (builder) {
                const schema = builder.schema;
                schema.display = 'form';
                await reinitializeBuilder(schema);
                updateDisplayToggle('form');
                hasUnsavedChanges = true;
              }
            });
          }

          if (wizardBtn) {
            wizardBtn.addEventListener('click', async () => {
              if (builder) {
                const schema = builder.schema;
                schema.display = 'wizard';
                await reinitializeBuilder(schema);
                updateDisplayToggle('wizard');
                hasUnsavedChanges = true;
                
                // Show helpful message
                showNotification('Wizard mode enabled! Use Panel components from the Layout tab to create pages.', 'info');
              }
            });
          }

          // Save button handler
          const saveBtn = document.getElementById('save-btn');
          if (saveBtn) {
            saveBtn.addEventListener('click', async () => {
              if (!builder) {
                showNotification('Builder not initialized', 'error');
                return;
              }

              try {
                const schema = builder.schema;
                const saveBtn = document.getElementById('save-btn');
                
                // Disable button during save
                saveBtn.disabled = true;
                saveBtn.innerHTML = '<svg class="animate-spin w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Saving...';

                const response = await fetch(\`/admin/forms/\${formId}\`, {
                  method: 'PUT',
                  headers: {
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({
                    formio_schema: schema
                  })
                });

                if (response.ok) {
                  hasUnsavedChanges = false;
                  showNotification('Form saved successfully!', 'success');
                  saveBtn.innerHTML = '<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Save Form';
                } else {
                  const error = await response.json();
                  showNotification('Failed to save form: ' + (error.error || 'Unknown error'), 'error');
                }
              } catch (error) {
                console.error('Save error:', error);
                showNotification('Failed to save form: ' + error.message, 'error');
              } finally {
                const saveBtn = document.getElementById('save-btn');
                saveBtn.disabled = false;
              }
            });
          }

          // Preview button handler
          const previewBtn = document.getElementById('preview-btn');
          if (previewBtn) {
            previewBtn.addEventListener('click', async () => {
              if (!builder) {
                showNotification('Builder not initialized', 'error');
                return;
              }

              try {
                const schema = builder.schema;
                const modal = document.getElementById('preview-modal');
                const container = document.getElementById('preview-container');
                
                // Clear previous preview
                container.innerHTML = '';
                
                // Create preview form
                await Formio.createForm(container, schema);
                
                // Show modal
                modal.classList.remove('hidden');
              } catch (error) {
                console.error('Preview error:', error);
                showNotification('Failed to create preview: ' + error.message, 'error');
              }
            });
          }

          // Close preview modal
          const closePreviewBtn = document.getElementById('close-preview-btn');
          if (closePreviewBtn) {
            closePreviewBtn.addEventListener('click', () => {
              document.getElementById('preview-modal').classList.add('hidden');
            });
          }

          // Close modal on backdrop click
          const previewModal = document.getElementById('preview-modal');
          if (previewModal) {
            previewModal.addEventListener('click', (e) => {
              if (e.target.id === 'preview-modal') {
                document.getElementById('preview-modal').classList.add('hidden');
              }
            });
          }

          // Warn about unsaved changes
          window.addEventListener('beforeunload', (e) => {
            if (hasUnsavedChanges) {
              e.preventDefault();
              e.returnValue = '';
            }
          });
          
          // Custom collapse handler (replaces Bootstrap JS)
          document.addEventListener('click', function(e) {
            const button = e.target.closest('[data-toggle="collapse"]');
            if (!button) return;
            
            const targetId = button.getAttribute('data-target');
            if (!targetId) return;
            
            const target = document.querySelector(targetId);
            if (!target) return;
            
            e.preventDefault();
            
            if (target.classList.contains('show')) {
              target.classList.remove('show');
            } else {
              const parent = button.getAttribute('data-parent');
              if (parent) {
                const siblings = document.querySelectorAll(parent + ' .collapse.show');
                siblings.forEach(function(sibling) {
                  if (sibling !== target) {
                    sibling.classList.remove('show');
                  }
                });
              }
              target.classList.add('show');
            }
          });
        }

        // Reinitialize builder with new display type
        async function reinitializeBuilder(schema) {
          if (builder) {
            builder.destroy();
          }
          
          const builderOptions = {
            display: schema.display || 'form',
            builder: {
              layout: {
                title: 'Layout',
                weight: 0,
                components: {
                  panel: true,
                  table: true,
                  tabs: true,
                  well: true,
                  columns: true,
                  fieldset: true,
                  content: true,
                  htmlelement: true
                }
              },
              premium: {
                title: 'Premium',
                default: false,
                weight: 50,
                components: {
                  file: true,
                  signature: true,
                  form: false,
                  custom: false,
                  resource: false
                }
              },
              advanced: {
                title: 'Advanced',
                weight: 20,
                components: {
                  email: true,
                  url: true,
                  phoneNumber: true,
                  tags: true,
                  address: {
                    schema: {
                      map: {
                        key: GOOGLE_MAPS_API_KEY || ''
                      }
                    }
                  },
                  datetime: true,
                  day: true,
                  time: true,
                  currency: true,
                  survey: true,
                  signature: true,
                  recaptcha: false
                }
              }
            }
          };
          
          builder = await Formio.builder(
            document.getElementById('builder-container'),
            schema,
            {
              ...builderOptions,
              turnstileSiteKey: '${turnstileSiteKey}'
            }
          );
          
          builder.on('change', function(updatedSchema) {
            hasUnsavedChanges = true;
            const saveBtn = document.getElementById('save-btn');
            if (saveBtn && !saveBtn.textContent.includes('*')) {
              saveBtn.innerHTML = '<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Save Form *';
            }
          });
        }

        // Initialize when DOM and Formio are ready
        function waitForFormio() {
          if (typeof Formio === 'undefined') {
            console.log('Waiting for Form.io to load...');
            setTimeout(waitForFormio, 100);
            return;
          }
          
          console.log('Form.io loaded, initializing builder...');
          setupEventListeners(); // Setup all event listeners first
          initBuilder();
        }
        
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', waitForFormio);
        } else {
          waitForFormio();
        }
      })();
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: `Form Builder: ${escapeHtml(data.display_name)}`,
    content: pageContent,
    user: data.user,
    version: data.version
  }

  return renderAdminLayoutCatalyst(layoutData)
}
