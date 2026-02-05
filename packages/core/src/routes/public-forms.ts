import { Hono } from 'hono'
import { TurnstileService } from '../plugins/core-plugins/turnstile-plugin/services/turnstile'
import { createContentFromSubmission } from '../services/form-collection-sync'

type Bindings = {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  ASSETS: Fetcher
  EMAIL_QUEUE?: Queue
  SENDGRID_API_KEY?: string
  DEFAULT_FROM_EMAIL?: string
  ENVIRONMENT?: string
  GOOGLE_MAPS_API_KEY?: string
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
    exp: number
    iat: number
  }
  requestId?: string
  startTime?: number
  appVersion?: string
}

export const publicFormsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Get Turnstile configuration for a form (for headless frontends)
publicFormsRoutes.get('/:identifier/turnstile-config', async (c) => {
  try {
    const db = c.env.DB
    const identifier = c.req.param('identifier')

    // Get form
    const form = await db.prepare(
      'SELECT id, turnstile_enabled, turnstile_settings FROM forms WHERE (id = ? OR name = ?) AND is_active = 1'
    ).bind(identifier, identifier).first()

    if (!form) {
      return c.json({ error: 'Form not found' }, 404)
    }

    const turnstileService = new TurnstileService(db)
    const globalSettings = await turnstileService.getSettings()
    
    const formSettings = form.turnstile_settings 
      ? JSON.parse(form.turnstile_settings as string)
      : { inherit: true }

    // Determine effective settings
    const enabled = form.turnstile_enabled === 1 || 
                   (formSettings.inherit && globalSettings?.enabled)

    if (!enabled || !globalSettings) {
      return c.json({ enabled: false })
    }

    return c.json({
      enabled: true,
      siteKey: formSettings.siteKey || globalSettings.siteKey,
      theme: formSettings.theme || globalSettings.theme || 'auto',
      size: formSettings.size || globalSettings.size || 'normal',
      mode: formSettings.mode || globalSettings.mode || 'managed',
      appearance: formSettings.appearance || globalSettings.appearance || 'always'
    })
  } catch (error: any) {
    console.error('Error fetching Turnstile config:', error)
    return c.json({ error: 'Failed to fetch config' }, 500)
  }
})

// Get form schema as JSON (for headless frontends)
publicFormsRoutes.get('/:identifier/schema', async (c) => {
  try {
    const db = c.env.DB
    const identifier = c.req.param('identifier')

    // Get form by ID or name
    const form = await db.prepare(
      'SELECT id, name, display_name, description, category, formio_schema, settings, is_active, is_public FROM forms WHERE (id = ? OR name = ?) AND is_active = 1 AND is_public = 1'
    ).bind(identifier, identifier).first()

    if (!form) {
      return c.json({ error: 'Form not found' }, 404)
    }

    const formioSchema = form.formio_schema ? JSON.parse(form.formio_schema as string) : { components: [] }
    const settings = form.settings ? JSON.parse(form.settings as string) : {}

    return c.json({
      id: form.id,
      name: form.name,
      displayName: form.display_name,
      description: form.description,
      category: form.category,
      schema: formioSchema,
      settings: settings,
      submitUrl: `/api/forms/${form.id}/submit`
    })
  } catch (error: any) {
    console.error('Error fetching form schema:', error)
    return c.json({ error: 'Failed to fetch form schema' }, 500)
  }
})

// Render public form by name
publicFormsRoutes.get('/:name', async (c) => {
  try {
    const db = c.env.DB
    const formName = c.req.param('name')
    const googleMapsApiKey = c.env.GOOGLE_MAPS_API_KEY || ''

    // Get form by name
    const form = await db.prepare(
      'SELECT * FROM forms WHERE name = ? AND is_active = 1 AND is_public = 1'
    ).bind(formName).first()

    if (!form) {
      return c.html('<h1>Form not found</h1><p>This form does not exist or is not publicly available.</p>', 404)
    }

    const formioSchema = form.formio_schema ? JSON.parse(form.formio_schema as string) : { components: [] }
    const settings = form.settings ? JSON.parse(form.settings as string) : {}

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${form.display_name}</title>
        <link rel="stylesheet" href="https://cdn.form.io/formiojs/formio.full.min.css">
        
        <!-- Google Maps API will be loaded dynamically per component -->
        
        <style>
          body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #f9fafb;
            padding: 20px;
            margin: 0;
          }
          .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          }
          h1 {
            margin: 0 0 10px 0;
            color: #111827;
            font-size: 28px;
            font-weight: 600;
          }
          .description {
            color: #6b7280;
            margin-bottom: 30px;
          }
          #formio-form {
            margin-bottom: 20px;
          }
          .success-message {
            background: #d1fae5;
            border: 1px solid #10b981;
            color: #065f46;
            padding: 16px;
            border-radius: 6px;
            margin-top: 20px;
            display: none;
          }
          .error-message {
            background: #fee2e2;
            border: 1px solid #ef4444;
            color: #991b1b;
            padding: 16px;
            border-radius: 6px;
            margin-top: 20px;
            display: none;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>${form.display_name}</h1>
          ${form.description ? `<p class="description">${form.description}</p>` : ''}
          
          <div id="formio-form"></div>
          
          <div id="success-message" class="success-message"></div>
          <div id="error-message" class="error-message"></div>
        </div>

        <script src="https://cdn.form.io/formiojs/formio.full.min.js"></script>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        
        <!-- Register Turnstile Component -->
        <script>
          // Register custom Turnstile component with Form.io
          (function() {
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
                  protected: true
                }, ...extend);
              }

              static get builderInfo() {
                return {
                  title: 'Turnstile',
                  group: 'premium',
                  icon: 'fa fa-shield-alt',
                  weight: 120,
                  schema: TurnstileComponent.schema()
                };
              }

              constructor(component, options, data) {
                super(component, options, data);
                this.widgetId = null;
              }

              render() {
                return super.render(\`
                  <div ref="turnstileContainer" class="formio-component-turnstile">
                    <div ref="turnstileWidget" style="margin: 10px 0;"></div>
                  </div>
                \`);
              }

              attach(element) {
                this.loadRefs(element, {
                  turnstileContainer: 'single',
                  turnstileWidget: 'single'
                });

                const superAttach = super.attach(element);
                // Widget will be rendered externally by main form script
                return superAttach;
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
                return super.setValue(value, flags);
              }

              isEmpty(value) {
                return !value;
              }
            }

            Formio.Components.addComponent('turnstile', TurnstileComponent);
            console.log('✅ Turnstile component registered on public form');
          })();
        </script>
        
        <script>
          const formioSchema = ${JSON.stringify(formioSchema)};
          const settings = ${JSON.stringify(settings)};
          const formId = '${form.id}';
          let turnstileToken = null;
          let turnstileWidgetId = null;
          
          // Configure Form.io
          Formio.setBaseUrl('https://api.form.io');

          // Extract Google Maps API key from Address components in the schema
          // Form.io stores it as component.map.key
          function loadGoogleMapsForComponents(schema) {
            const apiKeys = new Set();
            
            // Recursively find all address components and their API keys
            function findAddressComponents(components) {
              if (!components) return;
              
              components.forEach(comp => {
                if (comp.type === 'address' && comp.map && comp.map.key) {
                  apiKeys.add(comp.map.key);
                }
                // Check nested components (panels, fieldsets, etc.)
                if (comp.components) {
                  findAddressComponents(comp.components);
                }
                if (comp.columns && Array.isArray(comp.columns)) {
                  comp.columns.forEach(col => {
                    if (col.components) findAddressComponents(col.components);
                  });
                }
                if (comp.rows && Array.isArray(comp.rows)) {
                  comp.rows.forEach(row => {
                    if (Array.isArray(row)) {
                      row.forEach(col => {
                        if (col.components) findAddressComponents(col.components);
                      });
                    }
                  });
                }
              });
            }
            
            findAddressComponents(schema.components);
            
            // Load Google Maps script with the first API key found
            if (apiKeys.size > 0) {
              const apiKey = Array.from(apiKeys)[0];
              const script = document.createElement('script');
              script.src = \`https://maps.googleapis.com/maps/api/js?key=\${apiKey}&libraries=places\`;
              script.async = true;
              script.defer = true;
              document.head.appendChild(script);
            }
          }
          
          // Load Google Maps if any Address component has an API key
          loadGoogleMapsForComponents(formioSchema);

          Formio.createForm(document.getElementById('formio-form'), formioSchema).then(function(form) {
            // Fetch Turnstile config and render widget
            fetch('/api/forms/' + formId + '/turnstile-config')
              .then(r => r.json())
              .then(config => {
                if (config.enabled && config.siteKey) {
                  // Create Turnstile container
                  const turnstileDiv = document.createElement('div');
                  turnstileDiv.id = 'turnstile-widget';
                  turnstileDiv.style.marginTop = '20px';
                  turnstileDiv.style.marginBottom = '20px';
                  
                  // Insert before submit button
                  const formElement = document.getElementById('formio-form');
                  const submitButton = formElement.querySelector('button[type="submit"]');
                  if (submitButton && submitButton.parentElement) {
                    submitButton.parentElement.insertBefore(turnstileDiv, submitButton);
                  } else {
                    formElement.appendChild(turnstileDiv);
                  }
                  
                  // Render Turnstile widget when script is ready
                  function renderTurnstile() {
                    if (window.turnstile) {
                      turnstileWidgetId = window.turnstile.render('#turnstile-widget', {
                        sitekey: config.siteKey,
                        theme: config.theme || 'auto',
                        size: config.size || 'normal',
                        callback: function(token) {
                          turnstileToken = token;
                          console.log('Turnstile token received');
                        },
                        'error-callback': function() {
                          turnstileToken = null;
                          console.error('Turnstile error');
                        },
                        'expired-callback': function() {
                          turnstileToken = null;
                          console.warn('Turnstile token expired');
                        }
                      });
                    } else {
                      setTimeout(renderTurnstile, 100);
                    }
                  }
                  renderTurnstile();
                }
              })
              .catch(err => {
                console.error('Failed to load Turnstile config:', err);
              });
            
            form.on('submit', async function(submission) {
              try {
                // Hide any previous messages
                document.getElementById('success-message').style.display = 'none';
                document.getElementById('error-message').style.display = 'none';
                
                console.log('Form submitted:', submission.data);
                
                // Get the latest token from Turnstile widget
                if (turnstileWidgetId !== null && window.turnstile) {
                  turnstileToken = window.turnstile.getResponse(turnstileWidgetId);
                  console.log('Turnstile token at submit:', turnstileToken ? 'Present (' + turnstileToken.substring(0, 20) + '...)' : 'Missing');
                }
                
                // Prepare submission data
                const submissionData = {
                  data: {
                    ...submission.data
                  }
                };
                
                // Add turnstile token if available
                if (turnstileToken) {
                  submissionData.data.turnstile = turnstileToken;
                }
                
                console.log('Sending to API with turnstile:', !!submissionData.data.turnstile);
                
                // Submit to our API
                const response = await fetch('/api/forms/' + formId + '/submit', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify(submissionData)
                });

                if (response.ok) {
                  const result = await response.json();
                  
                  // Show success message
                  const successMsg = document.getElementById('success-message');
                  successMsg.textContent = settings.successMessage || 'Thank you for your submission!';
                  successMsg.style.display = 'block';
                  
                  // Reset form
                  form.submission = { data: {} };
                  
                  // Scroll to success message
                  successMsg.scrollIntoView({ behavior: 'smooth', block: 'center' });
                } else {
                  const error = await response.json();
                  throw new Error(error.error || 'Submission failed');
                }
              } catch (error) {
                console.error('Submission error:', error);
                
                // Show error message
                const errorMsg = document.getElementById('error-message');
                errorMsg.textContent = 'Failed to submit form: ' + error.message;
                errorMsg.style.display = 'block';
              }
            });
          }).catch(function(err) {
            console.error('Form render error:', err);
            document.getElementById('error-message').textContent = 'Failed to load form';
            document.getElementById('error-message').style.display = 'block';
          });
        </script>
      </body>
      </html>
    `

    return c.html(html)
  } catch (error: any) {
    console.error('Error rendering form:', error)
    return c.html('<p>Error loading form</p>', 500)
  }
})

// Handle form submission (accepts either name or ID)
publicFormsRoutes.post('/:identifier/submit', async (c) => {
  try {
    const db = c.env.DB
    const identifier = c.req.param('identifier')
    const body = await c.req.json()

    // Get form by ID or name
    const form = await db.prepare(
      'SELECT * FROM forms WHERE (id = ? OR name = ?) AND is_active = 1'
    ).bind(identifier, identifier).first()

    if (!form) {
      return c.json({ error: 'Form not found' }, 404)
    }

    // Check if Turnstile is enabled for this form
    const turnstileEnabled = form.turnstile_enabled === 1
    const turnstileSettings = form.turnstile_settings 
      ? JSON.parse(form.turnstile_settings as string) 
      : { inherit: true }

    // Validate Turnstile if enabled (or inheriting global settings)
    if (turnstileEnabled || turnstileSettings.inherit) {
      const turnstileService = new TurnstileService(db)
      
      // Check if Turnstile is globally enabled
      const globalEnabled = await turnstileService.isEnabled()
      
      if (globalEnabled || turnstileEnabled) {
        // Extract Turnstile token from submission data
        const turnstileToken = body.data?.turnstile || body.turnstile
        
        if (!turnstileToken) {
          return c.json({ 
            error: 'Turnstile verification required. Please complete the security check.',
            code: 'TURNSTILE_MISSING'
          }, 400)
        }

        // Verify the token
        const clientIp = c.req.header('cf-connecting-ip')
        const verification = await turnstileService.verifyToken(turnstileToken, clientIp)
        
        if (!verification.success) {
          return c.json({ 
            error: verification.error || 'Security verification failed. Please try again.',
            code: 'TURNSTILE_INVALID'
          }, 403)
        }

        // Remove Turnstile token from submission data before storing
        if (body.data?.turnstile) {
          delete body.data.turnstile
        }
      }
    }

    // Create submission
    const submissionId = crypto.randomUUID()
    const now = Date.now()

    await db.prepare(`
      INSERT INTO form_submissions (
        id, form_id, submission_data, user_id, ip_address, user_agent,
        submitted_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      submissionId,
      form.id,
      JSON.stringify(body.data),
      null, // user_id (for authenticated users)
      c.req.header('cf-connecting-ip') || null,
      c.req.header('user-agent') || null,
      now,
      now
    ).run()

    // Update submission count
    await db.prepare(`
      UPDATE forms
      SET submission_count = submission_count + 1,
          updated_at = ?
      WHERE id = ?
    `).bind(now, form.id).run()

    // Dual-write: create content item for this submission
    let contentId: string | null = null
    try {
      contentId = await createContentFromSubmission(
        db,
        body.data,
        { id: form.id as string, name: form.name as string, display_name: form.display_name as string },
        submissionId,
        {
          ipAddress: c.req.header('cf-connecting-ip') || null,
          userAgent: c.req.header('user-agent') || null,
          userEmail: body.data?.email || null,
          userId: null // anonymous submission
        }
      )
      if (!contentId) {
        console.warn('[FormSubmit] Content creation returned null for submission:', submissionId)
      }
    } catch (contentError) {
      // Don't fail the submission if content creation fails
      console.error('[FormSubmit] Error creating content from submission:', contentError)
    }

    return c.json({
      success: true,
      submissionId,
      contentId,
      message: 'Form submitted successfully'
    })
  } catch (error: any) {
    console.error('Error submitting form:', error)
    return c.json({ error: 'Failed to submit form' }, 500)
  }
})

export default publicFormsRoutes
