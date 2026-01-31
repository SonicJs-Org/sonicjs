# Creating Forms Programmatically in SonicJS

**Yes!** You can create forms programmatically via API calls or directly in code, just like collections!

---

## 📋 Overview

Forms can be created in **three ways**:

1. **Admin UI** - Visual form builder at `/admin/forms`
2. **API Calls** - HTTP POST to create forms via API
3. **Database Direct** - Insert into `forms` table in migrations or seed scripts

---

## 🚀 Method 1: API Calls

### Create Form via API

**Endpoint:** `POST /admin/forms`  
**Auth Required:** Yes (admin authentication)

#### Request Body (Form Data)

```typescript
{
  name: string           // Required: Unique identifier (lowercase, underscores, numbers)
  displayName: string    // Required: Human-readable name
  description?: string   // Optional: Form description
  category?: string      // Optional: Category (default: 'general')
}
```

#### Example: Using Fetch

```typescript
// Create a contact form
const response = await fetch('http://localhost:8787/admin/forms', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    // Session cookie sent automatically with credentials: 'include'
  },
  body: new URLSearchParams({
    name: 'contact_form',
    displayName: 'Contact Us',
    description: 'Customer contact form',
    category: 'customer_service'
  })
});

// Redirects to: /admin/forms/{formId}/builder
```

#### Example: Using curl

```bash
curl -X POST http://localhost:8787/admin/forms \
  -b cookies.txt \   # or Cookie: better-auth.session_token=...
  -d "name=contact_form" \
  -d "displayName=Contact Us" \
  -d "description=Customer contact form" \
  -d "category=customer_service"
```

#### Response

On success, **redirects to builder**: `/admin/forms/{formId}/builder`

On error:
```json
{
  "error": "Name and display name are required"
}
```

---

## 🗄️ Method 2: Database Direct (Migrations/Seeds)

Create forms directly in the database, perfect for **predefined forms** or **fixtures**.

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS forms (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT,
  category TEXT DEFAULT 'general',
  formio_schema TEXT NOT NULL,      -- JSON Form.io schema
  settings TEXT,                     -- JSON settings
  is_active INTEGER DEFAULT 1,
  is_public INTEGER DEFAULT 1,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

### Example: Create Form in Migration

```sql
-- migrations/030_add_contact_form.sql

-- Contact form with complete schema
INSERT INTO forms (
  id,
  name,
  display_name,
  description,
  category,
  formio_schema,
  settings,
  is_active,
  is_public,
  created_at,
  updated_at
) VALUES (
  '550e8400-e29b-41d4-a716-446655440000',
  'contact_form',
  'Contact Us',
  'General contact form for customer inquiries',
  'customer_service',
  json('{
    "display": "form",
    "components": [
      {
        "type": "textfield",
        "key": "name",
        "label": "Full Name",
        "placeholder": "Enter your name",
        "validate": {
          "required": true
        }
      },
      {
        "type": "email",
        "key": "email",
        "label": "Email Address",
        "placeholder": "you@example.com",
        "validate": {
          "required": true
        }
      },
      {
        "type": "textarea",
        "key": "message",
        "label": "Message",
        "placeholder": "How can we help you?",
        "rows": 5,
        "validate": {
          "required": true
        }
      }
    ]
  }'),
  json('{
    "submitButtonText": "Send Message",
    "successMessage": "Thank you! We will get back to you soon.",
    "requireAuth": false,
    "emailNotifications": true,
    "notificationEmail": "support@example.com"
  }'),
  1,
  1,
  1737767400000,
  1737767400000
);
```

### Example: Multi-Page Wizard Form

```sql
-- Create job application wizard
INSERT INTO forms (
  id,
  name,
  display_name,
  description,
  category,
  formio_schema,
  settings,
  is_active,
  is_public,
  created_at,
  updated_at
) VALUES (
  '660e8400-e29b-41d4-a716-446655440001',
  'job_application',
  'Job Application',
  'Multi-step job application form',
  'hr',
  json('{
    "display": "wizard",
    "components": [
      {
        "type": "panel",
        "key": "personalInfo",
        "title": "Personal Information",
        "components": [
          {
            "type": "textfield",
            "key": "firstName",
            "label": "First Name",
            "validate": {"required": true}
          },
          {
            "type": "textfield",
            "key": "lastName",
            "label": "Last Name",
            "validate": {"required": true}
          },
          {
            "type": "email",
            "key": "email",
            "label": "Email",
            "validate": {"required": true}
          }
        ]
      },
      {
        "type": "panel",
        "key": "experience",
        "title": "Experience",
        "components": [
          {
            "type": "number",
            "key": "yearsExperience",
            "label": "Years of Experience",
            "validate": {"required": true, "min": 0}
          },
          {
            "type": "file",
            "key": "resume",
            "label": "Upload Resume",
            "storage": "r2"
          }
        ]
      }
    ]
  }'),
  json('{
    "submitButtonText": "Submit Application",
    "successMessage": "Application received! We will review it shortly.",
    "requireAuth": false,
    "emailNotifications": true
  }'),
  1,
  1,
  1737767400000,
  1737767400000
);
```

---

## 🔧 Method 3: Programmatic Creation in Code

Create forms in TypeScript/JavaScript code (e.g., plugin initialization, setup scripts).

### Example: Form Creation Service

```typescript
// services/form-creator.ts

interface CreateFormOptions {
  name: string
  displayName: string
  description?: string
  category?: string
  schema?: any
  settings?: any
  isActive?: boolean
  isPublic?: boolean
}

export async function createForm(
  db: D1Database,
  options: CreateFormOptions
): Promise<string> {
  const {
    name,
    displayName,
    description = '',
    category = 'general',
    schema = { components: [] },
    settings = {
      submitButtonText: 'Submit',
      successMessage: 'Thank you for your submission!',
      requireAuth: false,
      emailNotifications: false
    },
    isActive = true,
    isPublic = true
  } = options

  // Validate name format
  if (!/^[a-z0-9_]+$/.test(name)) {
    throw new Error('Form name must contain only lowercase letters, numbers, and underscores')
  }

  // Check for duplicate
  const existing = await db.prepare('SELECT id FROM forms WHERE name = ?')
    .bind(name)
    .first()

  if (existing) {
    throw new Error(`Form with name '${name}' already exists`)
  }

  // Create form
  const formId = crypto.randomUUID()
  const now = Date.now()

  await db.prepare(`
    INSERT INTO forms (
      id, name, display_name, description, category,
      formio_schema, settings, is_active, is_public,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    formId,
    name,
    displayName,
    description,
    category,
    JSON.stringify(schema),
    JSON.stringify(settings),
    isActive ? 1 : 0,
    isPublic ? 1 : 0,
    now,
    now
  ).run()

  return formId
}

// Usage example
const formId = await createForm(db, {
  name: 'newsletter_signup',
  displayName: 'Newsletter Sign Up',
  description: 'Subscribe to our newsletter',
  category: 'marketing',
  schema: {
    display: 'form',
    components: [
      {
        type: 'email',
        key: 'email',
        label: 'Email Address',
        placeholder: 'you@example.com',
        validate: { required: true }
      },
      {
        type: 'checkbox',
        key: 'consent',
        label: 'I agree to receive newsletters',
        validate: { required: true }
      }
    ]
  },
  settings: {
    submitButtonText: 'Subscribe',
    successMessage: 'Successfully subscribed!',
    requireAuth: false,
    emailNotifications: true,
    notificationEmail: 'marketing@example.com'
  }
})

console.log(`Form created with ID: ${formId}`)
```

### Example: Plugin That Creates Forms

```typescript
// plugins/feedback-plugin.ts

export const feedbackPlugin = {
  name: 'feedback',
  displayName: 'Feedback System',
  version: '1.0.0',
  
  async install(db: D1Database) {
    // Create feedback form during plugin installation
    const formId = await createForm(db, {
      name: 'product_feedback',
      displayName: 'Product Feedback',
      description: 'Collect user feedback on products',
      category: 'feedback',
      schema: {
        display: 'form',
        components: [
          {
            type: 'select',
            key: 'product',
            label: 'Product',
            data: {
              values: [
                { label: 'Product A', value: 'product_a' },
                { label: 'Product B', value: 'product_b' },
                { label: 'Product C', value: 'product_c' }
              ]
            },
            validate: { required: true }
          },
          {
            type: 'radio',
            key: 'rating',
            label: 'How would you rate this product?',
            values: [
              { label: '⭐ 1 Star', value: '1' },
              { label: '⭐⭐ 2 Stars', value: '2' },
              { label: '⭐⭐⭐ 3 Stars', value: '3' },
              { label: '⭐⭐⭐⭐ 4 Stars', value: '4' },
              { label: '⭐⭐⭐⭐⭐ 5 Stars', value: '5' }
            ],
            validate: { required: true }
          },
          {
            type: 'textarea',
            key: 'comments',
            label: 'Additional Comments',
            rows: 5
          }
        ]
      }
    })
    
    console.log(`Feedback form created: ${formId}`)
  }
}
```

---

## 📝 Form Schema Structure

### Minimal Schema (Empty Form)

```json
{
  "components": []
}
```

### Single-Page Form Schema

```json
{
  "display": "form",
  "components": [
    {
      "type": "textfield",
      "key": "name",
      "label": "Name",
      "placeholder": "Enter your name",
      "validate": {
        "required": true
      }
    },
    {
      "type": "email",
      "key": "email",
      "label": "Email",
      "validate": {
        "required": true
      }
    }
  ]
}
```

### Multi-Page Wizard Schema

```json
{
  "display": "wizard",
  "components": [
    {
      "type": "panel",
      "key": "page1",
      "title": "Step 1: Basic Info",
      "components": [
        {
          "type": "textfield",
          "key": "name",
          "label": "Name",
          "validate": {"required": true}
        }
      ]
    },
    {
      "type": "panel",
      "key": "page2",
      "title": "Step 2: Contact",
      "components": [
        {
          "type": "email",
          "key": "email",
          "label": "Email",
          "validate": {"required": true}
        }
      ]
    }
  ]
}
```

### Settings Object

```json
{
  "submitButtonText": "Submit",
  "successMessage": "Thank you for your submission!",
  "requireAuth": false,
  "emailNotifications": false,
  "notificationEmail": "admin@example.com",
  "redirectUrl": "/thank-you",
  "allowDuplicates": true
}
```

---

## 🔐 Authentication & Permissions

### Admin Routes (Auth Required)

All `/admin/forms/*` routes require authentication:

```typescript
// Middleware automatically applied
adminFormsRoutes.use('*', requireAuth())

// Routes:
POST   /admin/forms          - Create form
GET    /admin/forms/:id      - View form details
PUT    /admin/forms/:id      - Update form
DELETE /admin/forms/:id      - Delete form
GET    /admin/forms/:id/builder      - Form builder UI
GET    /admin/forms/:id/submissions  - View submissions
```

### Public Routes (No Auth)

Forms can be accessed publicly:

```typescript
GET  /forms/:name        - Render public form
POST /api/forms/:id/submit  - Submit form data
```

---

## 📊 Complete Example: Registration System

### 1. Create Forms in Migration

```sql
-- migrations/031_registration_system.sql

-- User registration form
INSERT INTO forms (id, name, display_name, category, formio_schema, settings, is_active, is_public, created_at, updated_at)
VALUES (
  'reg-001',
  'user_registration',
  'User Registration',
  'auth',
  json('{
    "display": "wizard",
    "components": [
      {
        "type": "panel",
        "key": "account",
        "title": "Account Details",
        "components": [
          {"type": "textfield", "key": "username", "label": "Username", "validate": {"required": true, "minLength": 3}},
          {"type": "email", "key": "email", "label": "Email", "validate": {"required": true}},
          {"type": "password", "key": "password", "label": "Password", "validate": {"required": true, "minLength": 8}}
        ]
      },
      {
        "type": "panel",
        "key": "profile",
        "title": "Profile Information",
        "components": [
          {"type": "textfield", "key": "firstName", "label": "First Name", "validate": {"required": true}},
          {"type": "textfield", "key": "lastName", "label": "Last Name", "validate": {"required": true}},
          {"type": "phoneNumber", "key": "phone", "label": "Phone Number"}
        ]
      },
      {
        "type": "panel",
        "key": "consent",
        "title": "Terms & Conditions",
        "components": [
          {"type": "checkbox", "key": "agreeTerms", "label": "I agree to the Terms of Service", "validate": {"required": true}},
          {"type": "checkbox", "key": "agreePrivacy", "label": "I agree to the Privacy Policy", "validate": {"required": true}}
        ]
      }
    ]
  }'),
  json('{"submitButtonText": "Create Account", "successMessage": "Account created! Please check your email."}'),
  1, 1, 1737767400000, 1737767400000
);

-- Event registration form
INSERT INTO forms (id, name, display_name, category, formio_schema, settings, is_active, is_public, created_at, updated_at)
VALUES (
  'reg-002',
  'event_registration',
  'Event Registration',
  'events',
  json('{
    "display": "form",
    "components": [
      {"type": "textfield", "key": "attendeeName", "label": "Full Name", "validate": {"required": true}},
      {"type": "email", "key": "email", "label": "Email", "validate": {"required": true}},
      {"type": "select", "key": "ticketType", "label": "Ticket Type", "data": {"values": [
        {"label": "General Admission - $50", "value": "general"},
        {"label": "VIP - $150", "value": "vip"}
      ]}, "validate": {"required": true}},
      {"type": "number", "key": "quantity", "label": "Number of Tickets", "defaultValue": 1, "validate": {"required": true, "min": 1, "max": 10}}
    ]
  }'),
  json('{"submitButtonText": "Register Now", "successMessage": "Registration confirmed! Check your email for tickets."}'),
  1, 1, 1737767400000, 1737767400000
);
```

### 2. Use in Code

```typescript
// Get form and display
const form = await db.prepare('SELECT * FROM forms WHERE name = ?')
  .bind('user_registration')
  .first()

const schema = JSON.parse(form.formio_schema)
const settings = JSON.parse(form.settings)

// Render with Form.io
Formio.createForm(element, schema).then(form => {
  form.on('submit', async (submission) => {
    await fetch(`/api/forms/${form.id}/submit`, {
      method: 'POST',
      body: JSON.stringify(submission)
    })
  })
})
```

---

## 🎯 Best Practices

### 1. Use Migrations for System Forms

Forms that are **core to your app** (login, registration, checkout) should be created in migrations:

```sql
-- migrations/032_core_forms.sql
INSERT INTO forms (...) VALUES (...);
```

### 2. Use API for User-Generated Forms

Forms created by **users** should use the API:

```typescript
const response = await fetch('/admin/forms', {
  method: 'POST',
  body: formData
})
```

### 3. Validate Form Names

Always validate form names before creation:

```typescript
const isValid = /^[a-z0-9_]+$/.test(formName)
if (!isValid) {
  throw new Error('Invalid form name')
}
```

### 4. Start with Empty Schema

Create forms with empty schema, then build in the UI:

```typescript
const schema = { components: [] }  // Let users build visually
```

### 5. Version Control Form Schemas

Store important form schemas in version control:

```typescript
// schemas/contact-form.json
{
  "display": "form",
  "components": [...]
}
```

---

## 🔍 Query Forms

### Get Form by Name

```typescript
const form = await db.prepare('SELECT * FROM forms WHERE name = ?')
  .bind('contact_form')
  .first()
```

### Get All Forms in Category

```typescript
const forms = await db.prepare('SELECT * FROM forms WHERE category = ?')
  .bind('customer_service')
  .all()
```

### Get Active Public Forms

```typescript
const forms = await db.prepare(
  'SELECT * FROM forms WHERE is_active = 1 AND is_public = 1'
).all()
```

---

## 📚 Resources

- **Form.io Schema Docs:** https://formio.github.io/formio.js/docs/
- **Component Reference:** `/docs/FORMIO_COMPONENTS_CONFIG.md`
- **Wizard Forms:** `/docs/FORMIO_WIZARD_FORMS.md`
- **Admin Forms Route:** `/packages/core/src/routes/admin-forms.ts`
- **Public Forms Route:** `/packages/core/src/routes/public-forms.ts`

---

## Summary

✅ **API Creation** - `POST /admin/forms` with auth  
✅ **Database Direct** - SQL migrations for system forms  
✅ **Programmatic** - TypeScript service functions  
✅ **Same as Collections** - Multiple creation methods  
✅ **Full Schema Control** - Define Form.io schemas in code  
✅ **Wizard Support** - Create multi-page wizards programmatically  

**Ready to build?** Create your first form via API or migration! 🚀
