# Using SonicJS Forms in Headless Frontends

**Complete guide for integrating SonicJS forms into any modern frontend framework: React, Astro, Angular, Vue, Svelte, Next.js, and more.**

---

## 🎯 Overview

SonicJS forms are **fully headless-ready** with a JSON API that returns Form.io schemas. You can:

✅ **Fetch form schemas** via REST API  
✅ **Render forms** using Form.io React/Angular/Vue components  
✅ **Submit data** back to SonicJS  
✅ **Use any frontend framework** - React, Astro, Angular, Vue, Svelte, etc.  
✅ **Full TypeScript support**  

---

## 📡 API Endpoints

### Get Form Schema (JSON)

**Endpoint:** `GET /forms/:identifier/schema`  
**Auth:** No authentication required for public forms  
**Identifier:** Form ID (UUID) or form name

#### Response Format

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "contact_form",
  "displayName": "Contact Us",
  "description": "Customer contact form",
  "category": "customer_service",
  "schema": {
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
      }
    ]
  },
  "settings": {
    "submitButtonText": "Send Message",
    "successMessage": "Thank you for contacting us!",
    "requireAuth": false
  },
  "submitUrl": "/api/forms/550e8400-e29b-41d4-a716-446655440000/submit"
}
```

### Submit Form Data

**Endpoint:** `POST /api/forms/:identifier/submit`  
**Content-Type:** `application/json`  
**Auth:** Optional (depends on form settings)

#### Request Body

```json
{
  "data": {
    "name": "John Doe",
    "email": "john@example.com",
    "message": "Hello!"
  }
}
```

#### Response

```json
{
  "success": true,
  "submissionId": "660e8400-e29b-41d4-a716-446655440001",
  "message": "Form submitted successfully"
}
```

---

## ⚛️ React Integration

### Installation

```bash
npm install @formio/react
```

### Basic React Component

```tsx
// components/SonicForm.tsx
import { Form } from '@formio/react'
import { useState, useEffect } from 'react'

interface SonicFormProps {
  formName: string
  apiUrl?: string
}

export function SonicForm({ formName, apiUrl = 'http://localhost:8787' }: SonicFormProps) {
  const [formSchema, setFormSchema] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [submitted, setSubmitted] = useState(false)

  useEffect(() => {
    // Fetch form schema
    fetch(`${apiUrl}/forms/${formName}/schema`)
      .then(res => res.json())
      .then(data => {
        setFormSchema(data)
        setLoading(false)
      })
      .catch(err => {
        setError('Failed to load form')
        setLoading(false)
      })
  }, [formName, apiUrl])

  const handleSubmit = async (submission: any) => {
    try {
      const response = await fetch(`${apiUrl}${formSchema.submitUrl}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission)
      })

      if (response.ok) {
        setSubmitted(true)
      } else {
        alert('Submission failed')
      }
    } catch (error) {
      alert('Error submitting form')
    }
  }

  if (loading) return <div>Loading form...</div>
  if (error) return <div>Error: {error}</div>
  if (submitted) return <div>{formSchema.settings.successMessage}</div>

  return (
    <div>
      <h1>{formSchema.displayName}</h1>
      {formSchema.description && <p>{formSchema.description}</p>}
      
      <Form 
        form={formSchema.schema} 
        onSubmit={handleSubmit}
      />
    </div>
  )
}
```

### Usage in React App

```tsx
// pages/Contact.tsx
import { SonicForm } from '../components/SonicForm'

export default function ContactPage() {
  return (
    <div className="container">
      <SonicForm formName="contact_form" />
    </div>
  )
}
```

### Next.js Example (App Router)

```tsx
// app/contact/page.tsx
'use client'

import { SonicForm } from '@/components/SonicForm'

export default function ContactPage() {
  return (
    <main className="max-w-4xl mx-auto p-8">
      <SonicForm 
        formName="contact_form"
        apiUrl={process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8787'}
      />
    </main>
  )
}
```

### React Hook for Forms

```tsx
// hooks/useSonicForm.ts
import { useState, useEffect } from 'react'

export function useSonicForm(formName: string, apiUrl: string = 'http://localhost:8787') {
  const [formData, setFormData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch(`${apiUrl}/forms/${formName}/schema`)
      .then(res => res.json())
      .then(data => {
        setFormData(data)
        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [formName, apiUrl])

  const submitForm = async (data: any) => {
    const response = await fetch(`${apiUrl}${formData.submitUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data })
    })
    return response.json()
  }

  return { formData, loading, error, submitForm }
}

// Usage:
// const { formData, loading, submitForm } = useSonicForm('contact_form')
```

---

## 🚀 Astro Integration

### Basic Astro Component

```astro
---
// pages/contact.astro
const API_URL = import.meta.env.PUBLIC_API_URL || 'http://localhost:8787'
const formName = 'contact_form'

// Fetch form schema at build time (SSG) or request time (SSR)
const response = await fetch(`${API_URL}/forms/${formName}/schema`)
const formData = await response.json()
---

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{formData.displayName}</title>
  <link rel="stylesheet" href="https://cdn.form.io/formiojs/formio.full.min.css">
</head>
<body>
  <div class="container">
    <h1>{formData.displayName}</h1>
    {formData.description && <p>{formData.description}</p>}
    
    <div id="formio-form"></div>
    <div id="success-message" style="display: none;">
      {formData.settings.successMessage}
    </div>
  </div>

  <script src="https://cdn.form.io/formiojs/formio.full.min.js"></script>
  <script define:vars={{ formData, API_URL }}>
    Formio.createForm(
      document.getElementById('formio-form'),
      formData.schema
    ).then(form => {
      form.on('submit', async (submission) => {
        try {
          const response = await fetch(`${API_URL}${formData.submitUrl}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(submission)
          })

          if (response.ok) {
            document.getElementById('formio-form').style.display = 'none'
            document.getElementById('success-message').style.display = 'block'
          }
        } catch (error) {
          alert('Submission failed')
        }
      })
    })
  </script>
</body>
</html>
```

### Astro + React Island

```astro
---
// pages/contact.astro
import { SonicForm } from '../components/SonicForm'

const API_URL = import.meta.env.PUBLIC_API_URL || 'http://localhost:8787'
---

<Layout>
  <main>
    <!-- React component as island (client:load for interactivity) -->
    <SonicForm 
      formName="contact_form" 
      apiUrl={API_URL}
      client:load 
    />
  </main>
</Layout>
```

---

## 🅰️ Angular Integration

### Installation

```bash
npm install @formio/angular
```

### Angular Component

```typescript
// contact-form.component.ts
import { Component, OnInit } from '@angular/core'
import { HttpClient } from '@angular/common/http'

@Component({
  selector: 'app-contact-form',
  template: `
    <div class="container">
      <h1>{{ formData?.displayName }}</h1>
      <p *ngIf="formData?.description">{{ formData.description }}</p>
      
      <formio 
        *ngIf="formData" 
        [form]="formData.schema"
        (submit)="onSubmit($event)"
      ></formio>
      
      <div *ngIf="submitted" class="success">
        {{ formData?.settings?.successMessage }}
      </div>
    </div>
  `
})
export class ContactFormComponent implements OnInit {
  formData: any
  submitted = false
  private apiUrl = 'http://localhost:8787'

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.http.get(`${this.apiUrl}/forms/contact_form/schema`)
      .subscribe(data => {
        this.formData = data
      })
  }

  onSubmit(submission: any) {
    this.http.post(`${this.apiUrl}${this.formData.submitUrl}`, submission)
      .subscribe(
        () => this.submitted = true,
        error => alert('Submission failed')
      )
  }
}
```

### Angular Module

```typescript
// app.module.ts
import { FormioModule } from '@formio/angular'

@NgModule({
  imports: [
    BrowserModule,
    HttpClientModule,
    FormioModule  // Add Form.io module
  ],
  declarations: [ContactFormComponent]
})
export class AppModule {}
```

---

## 💚 Vue.js Integration

### Installation

```bash
npm install @formio/vue
```

### Vue Component

```vue
<!-- ContactForm.vue -->
<template>
  <div class="container">
    <h1 v-if="formData">{{ formData.displayName }}</h1>
    <p v-if="formData?.description">{{ formData.description }}</p>
    
    <Formio 
      v-if="formData && !submitted"
      :form="formData.schema"
      @submit="handleSubmit"
    />
    
    <div v-if="submitted" class="success">
      {{ formData?.settings?.successMessage }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Form as Formio } from '@formio/vue'

const props = defineProps<{
  formName: string
  apiUrl?: string
}>()

const apiUrl = props.apiUrl || 'http://localhost:8787'
const formData = ref<any>(null)
const submitted = ref(false)

onMounted(async () => {
  const response = await fetch(`${apiUrl}/forms/${props.formName}/schema`)
  formData.value = await response.json()
})

const handleSubmit = async (submission: any) => {
  try {
    const response = await fetch(`${apiUrl}${formData.value.submitUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(submission)
    })
    
    if (response.ok) {
      submitted.value = true
    }
  } catch (error) {
    alert('Submission failed')
  }
}
</script>

<style scoped>
.success {
  padding: 1rem;
  background: #d1fae5;
  border: 1px solid #10b981;
  border-radius: 0.5rem;
  color: #065f46;
}
</style>
```

### Usage in Vue App

```vue
<!-- pages/Contact.vue -->
<template>
  <ContactForm formName="contact_form" />
</template>

<script setup>
import ContactForm from '@/components/ContactForm.vue'
</script>
```

---

## 🔶 Svelte Integration

### Svelte Component

```svelte
<!-- ContactForm.svelte -->
<script lang="ts">
  import { onMount } from 'svelte'
  
  export let formName: string
  export let apiUrl: string = 'http://localhost:8787'
  
  let formData: any = null
  let formElement: HTMLDivElement
  let submitted = false
  
  onMount(async () => {
    // Fetch form schema
    const response = await fetch(`${apiUrl}/forms/${formName}/schema`)
    formData = await response.json()
    
    // Load Form.io script
    const script = document.createElement('script')
    script.src = 'https://cdn.form.io/formiojs/formio.full.min.js'
    script.onload = () => initializeForm()
    document.head.appendChild(script)
  })
  
  function initializeForm() {
    // @ts-ignore
    Formio.createForm(formElement, formData.schema).then((form: any) => {
      form.on('submit', async (submission: any) => {
        try {
          const response = await fetch(`${apiUrl}${formData.submitUrl}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(submission)
          })
          
          if (response.ok) {
            submitted = true
          }
        } catch (error) {
          alert('Submission failed')
        }
      })
    })
  }
</script>

<div class="container">
  {#if formData}
    <h1>{formData.displayName}</h1>
    {#if formData.description}
      <p>{formData.description}</p>
    {/if}
    
    {#if !submitted}
      <div bind:this={formElement}></div>
    {:else}
      <div class="success">
        {formData.settings.successMessage}
      </div>
    {/if}
  {/if}
</div>

<style>
  .success {
    padding: 1rem;
    background: #d1fae5;
    border: 1px solid #10b981;
    border-radius: 0.5rem;
    color: #065f46;
  }
</style>
```

---

## 🔧 Vanilla JavaScript

For frameworks not listed or custom implementations:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Contact Form</title>
  <link rel="stylesheet" href="https://cdn.form.io/formiojs/formio.full.min.css">
</head>
<body>
  <div id="app">
    <h1 id="form-title"></h1>
    <p id="form-description"></p>
    <div id="formio-form"></div>
    <div id="success-message" style="display: none;"></div>
  </div>

  <script src="https://cdn.form.io/formiojs/formio.full.min.js"></script>
  <script>
    const API_URL = 'http://localhost:8787'
    const FORM_NAME = 'contact_form'

    // Fetch form schema
    fetch(`${API_URL}/forms/${FORM_NAME}/schema`)
      .then(res => res.json())
      .then(formData => {
        // Update UI
        document.getElementById('form-title').textContent = formData.displayName
        document.getElementById('form-description').textContent = formData.description || ''
        document.getElementById('success-message').textContent = formData.settings.successMessage

        // Render form
        Formio.createForm(
          document.getElementById('formio-form'),
          formData.schema
        ).then(form => {
          form.on('submit', async (submission) => {
            try {
              const response = await fetch(`${API_URL}${formData.submitUrl}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(submission)
              })

              if (response.ok) {
                document.getElementById('formio-form').style.display = 'none'
                document.getElementById('success-message').style.display = 'block'
              }
            } catch (error) {
              alert('Submission failed')
            }
          })
        })
      })
  </script>
</body>
</html>
```

---

## 🎨 Styling & Customization

### Custom CSS

```css
/* Override Form.io styles */
.formio-component-label {
  font-weight: 600;
  color: #374151;
}

.formio-component-textfield input,
.formio-component-email input {
  border: 1px solid #d1d5db;
  border-radius: 0.375rem;
  padding: 0.5rem 0.75rem;
}

.formio-component-button button {
  background: #3b82f6;
  color: white;
  padding: 0.75rem 1.5rem;
  border-radius: 0.5rem;
  font-weight: 600;
}

.formio-component-button button:hover {
  background: #2563eb;
}
```

### Tailwind CSS Integration

```tsx
// Wrapper component with Tailwind
export function StyledSonicForm({ formName }: { formName: string }) {
  return (
    <div className="max-w-2xl mx-auto p-8 bg-white rounded-xl shadow-lg">
      <SonicForm formName={formName} />
    </div>
  )
}
```

---

## 🔐 Authentication

### Authenticated Requests

If your form requires authentication:

```typescript
// React example with auth
const handleSubmit = async (submission: any) => {
  // Session is in HTTP-only cookie; use credentials: 'include' so cookie is sent
  
  const response = await fetch(`${apiUrl}${formData.submitUrl}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}` // Add auth header
    },
    body: JSON.stringify(submission)
  })
  
  if (response.ok) {
    setSubmitted(true)
  } else if (response.status === 401) {
    alert('Please log in to submit this form')
  }
}
```

---

## 📊 Advanced Features

### Multi-Page Wizards

Wizards work automatically with Form.io components:

```tsx
// React - Wizard forms render with navigation automatically
<Form form={formSchema.schema} onSubmit={handleSubmit} />

// The schema.display === 'wizard' automatically enables:
// - Previous/Next buttons
// - Progress indicator
// - Per-page validation
```

### File Uploads

File components work with your R2 storage:

```typescript
// The file component automatically handles uploads to your configured storage
{
  "type": "file",
  "key": "resume",
  "label": "Upload Resume",
  "storage": "r2"  // Uses your R2 bucket
}
```

### Conditional Logic

Form.io conditional logic works client-side:

```json
{
  "type": "textfield",
  "key": "businessName",
  "label": "Business Name",
  "conditional": {
    "show": true,
    "when": "userType",
    "eq": "business"
  }
}
```

---

## 🧪 TypeScript Support

### Type Definitions

```typescript
// types/sonic-forms.ts

export interface FormSchema {
  display: 'form' | 'wizard'
  components: FormComponent[]
}

export interface FormComponent {
  type: string
  key: string
  label: string
  validate?: {
    required?: boolean
    [key: string]: any
  }
  [key: string]: any
}

export interface SonicFormData {
  id: string
  name: string
  displayName: string
  description?: string
  category: string
  schema: FormSchema
  settings: {
    submitButtonText: string
    successMessage: string
    requireAuth: boolean
    emailNotifications?: boolean
    [key: string]: any
  }
  submitUrl: string
}

export interface FormSubmission {
  data: Record<string, any>
}

export interface SubmissionResponse {
  success: boolean
  submissionId: string
  message: string
}
```

### Typed React Component

```tsx
// components/SonicForm.tsx
import type { SonicFormData, FormSubmission } from '@/types/sonic-forms'

interface Props {
  formName: string
  apiUrl?: string
  onSuccess?: (submissionId: string) => void
}

export function SonicForm({ formName, apiUrl = 'http://localhost:8787', onSuccess }: Props) {
  const [formData, setFormData] = useState<SonicFormData | null>(null)
  
  const handleSubmit = async (submission: FormSubmission) => {
    const response = await fetch(`${apiUrl}${formData!.submitUrl}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(submission)
    })
    
    const result: SubmissionResponse = await response.json()
    
    if (result.success && onSuccess) {
      onSuccess(result.submissionId)
    }
  }
  
  // ... rest of component
}
```

---

## 🚦 Error Handling

### Robust Error Handling

```typescript
async function fetchForm(formName: string) {
  try {
    const response = await fetch(`${API_URL}/forms/${formName}/schema`)
    
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Form not found')
      }
      throw new Error('Failed to load form')
    }
    
    return await response.json()
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('Network error - check your connection')
    }
    throw error
  }
}

// Usage with error states
const [error, setError] = useState<string | null>(null)

useEffect(() => {
  fetchForm('contact_form')
    .then(setFormData)
    .catch(err => setError(err.message))
}, [])
```

---

## 🧪 Testing

### Unit Test Example (React + Jest)

```typescript
// SonicForm.test.tsx
import { render, screen, waitFor } from '@testing-library/react'
import { SonicForm } from './SonicForm'

global.fetch = jest.fn()

describe('SonicForm', () => {
  beforeEach(() => {
    (fetch as jest.Mock).mockClear()
  })

  it('fetches and renders form', async () => {
    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        displayName: 'Contact Form',
        schema: { components: [] },
        settings: {}
      })
    })

    render(<SonicForm formName="contact_form" />)

    await waitFor(() => {
      expect(screen.getByText('Contact Form')).toBeInTheDocument()
    })

    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:8787/forms/contact_form/schema'
    )
  })
})
```

---

## 📚 Best Practices

### 1. Environment Variables

```bash
# .env
VITE_API_URL=https://api.yoursite.com
NEXT_PUBLIC_API_URL=https://api.yoursite.com
PUBLIC_API_URL=https://api.yoursite.com  # Astro
```

### 2. Loading States

Always show loading indicators:

```tsx
if (loading) {
  return <Spinner />
}
```

### 3. Error Boundaries

Wrap forms in error boundaries:

```tsx
<ErrorBoundary fallback={<ErrorMessage />}>
  <SonicForm formName="contact_form" />
</ErrorBoundary>
```

### 4. Caching

Cache form schemas for better performance:

```typescript
const formCache = new Map()

async function getCachedForm(formName: string) {
  if (formCache.has(formName)) {
    return formCache.get(formName)
  }
  
  const form = await fetchForm(formName)
  formCache.set(formName, form)
  return form
}
```

### 5. Validation Feedback

Provide clear validation feedback:

```tsx
<Form 
  form={schema}
  onSubmit={handleSubmit}
  onError={(errors) => {
    console.error('Validation errors:', errors)
    alert('Please fix the errors in the form')
  }}
/>
```

---

## 🔗 Resources

- **Form.io React Docs:** https://github.com/formio/react
- **Form.io Angular Docs:** https://github.com/formio/angular
- **Form.io Vue Docs:** https://github.com/formio/vue
- **API Reference:** `/docs/FORMS_API.md`
- **Component Config:** `/docs/FORMIO_COMPONENTS_CONFIG.md`
- **Wizard Forms:** `/docs/FORMIO_WIZARD_FORMS.md`

---

## Summary

✅ **Universal JSON API** - Works with any frontend framework  
✅ **Form.io Libraries** - React, Angular, Vue official support  
✅ **Vanilla JS** - Works without frameworks  
✅ **TypeScript Support** - Full type definitions  
✅ **SSR/SSG Ready** - Fetch at build time or request time  
✅ **Authentication** - Optional auth support  
✅ **File Uploads** - R2 integration works seamlessly  
✅ **Wizards** - Multi-page forms work automatically  

**Your forms are now truly headless!** 🚀
