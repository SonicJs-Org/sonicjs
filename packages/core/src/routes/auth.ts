import { Hono } from 'hono'
// import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { setCookie } from 'hono/cookie'
import { html } from 'hono/html'
import { AuthManager, requireAuth, generateCsrfToken } from '../middleware'
import { renderLoginPage, LoginPageData } from '../templates/pages/auth-login.template'
import { renderRegisterPage, RegisterPageData } from '../templates/pages/auth-register.template'
import { getCacheService, CACHE_CONFIGS } from '../services'
import { authValidationService, isRegistrationEnabled, isFirstUserRegistration } from '../services/auth-validation'
import type { RegistrationData } from '../services/auth-validation'
import type { Bindings, Variables } from '../app'

const JWT_SECRET_FALLBACK = 'your-super-secret-jwt-key-change-in-production'

/** Set a signed CSRF cookie alongside the auth cookie on login/register. */
async function setCsrfCookie(c: any): Promise<void> {
  const secret = c.env?.JWT_SECRET || JWT_SECRET_FALLBACK
  const isDev = c.env?.ENVIRONMENT === 'development' || !c.env?.ENVIRONMENT
  const csrfToken = await generateCsrfToken(secret)
  setCookie(c, 'csrf_token', csrfToken, {
    httpOnly: false,
    secure: !isDev,
    sameSite: 'Strict',
    path: '/',
    maxAge: 86400,
  })
}

/** Clear the CSRF cookie on logout. */
function clearCsrfCookie(c: any): void {
  setCookie(c, 'csrf_token', '', {
    httpOnly: false,
    secure: false,
    sameSite: 'Strict',
    path: '/',
    maxAge: 0,
  })
}

const authRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Login page (HTML form)
authRoutes.get('/login', async (c) => {
  const error = c.req.query('error')
  const message = c.req.query('message')
  
  const pageData: LoginPageData = {
    error: error || undefined,
    message: message || undefined,
    version: c.get('appVersion')
  }
  
  // Check if demo login plugin is active
  const db = c.env.DB
  let demoLoginActive = false
  try {
    const plugin = await db.prepare('SELECT * FROM plugins WHERE id = ? AND status = ?')
      .bind('demo-login-prefill', 'active')
      .first()
    demoLoginActive = !!plugin
  } catch (error) {
    // Ignore database errors - plugin system might not be initialized
  }
  
  return c.html(renderLoginPage(pageData, demoLoginActive))
})

// Registration page (HTML form)
authRoutes.get('/register', async (c) => {
  const db = c.env.DB

  // Check if this is the first user (bootstrap scenario) - always allow
  const isFirstUser = await isFirstUserRegistration(db)

  // If not first user, check if registration is enabled
  if (!isFirstUser) {
    const registrationEnabled = await isRegistrationEnabled(db)
    if (!registrationEnabled) {
      return c.redirect('/auth/login?error=Registration is currently disabled')
    }
  }

  const error = c.req.query('error')

  const pageData: RegisterPageData = {
    error: error || undefined
  }

  return c.html(renderRegisterPage(pageData))
})

// Login schema
const loginSchema = z.object({
  email: z.string().email('Valid email is required'),
  password: z.string().min(1, 'Password is required')
})

// Register new user
authRoutes.post('/register',
  async (c) => {
    try {
      const db = c.env.DB

      // Check if this is the first user (bootstrap scenario) - always allow
      const isFirstUser = await isFirstUserRegistration(db)

      // If not first user, check if registration is enabled
      if (!isFirstUser) {
        const registrationEnabled = await isRegistrationEnabled(db)
        if (!registrationEnabled) {
          return c.json({ error: 'Registration is currently disabled' }, 403)
        }
      }

      // Parse JSON with error handling
      let requestData
      try {
        requestData = await c.req.json()
      } catch (parseError) {
        return c.json({ error: 'Invalid JSON in request body' }, 400)
      }

      // Build and validate using dynamic schema
      const validationSchema = await authValidationService.buildRegistrationSchema(db)

      let validatedData: RegistrationData
      try {
        validatedData = await validationSchema.parseAsync(requestData)
      } catch (validationError: any) {
        return c.json({
          error: 'Validation failed',
          details: validationError.issues?.map((e: any) => e.message) || [validationError.message || 'Invalid request data']
        }, 400)
      }

      // Extract fields with defaults for optional ones
      const email = validatedData.email
      const password = validatedData.password
      const username = validatedData.username || authValidationService.generateDefaultValue('username', validatedData)
      const firstName = validatedData.firstName || authValidationService.generateDefaultValue('firstName', validatedData)
      const lastName = validatedData.lastName || authValidationService.generateDefaultValue('lastName', validatedData)

      // Normalize email to lowercase
      const normalizedEmail = email.toLowerCase()
      
      // Check if user already exists
      const existingUser = await db.prepare('SELECT id FROM users WHERE email = ? OR username = ?')
        .bind(normalizedEmail, username)
        .first()
      
      if (existingUser) {
        return c.json({ error: 'User with this email or username already exists' }, 400)
      }
      
      // Hash password
      const passwordHash = await AuthManager.hashPassword(password)
      
      // Create user
      const userId = crypto.randomUUID()
      const now = new Date()
      
      await db.prepare(`
        INSERT INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        userId,
        normalizedEmail,
        username,
        firstName,
        lastName,
        passwordHash,
        'viewer', // Default role
        1, // is_active
        now.getTime(),
        now.getTime()
      ).run()
      
      // Generate JWT token
      const token = await AuthManager.generateToken(userId, normalizedEmail, 'viewer', c.env.JWT_SECRET)
      
      // Set HTTP-only cookie
      setCookie(c, 'auth_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: 60 * 60 * 24 // 24 hours
      })

      // Set CSRF cookie for browser sessions
      await setCsrfCookie(c)

      return c.json({
        user: {
          id: userId,
          email: normalizedEmail,
          username,
          firstName,
          lastName,
          role: 'viewer'
        },
        token
      }, 201)
    } catch (error) {
      console.error('Registration error:', error)
      // Return validation errors as 400, other errors as 500
      if (error instanceof Error && error.message.includes('validation')) {
        return c.json({ error: error.message }, 400)
      }
      return c.json({
        error: 'Registration failed',
        details: error instanceof Error ? error.message : String(error)
      }, 500)
    }
  }
)

// Login user
authRoutes.post('/login', async (c) => {
    try {
      const body = await c.req.json()
      const validation = loginSchema.safeParse(body)
      if (!validation.success) {
        return c.json({ error: 'Validation failed', details: validation.error.issues }, 400)
      }
      const { email, password } = validation.data
      const db = c.env.DB
      
      // Normalize email to lowercase
      const normalizedEmail = email.toLowerCase()
      
      // Find user with caching
      const cache = getCacheService(CACHE_CONFIGS.user!)
      let user = await cache.get<any>(cache.generateKey('user', `email:${normalizedEmail}`))

      if (!user) {
        user = await db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1')
          .bind(normalizedEmail)
          .first() as any

        if (user) {
          // Cache the user for faster subsequent lookups
          await cache.set(cache.generateKey('user', `email:${normalizedEmail}`), user)
          await cache.set(cache.generateKey('user', user.id), user)
        }
      }

      if (!user) {
        return c.json({ error: 'Invalid email or password' }, 401)
      }
      
      // Verify password
      const isValidPassword = await AuthManager.verifyPassword(password, user.password_hash)
      if (!isValidPassword) {
        return c.json({ error: 'Invalid email or password' }, 401)
      }
      
      // Generate JWT token
      const token = await AuthManager.generateToken(user.id, user.email, user.role, c.env.JWT_SECRET)

      // Set HTTP-only cookie
      setCookie(c, 'auth_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: 60 * 60 * 24 // 24 hours
      })

      // Set CSRF cookie for browser sessions
      await setCsrfCookie(c)

      // Update last login
      await db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?')
        .bind(new Date().getTime(), user.id)
        .run()

      // Invalidate user cache on login
      await cache.delete(cache.generateKey('user', user.id))
      await cache.delete(cache.generateKey('user', `email:${normalizedEmail}`))

      return c.json({
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role
        },
        token
      })
    } catch (error) {
      console.error('Login error:', error)
      return c.json({ error: 'Login failed' }, 500)
    }
})

// Logout user (both GET and POST for convenience)
authRoutes.post('/logout', (c) => {
  // Clear the auth cookie
  setCookie(c, 'auth_token', '', {
    httpOnly: true,
    secure: false, // Set to true in production with HTTPS
    sameSite: 'Strict',
    maxAge: 0 // Expire immediately
  })
  clearCsrfCookie(c)

  return c.json({ message: 'Logged out successfully' })
})

authRoutes.get('/logout', (c) => {
  // Clear the auth cookie
  setCookie(c, 'auth_token', '', {
    httpOnly: true,
    secure: false, // Set to true in production with HTTPS
    sameSite: 'Strict',
    maxAge: 0 // Expire immediately
  })
  clearCsrfCookie(c)

  return c.redirect('/auth/login?message=You have been logged out successfully')
})

// Get current user
authRoutes.get('/me', requireAuth(), async (c) => {
  try {
    // This would need the auth middleware applied
    const user = c.get('user')
    
    if (!user) {
      return c.json({ error: 'Not authenticated' }, 401)
    }
    
    const db = c.env.DB
    const userData = await db.prepare('SELECT id, email, username, first_name, last_name, role, created_at FROM users WHERE id = ?')
      .bind(user.userId)
      .first()
    
    if (!userData) {
      return c.json({ error: 'User not found' }, 404)
    }
    
    return c.json({ user: userData })
  } catch (error) {
    console.error('Get user error:', error)
    return c.json({ error: 'Failed to get user' }, 500)
  }
})

// Refresh token
authRoutes.post('/refresh', requireAuth(), async (c) => {
  try {
    const user = c.get('user')
    
    if (!user) {
      return c.json({ error: 'Not authenticated' }, 401)
    }
    
    // Generate new token
    const token = await AuthManager.generateToken(user.userId, user.email, user.role, c.env.JWT_SECRET)
    
    // Set new cookie
    setCookie(c, 'auth_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 60 * 60 * 24 // 24 hours
    })

    // Set CSRF cookie for browser sessions
    await setCsrfCookie(c)

    return c.json({ token })
  } catch (error) {
    console.error('Token refresh error:', error)
    return c.json({ error: 'Token refresh failed' }, 500)
  }
})

// Form-based registration handler (for HTML forms)
authRoutes.post('/register/form', async (c) => {
  try {
    const db = c.env.DB

    // Check if this is the first user (bootstrap scenario) - always allow
    const isFirstUser = await isFirstUserRegistration(db)

    // If not first user, check if registration is enabled
    if (!isFirstUser) {
      const registrationEnabled = await isRegistrationEnabled(db)
      if (!registrationEnabled) {
        return c.html(html`
          <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            Registration is currently disabled. Please contact an administrator.
          </div>
        `)
      }
    }

    const formData = await c.req.formData()

    // Extract form data
    const requestData = {
      email: formData.get('email') as string,
      password: formData.get('password') as string,
      username: formData.get('username') as string,
      firstName: formData.get('firstName') as string,
      lastName: formData.get('lastName') as string,
    }

    // Normalize email to lowercase
    const normalizedEmail = requestData.email?.toLowerCase()
    requestData.email = normalizedEmail

    // Build and validate using dynamic schema
    const validationSchema = await authValidationService.buildRegistrationSchema(db)
    const validation = await validationSchema.safeParseAsync(requestData)

    if (!validation.success) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          ${validation.error.issues.map((err: { message: string }) => err.message).join(', ')}
        </div>
      `)
    }

      const validatedData: RegistrationData = validation.data

    // Extract fields with defaults for optional ones
    // const email = validatedData.email
    const password = validatedData.password
    const username = validatedData.username || authValidationService.generateDefaultValue('username', validatedData)
    const firstName = validatedData.firstName || authValidationService.generateDefaultValue('firstName', validatedData)
    const lastName = validatedData.lastName || authValidationService.generateDefaultValue('lastName', validatedData)
    
    // Check if user already exists
    const existingUser = await db.prepare('SELECT id FROM users WHERE email = ? OR username = ?')
      .bind(normalizedEmail, username)
      .first()
    
    if (existingUser) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          User with this email or username already exists
        </div>
      `)
    }
    
    // Hash password
    const passwordHash = await AuthManager.hashPassword(password)

    // Determine role: first user gets admin, others get viewer
    const role = isFirstUser ? 'admin' : 'viewer'

    // Create user
    const userId = crypto.randomUUID()
    const now = new Date()

    await db.prepare(`
      INSERT INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      userId,
      normalizedEmail,
      username,
      firstName,
      lastName,
      passwordHash,
      role,
      1, // is_active
      now.getTime(),
      now.getTime()
    ).run()

    // Generate JWT token
    const token = await AuthManager.generateToken(userId, normalizedEmail, role, c.env.JWT_SECRET)

    // Set HTTP-only cookie
    setCookie(c, 'auth_token', token, {
      httpOnly: true,
      secure: false, // Set to true in production with HTTPS
      sameSite: 'Strict',
      maxAge: 60 * 60 * 24 // 24 hours
    })

    // Set CSRF cookie for browser sessions
    await setCsrfCookie(c)

    // Redirect based on role
    const redirectUrl = role === 'admin' ? '/admin/dashboard' : '/admin/dashboard'

    return c.html(html`
      <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
        Account created successfully! Redirecting...
        <script>
          setTimeout(() => {
            window.location.href = '${redirectUrl}';
          }, 2000);
        </script>
      </div>
    `)
  } catch (error) {
    console.error('Registration error:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Registration failed. Please try again.
      </div>
    `)
  }
})

// Form-based login handler (for HTML forms)
authRoutes.post('/login/form', async (c) => {
  try {
    const formData = await c.req.formData()
    const email = formData.get('email') as string
    const password = formData.get('password') as string

    // Normalize email to lowercase
    const normalizedEmail = email.toLowerCase()

    // Validate the data
    const validation = loginSchema.safeParse({ email: normalizedEmail, password })

    if (!validation.success) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          ${validation.error.issues.map((err: { message: string }) => err.message).join(', ')}
        </div>
      `)
    }

    const db = c.env.DB
    
    // Find user
    const user = await db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1')
      .bind(normalizedEmail)
      .first() as any
    
    if (!user) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Invalid email or password
        </div>
      `)
    }
    
    // Verify password
    const isValidPassword = await AuthManager.verifyPassword(password, user.password_hash)
    if (!isValidPassword) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Invalid email or password
        </div>
      `)
    }
    
    // Generate JWT token
    const token = await AuthManager.generateToken(user.id, user.email, user.role, c.env.JWT_SECRET)

    // Set HTTP-only cookie
    setCookie(c, 'auth_token', token, {
      httpOnly: true,
      secure: false, // Set to true in production with HTTPS
      sameSite: 'Strict',
      maxAge: 60 * 60 * 24 // 24 hours
    })

    // Set CSRF cookie for browser sessions
    await setCsrfCookie(c)

    // Update last login
    await db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?')
      .bind(new Date().getTime(), user.id)
      .run()
    
    return c.html(html`
      <div id="form-response">
        <div class="rounded-lg bg-green-100 dark:bg-lime-500/10 p-4 ring-1 ring-green-400 dark:ring-lime-500/20">
          <div class="flex items-start gap-x-3">
            <svg class="h-5 w-5 text-green-600 dark:text-lime-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <div class="flex-1">
              <p class="text-sm font-medium text-green-700 dark:text-lime-300">Login successful! Redirecting to admin dashboard...</p>
            </div>
          </div>
          <script>
            setTimeout(() => {
              window.location.href = '/admin/dashboard';
            }, 2000);
          </script>
        </div>
      </div>
    `)
  } catch (error) {
    console.error('Login error:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Login failed. Please try again.
      </div>
    `)
  }
})

// Test seeding endpoint (only for development/testing)
authRoutes.post('/seed-admin', async (c) => {
  try {
    const db = c.env.DB
    
    // First ensure the users table exists
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        password_hash TEXT,
        role TEXT NOT NULL DEFAULT 'viewer',
        avatar TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_login_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `).run()
    
    // Check if admin user already exists
    const existingAdmin = await db.prepare('SELECT id FROM users WHERE email = ? OR username = ?')
      .bind('admin@sonicjs.com', 'admin')
      .first()

    if (existingAdmin) {
      // Update the password to ensure it's correct for testing
      const passwordHash = await AuthManager.hashPassword('sonicjs!')
      await db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?')
        .bind(passwordHash, Date.now(), existingAdmin.id)
        .run()

      return c.json({
        message: 'Admin user already exists (password updated)',
        user: {
          id: existingAdmin.id,
          email: 'admin@sonicjs.com',
          username: 'admin',
          role: 'admin'
        }
      })
    }

    // Hash password
    const passwordHash = await AuthManager.hashPassword('sonicjs!')
    
    // Create admin user
    const userId = 'admin-user-id'
    const now = Date.now()
    const adminEmail = 'admin@sonicjs.com'.toLowerCase()
    
    await db.prepare(`
      INSERT INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      userId,
      adminEmail,
      'admin',
      'Admin',
      'User',
      passwordHash,
      'admin',
      1, // is_active
      now,
      now
    ).run()
    
    return c.json({ 
      message: 'Admin user created successfully',
      user: {
        id: userId,
        email: adminEmail,
        username: 'admin',
        role: 'admin'
      },
      passwordHash: passwordHash // For debugging
    })
  } catch (error) {
    console.error('Seed admin error:', error)
    return c.json({ error: 'Failed to create admin user', details: error instanceof Error ? error.message : String(error) }, 500)
  }
})


// Accept invitation page
authRoutes.get('/accept-invitation', async (c) => {
  try {
    const token = c.req.query('token')
    
    if (!token) {
      return c.html(`
        <html>
          <head><title>Invalid Invitation</title></head>
          <body>
            <h1>Invalid Invitation</h1>
            <p>The invitation link is invalid or has expired.</p>
            <a href="/auth/login">Go to Login</a>
          </body>
        </html>
      `)
    }

    const db = c.env.DB
    
    // Check if invitation token is valid
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name, role, invited_at
      FROM users 
      WHERE invitation_token = ? AND is_active = 0
    `)
    const invitedUser = await userStmt.bind(token).first() as any

    if (!invitedUser) {
      return c.html(`
        <html>
          <head><title>Invalid Invitation</title></head>
          <body>
            <h1>Invalid Invitation</h1>
            <p>The invitation link is invalid or has expired.</p>
            <a href="/auth/login">Go to Login</a>
          </body>
        </html>
      `)
    }

    // Check if invitation is expired (7 days)
    const invitationAge = Date.now() - invitedUser.invited_at
    const maxAge = 7 * 24 * 60 * 60 * 1000 // 7 days
    
    if (invitationAge > maxAge) {
      return c.html(`
        <html>
          <head><title>Invitation Expired</title></head>
          <body>
            <h1>Invitation Expired</h1>
            <p>This invitation has expired. Please contact your administrator for a new invitation.</p>
            <a href="/auth/login">Go to Login</a>
          </body>
        </html>
      `)
    }

    // Show invitation acceptance form
    return c.html(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Accept Invitation - SonicJS AI</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
          body {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            min-height: 100vh;
          }
        </style>
      </head>
      <body class="bg-gray-900 text-white">
        <div class="min-h-screen flex items-center justify-center px-4">
          <div class="max-w-md w-full space-y-8">
            <div class="text-center">
              <div class="mx-auto w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center mb-6">
                <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>
                </svg>
              </div>
              <h2 class="text-3xl font-bold">Accept Invitation</h2>
              <p class="mt-2 text-gray-400">Complete your account setup</p>
              <p class="mt-4 text-sm">
                You've been invited as <strong>${invitedUser.first_name} ${invitedUser.last_name}</strong><br>
                <span class="text-gray-400">${invitedUser.email}</span><br>
                <span class="text-blue-400 capitalize">${invitedUser.role}</span>
              </p>
            </div>

            <form method="POST" action="/auth/accept-invitation" class="mt-8 space-y-6">
              <input type="hidden" name="token" value="${token}" />
              
              <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Username</label>
                <input 
                  type="text" 
                  name="username" 
                  required
                  class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 transition-all"
                  placeholder="Enter your username"
                >
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Password</label>
                <input 
                  type="password" 
                  name="password" 
                  required
                  minlength="8"
                  class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 transition-all"
                  placeholder="Enter your password"
                >
                <p class="text-xs text-gray-400 mt-1">Password must be at least 8 characters long</p>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Confirm Password</label>
                <input 
                  type="password" 
                  name="confirm_password" 
                  required
                  minlength="8"
                  class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 transition-all"
                  placeholder="Confirm your password"
                >
              </div>

              <button 
                type="submit"
                class="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-xl hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 transition-all"
              >
                Accept Invitation & Create Account
              </button>
            </form>
          </div>
        </div>
      </body>
      </html>
    `)

  } catch (error) {
    console.error('Accept invitation page error:', error)
    return c.html(`
      <html>
        <head><title>Error</title></head>
        <body>
          <h1>Error</h1>
          <p>An error occurred while processing your invitation.</p>
          <a href="/auth/login">Go to Login</a>
        </body>
      </html>
    `)
  }
})

// Process invitation acceptance
authRoutes.post('/accept-invitation', async (c) => {
  try {
    const formData = await c.req.formData()
    const token = formData.get('token')?.toString()
    const username = formData.get('username')?.toString()?.trim()
    const password = formData.get('password')?.toString()
    const confirmPassword = formData.get('confirm_password')?.toString()

    if (!token || !username || !password || !confirmPassword) {
      return c.json({ error: 'All fields are required' }, 400)
    }

    if (password !== confirmPassword) {
      return c.json({ error: 'Passwords do not match' }, 400)
    }

    if (password.length < 8) {
      return c.json({ error: 'Password must be at least 8 characters long' }, 400)
    }

    const db = c.env.DB

    // Check if invitation token is valid
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name, role, invited_at
      FROM users 
      WHERE invitation_token = ? AND is_active = 0
    `)
    const invitedUser = await userStmt.bind(token).first() as any

    if (!invitedUser) {
      return c.json({ error: 'Invalid or expired invitation' }, 400)
    }

    // Check if invitation is expired (7 days)
    const invitationAge = Date.now() - invitedUser.invited_at
    const maxAge = 7 * 24 * 60 * 60 * 1000 // 7 days
    
    if (invitationAge > maxAge) {
      return c.json({ error: 'Invitation has expired' }, 400)
    }

    // Check if username is available
    const existingUsernameStmt = db.prepare(`
      SELECT id FROM users WHERE username = ? AND id != ?
    `)
    const existingUsername = await existingUsernameStmt.bind(username, invitedUser.id).first()

    if (existingUsername) {
      return c.json({ error: 'Username is already taken' }, 400)
    }

    // Hash password
    const passwordHash = await AuthManager.hashPassword(password)

    // Activate user account
    const updateStmt = db.prepare(`
      UPDATE users SET 
        username = ?,
        password_hash = ?,
        is_active = 1,
        email_verified = 1,
        invitation_token = NULL,
        accepted_invitation_at = ?,
        updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(
      username,
      passwordHash,
      Date.now(),
      Date.now(),
      invitedUser.id
    ).run()

    // Generate JWT token for auto-login
    const authToken = await AuthManager.generateToken(invitedUser.id, invitedUser.email, invitedUser.role, c.env.JWT_SECRET)
    
    // Set HTTP-only cookie
    setCookie(c, 'auth_token', authToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 60 * 60 * 24 // 24 hours
    })

    // Set CSRF cookie for browser sessions
    await setCsrfCookie(c)

    // Log the activity (TODO: implement activity logging)
    // Activity logging is deferred until utils/log-activity is implemented

    // Redirect to admin dashboard
    return c.redirect('/admin/dashboard?welcome=true')

  } catch (error) {
    console.error('Accept invitation error:', error)
    return c.json({ error: 'Failed to accept invitation' }, 500)
  }
})

// Request password reset
authRoutes.post('/request-password-reset', async (c) => {
  try {
    const formData = await c.req.formData()
    const email = formData.get('email')?.toString()?.trim()?.toLowerCase()

    if (!email) {
      return c.json({ error: 'Email is required' }, 400)
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return c.json({ error: 'Please enter a valid email address' }, 400)
    }

    const db = c.env.DB

    // Check if user exists and is active
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name FROM users 
      WHERE email = ? AND is_active = 1
    `)
    const user = await userStmt.bind(email).first() as any

    // Always return success to prevent email enumeration
    if (!user) {
      return c.json({
        success: true,
        message: 'If an account with this email exists, a password reset link has been sent.'
      })
    }

    // Generate password reset token (expires in 1 hour)
    const resetToken = crypto.randomUUID()
    const resetExpires = Date.now() + (60 * 60 * 1000) // 1 hour

    // Update user with reset token
    const updateStmt = db.prepare(`
      UPDATE users SET 
        password_reset_token = ?,
        password_reset_expires = ?,
        updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(
      resetToken,
      resetExpires,
      Date.now(),
      user.id
    ).run()

    // Log the activity (TODO: implement activity logging)
    // Activity logging is deferred until utils/log-activity is implemented

    // In a real implementation, you would send an email here
    // For now, we'll return the reset link for development
    const resetLink = `${c.req.header('origin') || 'http://localhost:8787'}/auth/reset-password?token=${resetToken}`

    return c.json({
      success: true,
      message: 'If an account with this email exists, a password reset link has been sent.',
      reset_link: resetLink // In production, this would be sent via email
    })

  } catch (error) {
    console.error('Password reset request error:', error)
    return c.json({ error: 'Failed to process password reset request' }, 500)
  }
})

// Show password reset form
authRoutes.get('/reset-password', async (c) => {
  try {
    const token = c.req.query('token')
    
    if (!token) {
      return c.html(`
        <html>
          <head><title>Invalid Reset Link</title></head>
          <body>
            <h1>Invalid Reset Link</h1>
            <p>The password reset link is invalid or has expired.</p>
            <a href="/auth/login">Go to Login</a>
          </body>
        </html>
      `)
    }

    const db = c.env.DB
    
    // Check if reset token is valid and not expired
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name, password_reset_expires
      FROM users 
      WHERE password_reset_token = ? AND is_active = 1
    `)
    const user = await userStmt.bind(token).first() as any

    if (!user) {
      return c.html(`
        <html>
          <head><title>Invalid Reset Link</title></head>
          <body>
            <h1>Invalid Reset Link</h1>
            <p>The password reset link is invalid or has already been used.</p>
            <a href="/auth/login">Go to Login</a>
          </body>
        </html>
      `)
    }

    // Check if token is expired
    if (Date.now() > user.password_reset_expires) {
      return c.html(`
        <html>
          <head><title>Reset Link Expired</title></head>
          <body>
            <h1>Reset Link Expired</h1>
            <p>The password reset link has expired. Please request a new one.</p>
            <a href="/auth/login">Go to Login</a>
          </body>
        </html>
      `)
    }

    // Show password reset form
    return c.html(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Password - SonicJS AI</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
          body {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            min-height: 100vh;
          }
        </style>
      </head>
      <body class="bg-gray-900 text-white">
        <div class="min-h-screen flex items-center justify-center px-4">
          <div class="max-w-md w-full space-y-8">
            <div class="text-center">
              <div class="mx-auto w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center mb-6">
                <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-3.586l4.293-4.293A6 6 0 0119 9z"/>
                </svg>
              </div>
              <h2 class="text-3xl font-bold">Reset Password</h2>
              <p class="mt-2 text-gray-400">Choose a new password for your account</p>
              <p class="mt-4 text-sm">
                Reset password for <strong>${user.first_name} ${user.last_name}</strong><br>
                <span class="text-gray-400">${user.email}</span>
              </p>
            </div>

            <form method="POST" action="/auth/reset-password" class="mt-8 space-y-6">
              <input type="hidden" name="token" value="${token}" />
              
              <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">New Password</label>
                <input 
                  type="password" 
                  name="password" 
                  required
                  minlength="8"
                  class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 transition-all"
                  placeholder="Enter your new password"
                >
                <p class="text-xs text-gray-400 mt-1">Password must be at least 8 characters long</p>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Confirm New Password</label>
                <input 
                  type="password" 
                  name="confirm_password" 
                  required
                  minlength="8"
                  class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 transition-all"
                  placeholder="Confirm your new password"
                >
              </div>

              <button 
                type="submit"
                class="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-xl hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 transition-all"
              >
                Reset Password
              </button>
            </form>

            <div class="text-center">
              <a href="/auth/login" class="text-sm text-blue-400 hover:text-blue-300">
                Back to Login
              </a>
            </div>
          </div>
        </div>
      </body>
      </html>
    `)

  } catch (error) {
    console.error('Password reset page error:', error)
    return c.html(`
      <html>
        <head><title>Error</title></head>
        <body>
          <h1>Error</h1>
          <p>An error occurred while processing your password reset.</p>
          <a href="/auth/login">Go to Login</a>
        </body>
      </html>
    `)
  }
})

// Process password reset
authRoutes.post('/reset-password', async (c) => {
  try {
    const formData = await c.req.formData()
    const token = formData.get('token')?.toString()
    const password = formData.get('password')?.toString()
    const confirmPassword = formData.get('confirm_password')?.toString()

    if (!token || !password || !confirmPassword) {
      return c.json({ error: 'All fields are required' }, 400)
    }

    if (password !== confirmPassword) {
      return c.json({ error: 'Passwords do not match' }, 400)
    }

    if (password.length < 8) {
      return c.json({ error: 'Password must be at least 8 characters long' }, 400)
    }

    const db = c.env.DB

    // Check if reset token is valid and not expired
    const userStmt = db.prepare(`
      SELECT id, email, password_hash, password_reset_expires
      FROM users
      WHERE password_reset_token = ? AND is_active = 1
    `)
    const user = await userStmt.bind(token).first() as any

    if (!user) {
      return c.json({ error: 'Invalid or expired reset token' }, 400)
    }

    // Check if token is expired
    if (Date.now() > user.password_reset_expires) {
      return c.json({ error: 'Reset token has expired' }, 400)
    }

    // Hash new password
    const newPasswordHash = await AuthManager.hashPassword(password)

    // Store old password in history (skip if table doesn't exist)
    try {
      const historyStmt = db.prepare(`
        INSERT INTO password_history (id, user_id, password_hash, created_at)
        VALUES (?, ?, ?, ?)
      `)
      await historyStmt.bind(
        crypto.randomUUID(),
        user.id,
        user.password_hash,
        Date.now()
      ).run()
    } catch (historyError) {
      // Password history table may not exist yet
      console.warn('Could not store password history:', historyError)
    }

    // Update user password and clear reset token
    const updateStmt = db.prepare(`
      UPDATE users SET
        password_hash = ?,
        password_reset_token = NULL,
        password_reset_expires = NULL,
        updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(
      newPasswordHash,
      Date.now(),
      user.id
    ).run()

    // Log the activity (TODO: implement activity logging)
    // Activity logging is deferred until utils/log-activity is implemented

    // Redirect to login with success message
    return c.redirect('/auth/login?message=Password reset successfully. Please log in with your new password.')

  } catch (error) {
    console.error('Password reset error:', error)
    return c.json({ error: 'Failed to reset password' }, 500)
  }
})

export default authRoutes
