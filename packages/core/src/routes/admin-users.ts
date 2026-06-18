import { Hono } from 'hono'
import { requireAuth, requireRole, logActivity, AuthManager } from '../middleware'
import { sanitizeInput } from '../utils/sanitize'
import { renderProfilePage, renderAvatarImage, type UserProfile, type ProfilePageData } from '../templates/pages/admin-profile.template'
import { renderAlert } from '../templates/components/alert.template'
import { renderActivityLogsPage, type ActivityLogsPageData, type ActivityLog } from '../templates/pages/admin-activity-logs.template'
import { renderUserEditPage, type UserEditPageData, type UserEditData, type UserProfileData } from '../templates/pages/admin-user-edit.template'
import { renderUserNewPage, type UserNewPageData } from '../templates/pages/admin-user-new.template'
import { renderUsersListPage, type UsersListPageData, type User } from '../templates/pages/admin-users-list.template'
import type { Bindings, Variables } from '../app'
import { getUserProfileConfig, getRegistrationFields, renderCustomProfileSection, getCustomData, saveCustomData, extractCustomFieldsFromForm, sanitizeCustomData, validateCustomData, readProfileData, writeProfileData } from '../plugins/core-plugins/user-profiles'
import { TenantService, VALID_MEMBER_ROLES } from '../plugins/core-plugins/multi-tenant-plugin/services/tenant-service'

const userRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware to all routes
userRoutes.use('*', requireAuth())

// Enforce admin-only access on user management routes
userRoutes.use('/users/*', requireRole(['admin']))
userRoutes.use('/users', requireRole(['admin']))
userRoutes.use('/invite-user', requireRole(['admin']))
userRoutes.use('/resend-invitation/*', requireRole(['admin']))
userRoutes.use('/cancel-invitation/*', requireRole(['admin']))
userRoutes.use('/activity-logs', requireRole(['admin']))
userRoutes.use('/activity-logs/*', requireRole(['admin']))

// Redirect /admin to /admin/content
userRoutes.get('/', (c) => {
  return c.redirect('/admin/dashboard')
})

// Timezone options for profile form
const TIMEZONES = [
  { value: 'UTC', label: 'UTC' },
  { value: 'America/New_York', label: 'Eastern Time' },
  { value: 'America/Chicago', label: 'Central Time' },
  { value: 'America/Denver', label: 'Mountain Time' },
  { value: 'America/Los_Angeles', label: 'Pacific Time' },
  { value: 'Europe/London', label: 'London' },
  { value: 'Europe/Paris', label: 'Paris' },
  { value: 'Europe/Berlin', label: 'Berlin' },
  { value: 'Asia/Tokyo', label: 'Tokyo' },
  { value: 'Asia/Shanghai', label: 'Shanghai' },
  { value: 'Australia/Sydney', label: 'Sydney' }
]

// Language options for profile form
const LANGUAGES = [
  { value: 'en', label: 'English' },
  { value: 'es', label: 'Spanish' },
  { value: 'fr', label: 'French' },
  { value: 'de', label: 'German' },
  { value: 'it', label: 'Italian' },
  { value: 'pt', label: 'Portuguese' },
  { value: 'ja', label: 'Japanese' },
  { value: 'ko', label: 'Korean' },
  { value: 'zh', label: 'Chinese' }
]

// Role options for user form
const ROLES = [
  { value: 'admin', label: 'Administrator' },
  { value: 'editor', label: 'Editor' },
  { value: 'author', label: 'Author' },
  { value: 'viewer', label: 'Viewer' }
]

/**
 * GET /admin/profile - Show user profile page
 */
userRoutes.get('/profile', async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  try {
    // Get user profile data
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name, phone, bio, avatar,
             timezone, language, theme, email_notifications, 0 as two_factor_enabled,
             role, created_at, last_login_at
      FROM auth_user
      WHERE id = ? AND is_active = 1
    `)
    
    const userProfile = await userStmt.bind(user!.userId).first() as any

    if (!userProfile) {
      return c.json({ error: 'User not found' }, 404)
    }

    // Convert to UserProfile interface
    const profile: UserProfile = {
      id: userProfile.id,
      email: userProfile.email,
      first_name: userProfile.first_name || '',
      last_name: userProfile.last_name || '',
      phone: userProfile.phone,
      bio: userProfile.bio,
      avatar_url: userProfile.avatar,
      timezone: userProfile.timezone || 'UTC',
      language: userProfile.language || 'en',
      theme: userProfile.theme || 'dark',
      email_notifications: Boolean(userProfile.email_notifications),
      two_factor_enabled: Boolean(userProfile.two_factor_enabled),
      role: userProfile.role,
      created_at: userProfile.created_at,
      last_login_at: userProfile.last_login_at
    }

    // Get custom profile data
    const customData = await getCustomData(db, user!.userId)
    const profileConfig = getUserProfileConfig()
    const customProfileFieldsHtml = renderCustomProfileSection(profileConfig, customData)

    const pageData: ProfilePageData = {
      profile,
      timezones: TIMEZONES,
      languages: LANGUAGES,
      customProfileFieldsHtml,
      user: {
        name: `${profile.first_name} ${profile.last_name}`.trim() || user!.email,
        email: user!.email,
        role: user!.role
      }
    }

    return c.html(renderProfilePage(pageData))
  } catch (error) {
    console.error('Profile page error:', error)
    
    const pageData: ProfilePageData = {
      profile: {} as UserProfile,
      timezones: TIMEZONES,
      languages: LANGUAGES,
      error: 'Failed to load profile. Please try again.',
      user: {
        name: user!.email,
        email: user!.email,
        role: user!.role
      }
    }

    return c.html(renderProfilePage(pageData))
  }
})

/**
 * PUT /admin/profile - Update user profile
 */
userRoutes.put('/profile', async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  try {
    const formData = await c.req.formData()

    // Sanitize all user inputs to prevent XSS attacks
    const firstName = sanitizeInput(formData.get('first_name')?.toString())
    const lastName = sanitizeInput(formData.get('last_name')?.toString())
    const email = formData.get('email')?.toString()?.trim().toLowerCase() || ''
    const phone = sanitizeInput(formData.get('phone')?.toString()) || null
    const bio = sanitizeInput(formData.get('bio')?.toString()) || null
    const timezone = formData.get('timezone')?.toString() || 'UTC'
    const language = formData.get('language')?.toString() || 'en'
    const emailNotifications = formData.get('email_notifications') === '1'

    // Validate required fields
    if (!firstName || !lastName || !email) {
      return c.html(renderAlert({
        type: 'error',
        message: 'First name, last name, and email are required.',
        dismissible: true
      }))
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'Please enter a valid email address.',
        dismissible: true 
      }))
    }

    // Check if email is taken by another user
    const checkStmt = db.prepare(`
      SELECT id FROM auth_user
      WHERE email = ? AND id != ? AND is_active = 1
    `)
    const existingUser = await checkStmt.bind(email, user!.userId).first()

    if (existingUser) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Email is already taken by another user.',
        dismissible: true
      }))
    }

    // Update user profile
    const updateStmt = db.prepare(`
      UPDATE auth_user SET
        first_name = ?, last_name = ?, email = ?,
        phone = ?, bio = ?, timezone = ?, language = ?,
        email_notifications = ?, updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(
      firstName, lastName, email,
      phone, bio, timezone, language,
      emailNotifications ? 1 : 0, Date.now(),
      user!.userId
    ).run()

    // Save custom profile fields
    const profileConfig = getUserProfileConfig()
    if (profileConfig) {
      const rawCustom = extractCustomFieldsFromForm(formData, profileConfig)
      const sanitized = sanitizeCustomData(rawCustom, profileConfig)
      const validation = validateCustomData(sanitized, profileConfig)
      if (!validation.valid) {
        const errorMessages = Object.values(validation.errors).join(', ')
        return c.html(renderAlert({ type: 'error', message: errorMessages, dismissible: true }), 400)
      }
      await saveCustomData(db, user!.userId, sanitized)
    }

    // Log the activity
    await logActivity(
      db, user!.userId, 'profile.update', 'users', user!.userId,
      { fields: ['first_name', 'last_name', 'email', 'phone', 'bio', 'timezone', 'language', 'email_notifications'] },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.html(renderAlert({
      type: 'success', 
      message: 'Profile updated successfully!',
      dismissible: true 
    }))

  } catch (error) {
    console.error('Profile update error:', error)
    return c.html(renderAlert({ 
      type: 'error', 
      message: 'Failed to update profile. Please try again.',
      dismissible: true 
    }))
  }
})

/**
 * POST /admin/profile/avatar - Upload user avatar
 */
userRoutes.post('/profile/avatar', async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  try {
    const formData = await c.req.formData()
    const avatarFile = formData.get('avatar') as File | null

    if (!avatarFile || typeof avatarFile === 'string' || !avatarFile.name) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Please select an image file.',
        dismissible: true
      }))
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    if (!allowedTypes.includes(avatarFile.type)) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'Please upload a valid image file (JPEG, PNG, GIF, or WebP).',
        dismissible: true 
      }))
    }

    // Validate file size (5MB max)
    const maxSize = 5 * 1024 * 1024
    if (avatarFile.size > maxSize) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'Image file must be smaller than 5MB.',
        dismissible: true 
      }))
    }

    // For now, we'll simulate storing the avatar
    // In a real implementation, you'd upload to cloud storage (R2, S3, etc.)
    const avatarUrl = `/uploads/avatars/${user!.userId}-${Date.now()}.${avatarFile.type.split('/')[1]}`

    // Update user avatar URL in database
    const updateStmt = db.prepare(`
      UPDATE auth_user SET avatar = ?, updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(avatarUrl, Date.now(), user!.userId).run()

    // Get updated user data to render the avatar
    const userStmt = db.prepare(`
      SELECT first_name, last_name FROM auth_user WHERE id = ?
    `)
    const userData = await userStmt.bind(user!.userId).first() as any

    // Log the activity
    await logActivity(
      db, user!.userId, 'profile.avatar_update', 'users', user!.userId,
      { avatar_url: avatarUrl },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    // Return both the alert message and the updated avatar image using HTMX out-of-band swap
    const alertHtml = renderAlert({
      type: 'success',
      message: 'Profile picture updated successfully!',
      dismissible: true
    })

    // Add timestamp to avatar URL to bust cache
    const avatarUrlWithCache = `${avatarUrl}?t=${Date.now()}`
    const avatarImageHtml = renderAvatarImage(avatarUrlWithCache, userData.first_name, userData.last_name)

    // Use hx-swap-oob to update the avatar image container
    const avatarImageWithOob = avatarImageHtml.replace(
      'id="avatar-image-container"',
      'id="avatar-image-container" hx-swap-oob="true"'
    )

    return c.html(alertHtml + avatarImageWithOob)

  } catch (error) {
    console.error('Avatar upload error:', error)
    return c.html(renderAlert({ 
      type: 'error', 
      message: 'Failed to upload profile picture. Please try again.',
      dismissible: true 
    }))
  }
})

/**
 * POST /admin/profile/password - Change user password
 */
userRoutes.post('/profile/password', async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  try {
    const formData = await c.req.formData()
    
    const currentPassword = formData.get('current_password')?.toString() || ''
    const newPassword = formData.get('new_password')?.toString() || ''
    const confirmPassword = formData.get('confirm_password')?.toString() || ''

    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'All password fields are required.',
        dismissible: true 
      }))
    }

    if (newPassword !== confirmPassword) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'New passwords do not match.',
        dismissible: true 
      }))
    }

    if (newPassword.length < 8) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'New password must be at least 8 characters long.',
        dismissible: true 
      }))
    }

    // Get current user data
    const userStmt = db.prepare(`
      SELECT password_hash FROM auth_user WHERE id = ? AND is_active = 1
    `)
    const userData = await userStmt.bind(user!.userId).first() as any

    if (!userData) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'User not found.',
        dismissible: true 
      }))
    }

    // Verify current password
    const validPassword = await AuthManager.verifyPassword(currentPassword, userData.password_hash)
    if (!validPassword) {
      return c.html(renderAlert({ 
        type: 'error', 
        message: 'Current password is incorrect.',
        dismissible: true 
      }))
    }

    // Hash new password
    const newPasswordHash = await AuthManager.hashPassword(newPassword)

    // Store old password in history
    const historyStmt = db.prepare(`
      INSERT INTO auth_password_history (id, user_id, password_hash, created_at)
      VALUES (?, ?, ?, ?)
    `)
    await historyStmt.bind(
      crypto.randomUUID(),
      user!.userId,
      userData.password_hash,
      Date.now()
    ).run()

    // Update user password
    const updateStmt = db.prepare(`
      UPDATE auth_user SET password_hash = ?, updated_at = ?
      WHERE id = ?
    `)
    await updateStmt.bind(newPasswordHash, Date.now(), user!.userId).run()

    // Log the activity
    await logActivity(
      db, user!.userId, 'profile.password_change', 'users', user!.userId,
      null,
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.html(renderAlert({ 
      type: 'success', 
      message: 'Password updated successfully!',
      dismissible: true 
    }))

  } catch (error) {
    console.error('Password change error:', error)
    return c.html(renderAlert({ 
      type: 'error', 
      message: 'Failed to update password. Please try again.',
      dismissible: true 
    }))
  }
})

/**
 * GET /admin/users - List all users
 * Returns HTML for browser requests and JSON for API requests
 * Note: Already protected by requireAuth() and requireRole(['admin', 'editor'])
 */
userRoutes.get('/users', async (c) => {
  const db = c.env.DB
  const user = c.get('user')

  try {
    // Get pagination parameters
    const page = parseInt(c.req.query('page') || '1')
    const limit = parseInt(c.req.query('limit') || '20')
    const search = c.req.query('search') || ''
    const roleFilter = c.req.query('role') || ''
    const statusFilter = c.req.query('status') || 'active'
    const offset = (page - 1) * limit

    // Build search query
    let whereClause = ''
    let params: any[] = []

    // Handle status filter
    if (statusFilter === 'active') {
      whereClause = 'WHERE u.is_active = 1'
    } else if (statusFilter === 'inactive') {
      whereClause = 'WHERE u.is_active = 0'
    } else {
      // 'all' - no filter
      whereClause = 'WHERE 1=1'
    }

    if (search) {
      whereClause += ' AND (u.first_name LIKE ? OR u.last_name LIKE ? OR u.email LIKE ?)'
      const searchParam = `%${search}%`
      params.push(searchParam, searchParam, searchParam)
    }

    if (roleFilter) {
      whereClause += ' AND u.role = ?'
      params.push(roleFilter)
    }

    // Get users
    const usersStmt = db.prepare(`
      SELECT u.id, u.email, u.first_name, u.last_name,
             u.role, u.avatar, u.created_at, u.last_login_at, u.updated_at,
             u.email_verified, 0 as two_factor_enabled, u.is_active
      FROM auth_user u
      ${whereClause}
      ORDER BY u.created_at DESC
      LIMIT ? OFFSET ?
    `)

    const { results: usersData } = await usersStmt.bind(...params, limit, offset).all()

    // Get total count
    const countStmt = db.prepare(`
      SELECT COUNT(*) as total FROM auth_user u ${whereClause}
    `)
    const countResult = await countStmt.bind(...params).first() as any
    const totalUsers = countResult?.total || 0

    // Log the activity
    await logActivity(
      db, user!.userId, 'users.list_view', 'users', undefined,
      { search, page, limit },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    // Check if this is an API request (accept header contains 'application/json')
    const acceptHeader = c.req.header('accept') || ''
    const isApiRequest = acceptHeader.includes('application/json')

    if (isApiRequest) {
      // Return JSON for API requests
      return c.json({
        users: usersData || [],
        pagination: {
          page,
          limit,
          total: totalUsers,
          pages: Math.ceil(totalUsers / limit)
        }
      })
    }

    // Return HTML for browser requests
    const users: User[] = (usersData || []).map((u: any) => ({
      id: u.id,
      email: u.email,
      firstName: u.first_name || '',
      lastName: u.last_name || '',
      role: u.role,
      avatar: u.avatar,
      isActive: Boolean(u.is_active),
      lastLoginAt: u.last_login_at,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
      formattedLastLogin: u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : undefined,
      formattedCreatedAt: new Date(u.created_at).toLocaleDateString()
    }))

    const successMessage = c.req.query('success') || undefined

    const pageData: UsersListPageData = {
      users,
      currentPage: page,
      totalPages: Math.ceil(totalUsers / limit),
      totalUsers,
      searchFilter: search,
      roleFilter,
      statusFilter,
      success: successMessage,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalUsers / limit),
        totalItems: totalUsers,
        itemsPerPage: limit,
        startItem: offset + 1,
        endItem: Math.min(offset + limit, totalUsers),
        baseUrl: '/admin/users'
      },
      user: {
        name: user!.email.split('@')[0] || user!.email,
        email: user!.email,
        role: user!.role
      },
      version: c.get('appVersion')
    }

    return c.html(renderUsersListPage(pageData))

  } catch (error) {
    console.error('Users list error:', error)

    const acceptHeader = c.req.header('accept') || ''
    const isApiRequest = acceptHeader.includes('application/json')

    if (isApiRequest) {
      return c.json({ error: 'Failed to load users' }, 500)
    }

    return c.html(renderAlert({
      type: 'error',
      message: 'Failed to load users. Please try again.',
      dismissible: true
    }), 500)
  }
})

/**
 * GET /admin/users/new - Show new user creation page
 */
userRoutes.get('/users/new', async (c) => {
  const user = c.get('user')

  try {
    const db = c.env.DB
    const profileConfig = getUserProfileConfig()
    const upRow = profileConfig
      ? await db.prepare(
          `SELECT 1 FROM documents WHERE type_id = 'plugin' AND slug = 'user-profiles'
             AND q_plugin_status = 'active' AND is_current_draft = 1 AND deleted_at IS NULL`
        ).first().catch(() => null)
      : null
    const regFieldNames = profileConfig?.registrationFields ?? []
    const regFields = profileConfig && upRow
      ? (regFieldNames.length > 0 ? profileConfig.fields.filter(f => regFieldNames.includes(f.name)) : profileConfig.fields)
      : []
    const registrationFieldsHtml = regFields.length > 0
      ? renderCustomProfileSection({ fields: regFields }, {})
      : undefined

    const pageData: UserNewPageData = {
      roles: ROLES,
      registrationFieldsHtml,
      user: {
        name: user!.email.split('@')[0] || user!.email,
        email: user!.email,
        role: user!.role
      }
    }

    return c.html(renderUserNewPage(pageData))
  } catch (error) {
    console.error('User new page error:', error)

    return c.html(renderAlert({
      type: 'error',
      message: 'Failed to load user creation page. Please try again.',
      dismissible: true
    }), 500)
  }
})

/**
 * POST /admin/users/new - Create new user
 */
userRoutes.post('/users/new', async (c) => {
  const db = c.env.DB
  const user = c.get('user')

  try {
    const formData = await c.req.formData()

    // Sanitize all user inputs to prevent XSS attacks
    const firstName = sanitizeInput(formData.get('first_name')?.toString())
    const lastName = sanitizeInput(formData.get('last_name')?.toString())
    const email = formData.get('email')?.toString()?.trim().toLowerCase() || ''
    const phone = sanitizeInput(formData.get('phone')?.toString()) || null
    const bio = sanitizeInput(formData.get('bio')?.toString()) || null
    const roleInput = formData.get('role')?.toString() || 'viewer'
    const validRoles = ['admin', 'editor', 'author', 'viewer']
    const role = validRoles.includes(roleInput) ? roleInput : 'viewer'
    const password = formData.get('password')?.toString() || ''
    const confirmPassword = formData.get('confirm_password')?.toString() || ''
    const isActive = formData.get('is_active') === '1'
    const emailVerified = formData.get('email_verified') === '1'

    // Validate + extract registration profile fields (if profile plugin is configured)
    const profileConfig = getUserProfileConfig()
    const regFieldNames = profileConfig?.registrationFields ?? []
    const regFields = profileConfig
      ? (regFieldNames.length > 0 ? profileConfig.fields.filter(f => regFieldNames.includes(f.name)) : profileConfig.fields)
      : []
    let sanitizedRegistrationCustom: Record<string, any> | null = null
    if (regFields.length > 0) {
      const rawCustom = extractCustomFieldsFromForm(formData, { fields: regFields })
      const sanitized = sanitizeCustomData(rawCustom, profileConfig!)
      const validation = validateCustomData(sanitized, profileConfig!)
      if (!validation.valid) {
        const errorMessages = Object.values(validation.errors).join(', ')
        return c.html(renderAlert({ type: 'error', message: errorMessages, dismissible: true }), 400)
      }
      sanitizedRegistrationCustom = sanitized
    }

    // Validate required fields
    if (!firstName || !lastName || !email || !password) {
      return c.html(renderAlert({
        type: 'error',
        message: 'First name, last name, email, and password are required.',
        dismissible: true
      }))
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Please enter a valid email address.',
        dismissible: true
      }))
    }

    // Validate password
    if (password.length < 8) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Password must be at least 8 characters long.',
        dismissible: true
      }))
    }

    if (password !== confirmPassword) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Passwords do not match.',
        dismissible: true
      }))
    }

    // Check if email is already taken
    const checkStmt = db.prepare(`
      SELECT id FROM auth_user
      WHERE email = ?
    `)
    const existingUser = await checkStmt.bind(email).first()

    if (existingUser) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Email is already taken.',
        dismissible: true
      }))
    }

    // Hash password
    const passwordHash = await AuthManager.hashPassword(password)

    // Create user
    const userId = crypto.randomUUID()
    const createStmt = db.prepare(`
      INSERT INTO auth_user (
        id, email, first_name, last_name, phone, bio,
        password_hash, role, is_active, email_verified, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    await createStmt.bind(
      userId, email, firstName, lastName, phone, bio,
      passwordHash, role, isActive ? 1 : 0, emailVerified ? 1 : 0,
      Date.now(), Date.now()
    ).run()

    // Save registration profile fields if profile plugin is configured
    if (sanitizedRegistrationCustom !== null && Object.keys(sanitizedRegistrationCustom).length > 0) {
      await writeProfileData(db, userId, { custom: sanitizedRegistrationCustom }, user!.userId)
    }

    // Log the activity
    await logActivity(
      db, user!.userId, 'user!.create', 'users', userId,
      { email, role },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    // Redirect to user list (use HX-Redirect for HTMX requests)
    c.header('HX-Redirect', '/admin/users?success=User created successfully')
    return c.body(null, 200)

  } catch (error) {
    console.error('User creation error:', error)
    return c.html(renderAlert({
      type: 'error',
      message: 'Failed to create user!. Please try again.',
      dismissible: true
    }))
  }
})

/**
 * GET /admin/users/:id - Get user by ID
 * Note: This endpoint returns users regardless of is_active status for admin purposes
 */
userRoutes.get('/users/:id', async (c) => {
  // Check if this is actually the edit route
  if (c.req.path.endsWith('/edit')) {
    return c.notFound()
  }

  const db = c.env.DB
  const user = c.get('user')
  const userId = c.req.param('id')

  try {
    // Get user data (including inactive users for admin access)
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name, phone, bio, avatar,
             role, is_active, email_verified, 0 as two_factor_enabled, created_at, last_login_at
      FROM auth_user
      WHERE id = ?
    `)

    const userRecord = await userStmt.bind(userId).first() as any

    if (!userRecord) {
      return c.json({ error: 'User not found' }, 404)
    }

    // Log the activity
    await logActivity(
      db, user!.userId, 'user!.view', 'users', userId,
      null,
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.json({
      user: {
        id: userRecord.id,
        email: userRecord.email,
        first_name: userRecord.first_name,
        last_name: userRecord.last_name,
        phone: userRecord.phone,
        bio: userRecord.bio,
        avatar_url: userRecord.avatar,
        role: userRecord.role,
        is_active: userRecord.is_active,
        email_verified: userRecord.email_verified,
        two_factor_enabled: userRecord.two_factor_enabled,
        created_at: userRecord.created_at,
        last_login_at: userRecord.last_login_at
      }
    })

  } catch (error) {
    console.error('User fetch error:', error)
    return c.json({ error: 'Failed to fetch user' }, 500)
  }
})

/**
 * GET /admin/users/:id/edit - Show user edit page
 */
userRoutes.get('/users/:id/edit', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const userId = c.req.param('id')

  try {
    // Get user data (removed bio - now in profile)
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name, phone, avatar,
             role, is_active, email_verified, 0 as two_factor_enabled, created_at, last_login_at
      FROM auth_user
      WHERE id = ?
    `)

    const userToEdit = await userStmt.bind(userId).first() as any

    if (!userToEdit) {
      return c.html(renderAlert({
        type: 'error',
        message: 'User not found',
        dismissible: true
      }), 404)
    }

    // Get user profile data (backed by the user_profile document)
    const profileData = await readProfileData(db, userId)
    const hasProfile = profileData.displayName != null ||
      Object.keys(profileData.custom).length > 0

    // Convert profile to UserProfileData interface
    const profile: UserProfileData | undefined = hasProfile ? {
      displayName: profileData.displayName ?? undefined,
    } : undefined

    // Custom profile data lives under data.custom
    const customData: Record<string, any> = profileData.custom
    const profileConfig = getUserProfileConfig()
    const customProfileFieldsHtml = renderCustomProfileSection(profileConfig, customData)

    // Convert to UserEditData interface
    const editData: UserEditData = {
      id: userToEdit.id,
      email: userToEdit.email,
      firstName: userToEdit.first_name || '',
      lastName: userToEdit.last_name || '',
      phone: userToEdit.phone,
      avatarUrl: userToEdit.avatar,
      role: userToEdit.role,
      isActive: Boolean(userToEdit.is_active),
      emailVerified: Boolean(userToEdit.email_verified),
      twoFactorEnabled: Boolean(userToEdit.two_factor_enabled),
      createdAt: userToEdit.created_at,
      lastLoginAt: userToEdit.last_login_at,
      profile
    }

    // User-profiles plugin active in DB?
    const upRow = await db.prepare(
      `SELECT 1 FROM documents WHERE type_id = 'plugin' AND slug = 'user-profiles'
         AND q_plugin_status = 'active' AND is_current_draft = 1 AND deleted_at IS NULL`
    ).first().catch(() => null)

    // Multi-tenant plugin active? Fetch memberships inline for the matrix section.
    const mtRow = await db.prepare(
      `SELECT 1 FROM documents WHERE type_id = 'plugin' AND slug = 'multi-tenant'
         AND q_plugin_status = 'active' AND is_current_draft = 1 AND deleted_at IS NULL`
    ).first().catch(() => null)

    let tenantMemberships: UserEditPageData['tenantMemberships']
    if (mtRow) {
      const svc = new TenantService(db)
      const [memberships, allTenants] = await Promise.all([
        svc.listUserMemberships(userId),
        svc.listTenants(),
      ])
      const memberSlugs = new Set(memberships.map((m) => m.slug))
      tenantMemberships = {
        memberships,
        availableTenants: allTenants
          .filter((t) => t.status === 'active' && !memberSlugs.has(t.slug))
          .map((t) => ({ slug: t.slug, name: t.name })),
        memberRoles: [...VALID_MEMBER_ROLES],
      }
    }

    const queryMessage = c.req.query('message')
    const queryType = c.req.query('type') === 'error' ? 'error' : 'success'

    const pageData: UserEditPageData = {
      userToEdit: editData,
      roles: ROLES,
      hasProfilePlugin: profileConfig !== null && upRow !== null,
      customProfileFieldsHtml,
      tenantMemberships,
      ...(queryMessage && queryType === 'error' ? { error: queryMessage } : {}),
      ...(queryMessage && queryType === 'success' ? { success: queryMessage } : {}),
      user: {
        name: user!.email.split('@')[0] || user!.email,
        email: user!.email,
        role: user!.role
      }
    }

    return c.html(renderUserEditPage(pageData))
  } catch (error) {
    console.error('User edit page error:', error)

    return c.html(renderAlert({
      type: 'error',
      message: 'Failed to load user. Please try again.',
      dismissible: true
    }), 500)
  }
})

/**
 * PUT /admin/users/:id - Update user
 */
userRoutes.put('/users/:id', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const userId = c.req.param('id')

  try {
    const formData = await c.req.formData()

    // Sanitize all user inputs to prevent XSS attacks
    const firstName = sanitizeInput(formData.get('first_name')?.toString())
    const lastName = sanitizeInput(formData.get('last_name')?.toString())
    const email = formData.get('email')?.toString()?.trim().toLowerCase() || ''
    const phone = sanitizeInput(formData.get('phone')?.toString()) || null
    const roleInput = formData.get('role')?.toString() || 'viewer'
    const validRoles = ['admin', 'editor', 'author', 'viewer']
    const role = validRoles.includes(roleInput) ? roleInput : 'viewer'
    const isActive = formData.get('is_active') === '1'
    const emailVerified = formData.get('email_verified') === '1'

    // Optional password change
    const newPassword = formData.get('new_password')?.toString() || ''
    const confirmPassword = formData.get('confirm_password')?.toString() || ''

    // Extract profile fields
    const profileDisplayName = sanitizeInput(formData.get('profile_display_name')?.toString()) || null
    // Extract custom profile fields (merged into the profile document below)
    const profileConfig = getUserProfileConfig()
    let sanitizedCustom: Record<string, any> | null = null
    if (profileConfig) {
      const rawCustom = extractCustomFieldsFromForm(formData, profileConfig)
      const sanitized = sanitizeCustomData(rawCustom, profileConfig)
      const validation = validateCustomData(sanitized, profileConfig)
      if (!validation.valid) {
        const errorMessages = Object.values(validation.errors).join(', ')
        return c.html(renderAlert({ type: 'error', message: errorMessages, dismissible: true }), 400)
      }
      sanitizedCustom = sanitized
    }

    // Validate required fields
    if (!email) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Email is required.',
        dismissible: true
      }))
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Please enter a valid email address.',
        dismissible: true
      }))
    }

    // Validate password if provided
    if (newPassword) {
      if (newPassword.length < 8) {
        return c.html(renderAlert({
          type: 'error',
          message: 'Password must be at least 8 characters long.',
          dismissible: true
        }))
      }
      if (newPassword !== confirmPassword) {
        return c.html(renderAlert({
          type: 'error',
          message: 'Passwords do not match.',
          dismissible: true
        }))
      }
    }

    // Check if email is taken by another user
    const checkStmt = db.prepare(`
      SELECT id FROM auth_user
      WHERE email = ? AND id != ?
    `)
    const existingUser = await checkStmt.bind(email, userId).first()

    if (existingUser) {
      return c.html(renderAlert({
        type: 'error',
        message: 'Email is already taken by another user.',
        dismissible: true
      }))
    }

    // Update user (removed bio - now in profile)
    const updateStmt = db.prepare(`
      UPDATE auth_user SET
        first_name = ?, last_name = ?, email = ?,
        phone = ?, role = ?, is_active = ?, email_verified = ?,
        updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(
      firstName, lastName, email,
      phone, role, isActive ? 1 : 0, emailVerified ? 1 : 0,
      Date.now(), userId
    ).run()

    // Update password if provided
    if (newPassword) {
      const passwordHash = await AuthManager.hashPassword(newPassword)
      const updatePasswordStmt = db.prepare(`
        UPDATE auth_user SET password_hash = ?, updated_at = ? WHERE id = ?
      `)
      await updatePasswordStmt.bind(passwordHash, Date.now(), userId).run()
    }

    // Check if any profile field has data
    const hasProfileData = profileDisplayName

    if (hasProfileData || sanitizedCustom !== null) {
      // Persist to the user_profile document (typed fields + custom namespace).
      await writeProfileData(db, userId, {
        displayName: profileDisplayName,
        ...(sanitizedCustom !== null ? { custom: sanitizedCustom } : {}),
      }, user!.userId)
    }

    // Log the activity
    await logActivity(
      db, user!.userId, 'user.update', 'users', userId,
      { fields: ['first_name', 'last_name', 'email', 'phone', 'role', 'is_active', 'email_verified', 'profile', ...(newPassword ? ['password'] : [])] },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.html(renderAlert({
      type: 'success',
      message: 'User updated successfully!',
      dismissible: true,
      className: 'mb-4'
    }))

  } catch (error) {
    console.error('User update error:', error)
    return c.html(renderAlert({
      type: 'error',
      message: 'Failed to update user. Please try again.',
      dismissible: true
    }))
  }
})

/**
 * POST /admin/users/:id/toggle - Toggle user active status
 */
userRoutes.post('/users/:id/toggle', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const userId = c.req.param('id')

  try {
    const body = await c.req.json().catch(() => ({ active: true }))
    const active = body.active === true

    // Prevent self-deactivation
    if (userId === user!.userId && !active) {
      return c.json({ error: 'You cannot deactivate your own account' }, 400)
    }

    // Check if user exists
    const userStmt = db.prepare(`
      SELECT id, email FROM auth_user WHERE id = ?
    `)
    const userToToggle = await userStmt.bind(userId).first() as any

    if (!userToToggle) {
      return c.json({ error: 'User not found' }, 404)
    }

    // Toggle user status
    const toggleStmt = db.prepare(`
      UPDATE auth_user SET is_active = ?, updated_at = ? WHERE id = ?
    `)
    await toggleStmt.bind(active ? 1 : 0, Date.now(), userId).run()

    // Log the activity
    await logActivity(
      db, user!.userId, active ? 'user.activate' : 'user.deactivate', 'users', userId,
      { email: userToToggle.email },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.json({
      success: true,
      message: active ? 'User activated successfully' : 'User deactivated successfully'
    })

  } catch (error) {
    console.error('User toggle error:', error)
    return c.json({ error: 'Failed to toggle user status' }, 500)
  }
})

/**
 * DELETE /admin/users/:id - Delete user
 */
userRoutes.delete('/users/:id', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const userId = c.req.param('id')

  try {
    // Get request body to check for hard delete option
    const body = await c.req.json().catch(() => ({ hardDelete: false }))
    const hardDelete = body.hardDelete === true

    // Prevent self-deletion
    if (userId === user!.userId) {
      return c.json({ error: 'You cannot delete your own account' }, 400)
    }

    // Check if user exists
    const userStmt = db.prepare(`
      SELECT id, email FROM auth_user WHERE id = ?
    `)
    const userToDelete = await userStmt.bind(userId).first() as any

    if (!userToDelete) {
      return c.json({ error: 'User not found' }, 404)
    }

    if (hardDelete) {
      // Hard delete - permanently remove from database
      const deleteStmt = db.prepare(`
        DELETE FROM auth_user WHERE id = ?
      `)
      await deleteStmt.bind(userId).run()

      // Log the activity
      await logActivity(
        db, user!.userId, 'user!.hard_delete', 'users', userId,
        { email: userToDelete.email, permanent: true },
        c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
        c.req.header('user-agent')
      )

      return c.json({
        success: true,
        message: 'User permanently deleted'
      })
    } else {
      // Soft delete - deactivate by setting is_active = 0
      const deleteStmt = db.prepare(`
        UPDATE auth_user SET is_active = 0, updated_at = ? WHERE id = ?
      `)
      await deleteStmt.bind(Date.now(), userId).run()

      // Log the activity
      await logActivity(
        db, user!.userId, 'user!.soft_delete', 'users', userId,
        { email: userToDelete.email },
        c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
        c.req.header('user-agent')
      )

      return c.json({
        success: true,
        message: 'User deactivated successfully'
      })
    }

  } catch (error) {
    console.error('User deletion error:', error)
    return c.json({ error: 'Failed to delete user' }, 500)
  }
})

/**
 * POST /admin/invite-user - Invite a new user
 */
userRoutes.post('/invite-user', async (c) => {
  const db = c.env.DB
  const user = c.get('user')

  try {
    const formData = await c.req.formData()

    // Sanitize all user inputs to prevent XSS attacks
    const email = formData.get('email')?.toString()?.trim().toLowerCase() || ''
    const role = formData.get('role')?.toString()?.trim() || 'viewer'
    const firstName = sanitizeInput(formData.get('first_name')?.toString())
    const lastName = sanitizeInput(formData.get('last_name')?.toString())

    // Validate input
    if (!email || !firstName || !lastName) {
      return c.json({ error: 'Email, first name, and last name are required' }, 400)
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return c.json({ error: 'Please enter a valid email address' }, 400)
    }

    // Check if user already exists
    const existingUserStmt = db.prepare(`
      SELECT id FROM auth_user WHERE email = ?
    `)
    const existingUser = await existingUserStmt.bind(email).first()

    if (existingUser) {
      return c.json({ error: 'A user with this email already exists' }, 400)
    }

    // Generate invitation token
    const invitationToken = crypto.randomUUID()
    // const invitationExpires = Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days

    // Create user record with invitation
    const userId = crypto.randomUUID()
    const createUserStmt = db.prepare(`
      INSERT INTO auth_user (
        id, email, first_name, last_name, role, 
        invitation_token, invited_by, invited_at,
        is_active, email_verified, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    await createUserStmt.bind(
      userId, email, firstName, lastName, role,
      invitationToken, user!.userId, Date.now(),
      0, 0, Date.now(), Date.now()
    ).run()

    // Log the activity
    await logActivity(
      db, user!.userId, 'user!.invite_sent', 'users', userId,
      { email, role, invited_user_id: userId },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    // In a real implementation, you would send an email here
    // For now, we'll return the invitation link
    const invitationLink = `${c.req.header('origin') || 'http://localhost:8787'}/auth/accept-invitation?token=${invitationToken}`

    return c.json({
      success: true,
      message: 'User invitation sent successfully',
      user: {
        id: userId,
        email,
        first_name: firstName,
        last_name: lastName,
        role
      },
      invitation_link: invitationLink // In production, this would be sent via email
    })

  } catch (error) {
    console.error('User invitation error:', error)
    return c.json({ error: 'Failed to send user invitation' }, 500)
  }
})

/**
 * POST /admin/resend-invitation/:id - Resend invitation
 */
userRoutes.post('/resend-invitation/:id', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const userId = c.req.param('id')

  try {
    // Check if user exists and is invited but not active
    const userStmt = db.prepare(`
      SELECT id, email, first_name, last_name, role, invitation_token
      FROM auth_user 
      WHERE id = ? AND is_active = 0 AND invitation_token IS NOT NULL
    `)
    const invitedUser = await userStmt.bind(userId).first() as any

    if (!invitedUser) {
      return c.json({ error: 'User not found or invitation not valid' }, 404)
    }

    // Generate new invitation token
    const newInvitationToken = crypto.randomUUID()

    // Update invitation token and date
    const updateStmt = db.prepare(`
      UPDATE auth_user SET 
        invitation_token = ?, 
        invited_at = ?, 
        updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(
      newInvitationToken,
      Date.now(),
      Date.now(),
      userId
    ).run()

    // Log the activity
    await logActivity(
      db, user!.userId, 'user!.invitation_resent', 'users', userId,
      { email: invitedUser.email },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    // Generate new invitation link
    const invitationLink = `${c.req.header('origin') || 'http://localhost:8787'}/auth/accept-invitation?token=${newInvitationToken}`

    return c.json({
      success: true,
      message: 'Invitation resent successfully',
      invitation_link: invitationLink
    })

  } catch (error) {
    console.error('Resend invitation error:', error)
    return c.json({ error: 'Failed to resend invitation' }, 500)
  }
})

/**
 * DELETE /admin/cancel-invitation/:id - Cancel invitation
 */
userRoutes.delete('/cancel-invitation/:id', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const userId = c.req.param('id')

  try {
    // Check if user exists and is invited but not active
    const userStmt = db.prepare(`
      SELECT id, email FROM auth_user 
      WHERE id = ? AND is_active = 0 AND invitation_token IS NOT NULL
    `)
    const invitedUser = await userStmt.bind(userId).first() as any

    if (!invitedUser) {
      return c.json({ error: 'User not found or invitation not valid' }, 404)
    }

    // Delete the user record (since they haven't activated yet)
    const deleteStmt = db.prepare(`DELETE FROM auth_user WHERE id = ?`)
    await deleteStmt.bind(userId).run()

    // Log the activity
    await logActivity(
      db, user!.userId, 'user!.invitation_cancelled', 'users', userId,
      { email: invitedUser.email },
      c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.json({
      success: true,
      message: 'Invitation cancelled successfully'
    })

  } catch (error) {
    console.error('Cancel invitation error:', error)
    return c.json({ error: 'Failed to cancel invitation' }, 500)
  }
})

/**
 * GET /admin/activity-logs - View activity logs
 */
userRoutes.get('/activity-logs', async (c) => {
  // activity_logs is not yet available — will be implemented as a plugin
  const user = c.get('user')
  const page = parseInt(c.req.query('page') || '1')
  const limit = parseInt(c.req.query('limit') || '50')
  const filters = {
    action: c.req.query('action') || '',
    resource_type: c.req.query('resource_type') || '',
    date_from: c.req.query('date_from') || '',
    date_to: c.req.query('date_to') || '',
    user_id: c.req.query('user_id') || ''
  }
  const pageData: ActivityLogsPageData = {
    logs: [],
    pagination: { page, limit, total: 0, pages: 0 },
    filters,
    user: {
      name: user!.email.split('@')[0] || user!.email,
      email: user!.email,
      role: user!.role
    }
  }
  return c.html(renderActivityLogsPage(pageData))
})

/**
 * GET /admin/activity-logs/export - Export activity logs to CSV
 */
userRoutes.get('/activity-logs/export', async (c) => {
  // activity_logs is not yet available — will be implemented as a plugin
  const csvHeaders = ['Timestamp', 'User', 'Email', 'Action', 'Resource Type', 'Resource ID', 'IP Address', 'Details']
  const csvContent = csvHeaders.join(',')
  const filename = `activity-logs-${new Date().toISOString().split('T')[0]}.csv`
  return new Response(csvContent, {
    headers: {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="${filename}"`
    }
  })
})

export { userRoutes }