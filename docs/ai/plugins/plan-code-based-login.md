# Code-Based Login (OTP) Plugin - Implementation Plan

**Status: Obsolete.** The OTP Login and Magic Link plugins were removed. Email OTP and magic link are now provided via **Better Auth** plugins in app config. See [docs/authentication.md](../../authentication.md) for Magic Link and Email OTP setup with `auth.extendBetterAuth`. This plan is retained for historical context only.

---

## Overview (historical)

Create a passwordless authentication plugin that sends a 6-digit one-time password (OTP) code via email. Users enter their email, receive a code, and enter it to authenticate. This is simpler than magic links (no clicking links) and more user-friendly for mobile devices.

## Plugin Architecture Decision

**Should this be a plugin?** **YES** ✅

### Rationale:
1. **Optional Feature**: Not all applications need OTP authentication
2. **Email Dependency**: Requires the email plugin to be configured
3. **Modular**: Can be enabled/disabled per application needs
4. **Follows SonicJS Pattern**: Similar to existing magic-link-auth plugin
5. **Plugin System Benefits**: Settings, lifecycle hooks, admin UI integration

### Plugin Type:
- **Location**: `packages/core/src/plugins/core-plugins/otp-login-plugin/`
- **Type**: Core plugin (ships with SonicJS but inactive by default)
- **Category**: `authentication`
- **Plugin ID**: `otp-login`

## Comparison: OTP vs Magic Link vs Password

| Feature | OTP Code | Magic Link | Email/Password |
|---------|----------|------------|----------------|
| **User Flow** | Enter email → Receive code → Enter code | Enter email → Click link | Enter email & password |
| **Security** | High | Very High | Medium |
| **Mobile UX** | Excellent (copy/paste) | Good (app switching) | Good |
| **Desktop UX** | Good (type code) | Excellent (one click) | Excellent |
| **Setup Complexity** | Requires email | Requires email | None |
| **Code Expiry** | 5-10 minutes | 15 minutes | N/A |
| **Rate Limiting** | Per email/IP | Per email | Login attempts |
| **Best For** | Mobile apps, APIs | Web apps | Traditional apps |

## Technical Architecture

### 1. Database Schema

```sql
-- Migration: 021_add_otp_login.sql
CREATE TABLE IF NOT EXISTS otp_codes (
  id TEXT PRIMARY KEY,
  user_email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  used_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  attempts INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  INDEX idx_email_code (user_email, code),
  INDEX idx_expires (expires_at)
);

-- Add plugin record
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES (
    'otp-login',
    'otp-login',
    'OTP Login',
    'Passwordless authentication via email one-time codes',
    '1.0.0-beta.1',
    'SonicJS Team',
    'authentication',
    '🔢',
    'inactive',
    TRUE,
    '["otp:manage", "otp:request", "otp:verify"]',
    unixepoch(),
    unixepoch()
);
```

### 2. Plugin Structure

```
packages/core/src/plugins/core-plugins/otp-login-plugin/
├── index.ts              # Main plugin file
├── manifest.json         # Plugin metadata
├── email-templates.ts    # OTP email templates
├── otp-service.ts        # OTP generation/verification logic
└── README.md            # Documentation
```

### 3. API Endpoints

#### A. Request OTP Code
```
POST /auth/otp/request
Content-Type: application/json

{
  "email": "user@example.com"
}

Response:
{
  "message": "If an account exists for this email, you will receive a verification code shortly.",
  "expiresIn": 600,  // seconds
  "dev_code": "123456"  // Only in development mode
}
```

#### B. Verify OTP Code
```
POST /auth/otp/verify
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "123456"
}

Response (Success):
{
  "success": true,
  "token": "jwt-token-here",
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "role": "admin"
  }
}

Response (Failure):
{
  "error": "Invalid or expired code",
  "attemptsRemaining": 2
}
```

#### C. Resend OTP Code
```
POST /auth/otp/resend
Content-Type: application/json

{
  "email": "user@example.com"
}
```

### 4. Settings Configuration

```json
{
  "codeLength": {
    "type": "number",
    "label": "Code Length",
    "default": 6,
    "min": 4,
    "max": 8,
    "description": "Length of OTP code (4-8 digits)"
  },
  "codeExpiryMinutes": {
    "type": "number",
    "label": "Code Expiry (minutes)",
    "default": 10,
    "min": 5,
    "max": 60,
    "description": "How long codes remain valid"
  },
  "maxAttempts": {
    "type": "number",
    "label": "Maximum Attempts",
    "default": 3,
    "min": 3,
    "max": 10,
    "description": "Max verification attempts before code invalidation"
  },
  "rateLimitPerHour": {
    "type": "number",
    "label": "Rate Limit (per hour)",
    "default": 5,
    "min": 3,
    "max": 20,
    "description": "Max code requests per email per hour"
  },
  "allowNewUserRegistration": {
    "type": "boolean",
    "label": "Allow New User Registration",
    "default": false,
    "description": "Allow new users to register via OTP"
  },
  "sessionDurationDays": {
    "type": "number",
    "label": "Session Duration (days)",
    "default": 30,
    "min": 1,
    "max": 365,
    "description": "How long authentication sessions last"
  }
}
```

### 5. Email Templates

**Subject**: `Your login code for [App Name]`

**HTML Template**:
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">

  <div style="text-align: center; padding: 20px 0;">
    {{#if logoUrl}}
    <img src="{{logoUrl}}" alt="Logo" style="max-width: 150px; height: auto;">
    {{/if}}
  </div>

  <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin: 20px 0;">
    <h1 style="margin: 0 0 10px 0; font-size: 28px;">Your Login Code</h1>
    <p style="margin: 0; opacity: 0.9; font-size: 14px;">Enter this code to sign in</p>
  </div>

  <div style="background: #f7f7f7; border-radius: 10px; padding: 30px; text-align: center; margin: 20px 0;">
    <div style="font-size: 48px; font-weight: bold; letter-spacing: 10px; color: #667eea; font-family: 'Courier New', monospace;">
      {{code}}
    </div>
  </div>

  <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px;">
    <p style="margin: 0; font-size: 14px; color: #856404;">
      ⚠️ This code expires in <strong>{{expiryMinutes}} minutes</strong>
    </p>
  </div>

  <div style="margin: 30px 0;">
    <h3 style="color: #333; margin-bottom: 10px;">Quick Tips:</h3>
    <ul style="color: #666; font-size: 14px; line-height: 1.8;">
      <li>Enter the code exactly as shown ({{codeLength}} digits)</li>
      <li>The code is case-sensitive</li>
      <li>You have {{maxAttempts}} attempts to enter the correct code</li>
      <li>Request a new code if this one expires</li>
    </ul>
  </div>

  <div style="border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; text-align: center; color: #999; font-size: 12px;">
    <p><strong>Didn't request this code?</strong><br>
    Someone may have entered your email by mistake. You can safely ignore this email.</p>

    <p style="margin-top: 20px;">
      This email was sent to {{email}}<br>
      IP Address: {{ipAddress}}<br>
      Time: {{timestamp}}
    </p>
  </div>

</body>
</html>
```

**Plain Text Template**:
```
Your Login Code for [App Name]

Your one-time verification code is:

{{code}}

This code expires in {{expiryMinutes}} minutes.

Quick Tips:
• Enter the code exactly as shown ({{codeLength}} digits)
• The code is case-sensitive
• You have {{maxAttempts}} attempts to enter the correct code
• Request a new code if this one expires

Didn't request this code?
Someone may have entered your email by mistake. You can safely ignore this email.

---
This email was sent to {{email}}
IP Address: {{ipAddress}}
Time: {{timestamp}}
```

### 6. Security Features

#### Rate Limiting
```typescript
interface RateLimitCheck {
  email: string
  ip: string
  timeWindow: number  // 1 hour default
  maxRequests: number  // 5 default
}
```

#### Brute Force Protection
- Max 3 attempts per code (configurable)
- Code invalidated after max attempts
- Exponential backoff on failed attempts
- IP-based rate limiting

#### Token Security
```typescript
function generateOTPCode(length: number = 6): string {
  // Use crypto for secure random generation
  const digits = '0123456789'
  let code = ''

  for (let i = 0; i < length; i++) {
    const randomValues = new Uint8Array(1)
    crypto.getRandomValues(randomValues)
    code += digits[randomValues[0] % digits.length]
  }

  return code
}
```

#### Session Management
- JWT token generation on successful verification
- Configurable session duration
- Secure cookie storage (httpOnly, secure, sameSite)

### 7. Admin UI Pages

#### A. Settings Page
**Route**: `/admin/plugins/otp-login/settings`

Features:
- Configure code length (4-8 digits)
- Set expiry time (5-60 minutes)
- Set max attempts (3-10)
- Set rate limits
- Enable/disable new user registration
- Test OTP send functionality

#### B. Activity Log Page
**Route**: `/admin/plugins/otp-login/activity`

Features:
- View recent OTP requests
- See success/failure rates
- IP addresses and user agents
- Export logs to CSV

#### C. Statistics Dashboard
**Route**: `/admin/plugins/otp-login/stats`

Metrics:
- Total codes sent (24h, 7d, 30d)
- Success rate
- Average verification time
- Failed attempts by IP
- Top requesting emails

### 8. Integration with Email Plugin

```typescript
async function sendOTPEmail(
  email: string,
  code: string,
  settings: OTPSettings,
  emailService: EmailService
): Promise<void> {
  const template = renderOTPEmailTemplate({
    code,
    expiryMinutes: settings.codeExpiryMinutes,
    codeLength: settings.codeLength,
    maxAttempts: settings.maxAttempts,
    email,
    ipAddress: '...',
    timestamp: new Date().toISOString(),
    logoUrl: settings.logoUrl
  })

  await emailService.send({
    to: email,
    subject: `Your login code for ${settings.appName}`,
    html: template.html,
    text: template.text
  })
}
```

## Implementation Phases

### Phase 1: Core Plugin Foundation (1-2 hours)
- [ ] Create plugin directory structure
- [ ] Create database migration (021_add_otp_login.sql)
- [ ] Create manifest.json with metadata and settings schema
- [ ] Create README.md with documentation
- [ ] Export plugin from core-plugins/index.ts

**Files to Create**:
1. `packages/core/migrations/021_add_otp_login.sql`
2. `packages/core/src/plugins/core-plugins/otp-login-plugin/manifest.json`
3. `packages/core/src/plugins/core-plugins/otp-login-plugin/README.md`

**Files to Modify**:
1. `packages/core/src/plugins/core-plugins/index.ts` - Add exports

### Phase 2: OTP Service Logic (2-3 hours)
- [ ] Create OTP generation function (secure crypto)
- [ ] Create OTP verification function
- [ ] Implement rate limiting logic
- [ ] Implement brute force protection
- [ ] Create email template rendering
- [ ] Add database cleanup for expired codes

**Files to Create**:
1. `packages/core/src/plugins/core-plugins/otp-login-plugin/otp-service.ts`
2. `packages/core/src/plugins/core-plugins/otp-login-plugin/email-templates.ts`

### Phase 3: API Endpoints (2-3 hours)
- [ ] Implement POST /auth/otp/request endpoint
- [ ] Implement POST /auth/otp/verify endpoint
- [ ] Implement POST /auth/otp/resend endpoint
- [ ] Add request validation (zod schemas)
- [ ] Add error handling
- [ ] Add development mode helpers (return code in response)

**Files to Create**:
1. `packages/core/src/plugins/core-plugins/otp-login-plugin/index.ts`

### Phase 4: Admin UI (2-3 hours)
- [ ] Create settings page with form
- [ ] Create activity log page
- [ ] Create statistics dashboard
- [ ] Add plugin menu items
- [ ] Add test OTP functionality

**Files to Modify**:
1. `packages/core/src/plugins/core-plugins/otp-login-plugin/index.ts` - Add admin routes

### Phase 5: Testing & Integration (1-2 hours)
- [ ] Create unit tests for OTP service
- [ ] Create integration tests for API endpoints
- [ ] Test with email plugin
- [ ] Test rate limiting
- [ ] Test brute force protection
- [ ] Test expiry logic

**Files to Create**:
1. `packages/core/src/__tests__/plugins/otp-login.test.ts`

### Phase 6: Documentation & Polish (1 hour)
- [ ] Update main README if needed
- [ ] Add example usage in README
- [ ] Add troubleshooting guide
- [ ] Add security best practices
- [ ] Test in production-like environment

## File Changes Summary

### New Files (7 files)
```
packages/core/migrations/021_add_otp_login.sql
packages/core/src/plugins/core-plugins/otp-login-plugin/index.ts
packages/core/src/plugins/core-plugins/otp-login-plugin/manifest.json
packages/core/src/plugins/core-plugins/otp-login-plugin/otp-service.ts
packages/core/src/plugins/core-plugins/otp-login-plugin/email-templates.ts
packages/core/src/plugins/core-plugins/otp-login-plugin/README.md
packages/core/src/__tests__/plugins/otp-login.test.ts
```

### Modified Files (1 file)
```
packages/core/src/plugins/core-plugins/index.ts
```

## Usage Examples

### Example 1: Request OTP from Frontend
```typescript
// React/Vue/Vanilla JS
async function requestOTP(email: string) {
  const response = await fetch('/auth/otp/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  })

  const data = await response.json()

  if (response.ok) {
    console.log('Code sent!', data.message)
    // Show code input form
  } else {
    console.error('Error:', data.error)
  }
}
```

### Example 2: Verify OTP
```typescript
async function verifyOTP(email: string, code: string) {
  const response = await fetch('/auth/otp/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code })
  })

  const data = await response.json()

  if (response.ok) {
    // Store JWT token
    localStorage.setItem('auth_token', data.token)
    // Redirect to dashboard
    window.location.href = '/admin'
  } else {
    console.error('Invalid code:', data.error)
    console.log(`Attempts remaining: ${data.attemptsRemaining}`)
  }
}
```

### Example 3: Full Login Flow Component
```typescript
// Login page with OTP
function OTPLoginPage() {
  const [step, setStep] = useState<'email' | 'code'>('email')
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')

  async function handleEmailSubmit(e: FormEvent) {
    e.preventDefault()

    const response = await fetch('/auth/otp/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    })

    if (response.ok) {
      setStep('code')
      setError('')
    } else {
      const data = await response.json()
      setError(data.error)
    }
  }

  async function handleCodeSubmit(e: FormEvent) {
    e.preventDefault()

    const response = await fetch('/auth/otp/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code })
    })

    const data = await response.json()

    if (response.ok) {
      localStorage.setItem('auth_token', data.token)
      window.location.href = '/admin'
    } else {
      setError(data.error)
    }
  }

  if (step === 'email') {
    return (
      <form onSubmit={handleEmailSubmit}>
        <h2>Sign in with Email</h2>
        <input
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        {error && <p className="error">{error}</p>}
        <button type="submit">Send Code</button>
      </form>
    )
  }

  return (
    <form onSubmit={handleCodeSubmit}>
      <h2>Enter Verification Code</h2>
      <p>We sent a code to {email}</p>
      <input
        type="text"
        placeholder="Enter 6-digit code"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        maxLength={6}
        pattern="[0-9]{6}"
        required
      />
      {error && <p className="error">{error}</p>}
      <button type="submit">Verify</button>
      <button type="button" onClick={() => setStep('email')}>
        Change Email
      </button>
    </form>
  )
}
```

## Security Considerations

### 1. Code Generation
- Use `crypto.getRandomValues()` for secure randomness
- Avoid predictable patterns
- Use sufficient length (6 digits = 1 million possibilities)
- Consider alphanumeric for higher entropy (optional)

### 2. Rate Limiting Strategy
```typescript
interface RateLimitStrategy {
  perEmail: {
    window: '1 hour',
    limit: 5  // 5 requests per email per hour
  },
  perIP: {
    window: '1 hour',
    limit: 20  // 20 requests per IP per hour
  },
  global: {
    window: '1 minute',
    limit: 100  // 100 total requests per minute
  }
}
```

### 3. Database Cleanup
- Auto-delete expired codes (cron job or on-query cleanup)
- Archive used codes for audit trail
- Implement retention policy (30 days)

### 4. Email Security
- Don't send codes to unverified emails (if email verification enabled)
- Include IP and timestamp in email for transparency
- Warn users about phishing attempts

### 5. Compliance Considerations
- GDPR: Log retention and data deletion
- CCPA: User data access and deletion
- SOC2: Audit logging and monitoring
- PCI-DSS: If handling payment data

## Benefits Over Magic Links

1. **Mobile-Friendly**: No app switching, copy/paste code
2. **Simpler UX**: One field vs clicking link
3. **Works Everywhere**: No link tracking issues
4. **Offline Backup**: Can read code from another device
5. **2FA Compatible**: Can be used as second factor

## Drawbacks vs Magic Links

1. **More User Steps**: Must type code (vs one click)
2. **Typo Risk**: Users might enter wrong code
3. **Lower Security**: Code visible in email (vs single-use link)
4. **Code Sharing**: Users might share codes (security risk)

## Recommendation

**Use OTP Login When**:
- Building mobile-first applications
- Users frequently access from multiple devices
- Need simpler authentication flow
- Want 2FA-compatible system
- Target non-technical users

**Use Magic Link When**:
- Building desktop web applications
- Security is paramount
- Want one-click experience
- Link click tracking is important

**Use Both**:
- Let users choose their preferred method
- OTP for mobile, magic link for desktop
- Maximum flexibility and UX

## Timeline Estimate

- **Phase 1**: 1-2 hours
- **Phase 2**: 2-3 hours
- **Phase 3**: 2-3 hours
- **Phase 4**: 2-3 hours
- **Phase 5**: 1-2 hours
- **Phase 6**: 1 hour

**Total**: 9-14 hours

## Success Criteria

- [ ] Plugin shows in admin plugins list
- [ ] Can be activated/deactivated
- [ ] Settings page is functional
- [ ] Can send OTP codes via email
- [ ] Can verify OTP codes
- [ ] Rate limiting works
- [ ] Brute force protection works
- [ ] Codes expire correctly
- [ ] Admin UI displays stats
- [ ] All tests pass
- [ ] Documentation is complete

## Next Steps

1. Review and approve this plan
2. Begin Phase 1 implementation
3. Test each phase before moving to next
4. Deploy and monitor in staging
5. Gather user feedback
6. Iterate and improve
