# SonicJS Postman Collection

A comprehensive Postman collection for manually testing the SonicJS API.

## Quick Start

1. **Import into Postman**:
   - Open Postman
   - Click "Import" and select both files:
     - `SonicJS-API.postman_collection.json`
     - `SonicJS-API.postman_environment.json` (optional but recommended)

2. **Start SonicJS locally**:
   ```bash
   npm run dev
   ```

3. **Seed the admin user** (first time only):
   - Run the "Seed Admin User" request in the Authentication folder
   - Default credentials: `admin@sonicjs.com` / `sonicjs!`

4. **Start testing**:
   - Run any endpoint - authentication is handled automatically

## Features

### Auto-Authentication
The collection includes a pre-request script that automatically:
- Logs in if no token exists
- Refreshes token if expired
- Skips auth for public endpoints

### Collection Variables
Variables are automatically managed:
- `authToken` - JWT token (auto-populated on login)
- `tokenExpiry` - Token expiration timestamp
- `userId` - Current user ID
- `testContentId` - ID for content operations
- `testMediaId` - ID for media operations
- `otpEmail` / `otpCode` - For OTP testing

## API Coverage

### Public API
- `GET /health` - Root health check
- `GET /api/health` - API health check
- `GET /api/` - API info
- `GET /api/collections` - List collections
- `GET /api/content` - List content (with filters)
- `GET /api/content/:id` - Get content by ID
- `GET /api/collections/:name/content` - Get collection content

### System API
- `GET /api/system/health` - Detailed health check (DB, KV, R2)
- `GET /api/system/info` - System information
- `GET /api/system/stats` - Content, media, and user statistics
- `GET /api/system/ping` - Database connectivity check
- `GET /api/system/env` - Environment and feature flags

### Authentication
- `POST /auth/seed-admin` - Create initial admin user (dev/test only; needs `ENABLE_SEED_ADMIN = "true"`)
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login with email/password
- `GET /auth/me` - Get current user
- `POST /auth/refresh` - Refresh JWT token
- `POST /auth/logout` - Logout
- `POST /auth/request-password-reset` - Request password reset
- `POST /auth/reset-password` - Reset password with token

### OTP Authentication (Passwordless)
The OTP plugin provides passwordless login via email codes:
- `POST /auth/otp/request` - Request OTP code for email
- `POST /auth/otp/verify` - Verify OTP code and get token
- `POST /auth/otp/resend` - Resend OTP code

**Note**: In development mode, the OTP code is returned in the response (`dev_code` field) for easy testing.

### Admin - Users
- `GET /admin/users` - List users (with pagination, filters)
- `GET /admin/users/:id` - Get user details
- `POST /admin/users/new` - Create user
- `PUT /admin/users/:id` - Update user
- `POST /admin/users/:id/toggle` - Toggle user active status
- `DELETE /admin/users/:id` - Delete user (soft delete)
- `POST /admin/invite-user` - Invite user via email
- `POST /admin/resend-invitation/:id` - Resend invitation
- `DELETE /admin/cancel-invitation/:id` - Cancel invitation

### Admin - Profile
- `GET /admin/profile` - Get current user's profile
- `PUT /admin/profile` - Update profile
- `POST /admin/profile/password` - Change password
- `POST /admin/profile/avatar` - Upload avatar

### Admin - Content
- `GET /admin/content/` - List content
- `POST /admin/content/` - Create content
- `GET /admin/content/:id/edit` - Get content for editing
- `PUT /admin/content/:id` - Update content
- `POST /admin/content/duplicate` - Duplicate content
- `GET /admin/content/:id/versions` - Get content versions
- `POST /admin/content/:id/restore/:version` - Restore version
- `POST /admin/content/bulk-action` - Bulk actions (publish, unpublish, delete)
- `DELETE /admin/content/:id` - Delete content

### Admin - Media
- `GET /admin/media/` - List media files
- `POST /api/media/upload` - Upload single file
- `POST /api/media/upload-multiple` - Upload multiple files
- `PATCH /api/media/:id` - Update metadata (alt, caption, tags, folder)
- `POST /api/media/create-folder` - Create folder
- `POST /api/media/bulk-move` - Move files to folder
- `POST /api/media/bulk-delete` - Bulk delete files
- `DELETE /api/media/:id` - Delete single file
- `GET /files/:folder/:filename` - Serve media file (public)

### Admin - Plugins
- `GET /admin/plugins` - List all plugins
- `GET /admin/plugins/:id` - Get plugin details
- `POST /admin/plugins/:id/activate` - Activate plugin
- `POST /admin/plugins/:id/deactivate` - Deactivate plugin
- `POST /admin/plugins/install` - Install plugin
- `POST /admin/plugins/:id/uninstall` - Uninstall plugin
- `POST /admin/plugins/:id/settings` - Update plugin settings

### Admin - Settings
- `GET /admin/settings/api/migrations/status` - Migration status
- `POST /admin/settings/api/migrations/run` - Run migrations
- `GET /admin/settings/api/migrations/validate` - Validate schema
- `GET /admin/settings/api/database-tools/stats` - Database stats
- `GET /admin/settings/api/database-tools/validate` - Validate database
- `POST /admin/settings/api/database-tools/backup` - Create backup
- `POST /admin/settings/api/database-tools/truncate` - Truncate tables
- `POST /admin/settings/general` - Update general settings

### Admin - Activity Logs
- `GET /admin/activity-logs` - View activity logs (with filters)
- `GET /admin/activity-logs/export` - Export logs as CSV

### Admin - Dashboard API
- `GET /admin/api/stats` - Dashboard statistics
- `GET /admin/api/storage` - Storage information
- `GET /admin/api/activity` - Recent activity

## Environment Variables

The environment file provides:
| Variable | Default | Description |
|----------|---------|-------------|
| `baseUrl` | `http://localhost:8787` | SonicJS server URL |
| `testUserEmail` | `admin@sonicjs.com` | Default admin email |
| `testUserPassword` | `sonicjs!` | Default admin password |
| `otpTestEmail` | `otp-test@example.com` | Email for OTP testing |

## Testing Workflow Examples

### OTP Login Flow
1. Set `otpEmail` variable to your test email
2. Run: `OTP Authentication > Request OTP Code`
   - In dev mode, the code is saved to `otpCode` automatically
3. Run: `OTP Authentication > Verify OTP Code`
   - Token is saved for subsequent requests

### Complete Content Workflow
1. Run: `Authentication > Seed Admin User` (first time only)
2. Run: `Admin - Content > Create Content`
   - Creates content and saves ID to `{{testContentId}}`
3. Run: `Admin - Content > Get Content by ID`
4. Run: `Admin - Content > Update Content`
5. Run: `Admin - Content > Delete Content`

### Media Upload & Management
1. Run: `Admin - Media > Upload Media (Single)`
   - Select a file in form-data
   - Media ID saved to `{{testMediaId}}`
2. Run: `Admin - Media > Update Media Metadata`
3. Run: `Admin - Media > Create Folder`
4. Run: `Admin - Media > Bulk Move Files`

## Tips

1. **Run requests in order**: For CRUD operations, create → read → update → delete
2. **Check console**: Response scripts log useful info to Postman console
3. **Modify body data**: Edit request bodies to test different scenarios
4. **Enable/disable query params**: Use Postman's checkboxes to toggle filters
5. **OTP Testing**: The OTP code is auto-saved to `otpCode` variable in dev mode

## Troubleshooting

**401 Unauthorized**: Token may be expired. Run "Login" request or let auto-login handle it.

**404 Not Found**: Check that the resource ID variables (`testContentId`, etc.) are set.

**500 Server Error**: Check SonicJS logs for details. May need to run migrations first.

**OTP endpoints not working**: Ensure the OTP Login plugin is activated in Admin > Plugins.

## Request Body Examples

### Register User
```json
{
  "email": "user@example.com",
  "password": "Password123!",
  "username": "myusername",
  "firstName": "John",
  "lastName": "Doe"
}
```

### Create Content
```json
{
  "title": "My Page Title",
  "slug": "my-page",
  "collection": "pages",
  "status": "draft",
  "fields": {
    "body": "Page content here",
    "excerpt": "Short description"
  }
}
```

### Upload Media
Uses `multipart/form-data`:
- `file` (File) - Required
- `folder` (string) - Optional, default: "uploads"

### Update Media Metadata
```json
{
  "alt": "Image description",
  "caption": "Photo caption",
  "tags": ["nature", "landscape"],
  "folder": "gallery"
}
```

## Additional Resources

- [SonicJS Documentation](https://github.com/lane711/sonicjs)
- [Postman Learning Center](https://learning.postman.com/)
