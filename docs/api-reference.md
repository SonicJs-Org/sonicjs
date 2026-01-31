# API Reference

SonicJS AI provides a comprehensive REST API for managing content, collections, media, and authentication programmatically. The API is built on Cloudflare Workers and features a three-tiered caching system for optimal performance.

## Base URL

```
https://your-domain.com/api
```

For local development:
```
http://localhost:8787/api
```

## Authentication

Most API endpoints require authentication. SonicJS uses **Better Auth** for sign-in and sessions. Authentication is session-cookie based (HTTP-only cookie `better-auth.session_token`).

### Sign-in (Better Auth)

**Endpoint:** `POST /auth/sign-in/email`

```bash
curl -X POST "http://localhost:8787/auth/sign-in/email" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@sonicjs.com",
    "password": "sonicjs!"
  }' \
  -c cookies.txt
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

On success, Better Auth sets a session cookie. Use `-c cookies.txt` (and `-b cookies.txt` on subsequent requests) to send the cookie with curl. In browsers, use `credentials: 'include'` so the cookie is sent automatically.

### Using the Session

Include the session cookie on authenticated requests. In browsers, send credentials so the cookie is attached:

```javascript
fetch('/api/...', { credentials: 'include' })
```

With curl, use the cookie file saved at sign-in:

```bash
curl -b cookies.txt "http://localhost:8787/auth/me"
```

### Session Refresh

Session refresh is handled automatically by Better Auth. The endpoint `POST /auth/refresh` returns a message to that effect; no new token is issued.

### User Registration

**Endpoint:** `POST /auth/sign-up/email` (Better Auth)

```bash
curl -X POST "http://localhost:8787/auth/sign-up/email" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "password": "securepassword123",
    "username": "newuser",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "password": "securepassword123",
  "name": "John Doe"
}
```

Optional fields (e.g. `username`, `firstName`, `lastName`) depend on your Better Auth user config. On success, Better Auth sets a session cookie. Use `-c cookies.txt` with curl to save it. See [authentication](authentication.md).

### Get Current User

**Endpoint:** `GET /auth/me`

Requires authentication (session cookie).

```bash
curl -X GET "http://localhost:8787/auth/me" \
  -b cookies.txt
```

**Response (200 OK):**
```json
{
  "user": {
    "id": "admin-user-id",
    "email": "admin@sonicjs.com",
    "username": "admin",
    "first_name": "Admin",
    "last_name": "User",
    "role": "admin",
    "created_at": 1730000000
  }
}
```

### Logout

**Endpoint:** `GET /auth/logout` or `POST /auth/logout`

Calls Better Auth sign-out and redirects to the login page. Include the session cookie so the session can be cleared.

## API Endpoints

### Health Check

**Endpoint:** `GET /api/health`

Check API health and view available schemas.

**Authentication:** None required

```bash
curl -X GET "http://localhost:8787/api/health"
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-06T12:34:56.789Z",
  "schemas": [
    "users",
    "blog-posts",
    "pages",
    "products"
  ]
}
```

### OpenAPI Specification

**Endpoint:** `GET /api/`

Get the complete OpenAPI 3.0 specification.

**Authentication:** None required

```bash
curl -X GET "http://localhost:8787/api/"
```

**Response (200 OK):**
```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "SonicJS AI API",
    "version": "0.1.0",
    "description": "RESTful API for SonicJS AI - A modern headless CMS built for Cloudflare's edge platform"
  },
  "servers": [
    {
      "url": "http://localhost:8787",
      "description": "Current server"
    }
  ],
  "paths": {
    "/api/health": {...},
    "/api/collections": {...},
    "/api/content": {...}
  }
}
```

## Collections

### List All Collections

**Endpoint:** `GET /api/collections`

Retrieve all active collections with their schemas.

**Authentication:** None required

**Cache Headers:** Cached for 5 minutes (API cache tier)

```bash
curl -X GET "http://localhost:8787/api/collections"
```

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "blog-posts-collection-id",
      "name": "blog-posts",
      "display_name": "Blog Posts",
      "description": "Blog posts collection",
      "schema": {
        "name": "blog-posts",
        "displayName": "Blog Posts",
        "fields": [
          {
            "name": "title",
            "type": "text",
            "label": "Title",
            "required": true
          },
          {
            "name": "content",
            "type": "richtext",
            "label": "Content"
          },
          {
            "name": "excerpt",
            "type": "textarea",
            "label": "Excerpt"
          },
          {
            "name": "featuredImage",
            "type": "media",
            "label": "Featured Image"
          }
        ]
      },
      "is_active": 1,
      "created_at": 1730000000,
      "updated_at": 1730000000
    }
  ],
  "meta": {
    "count": 1,
    "timestamp": "2025-10-06T12:34:56.789Z",
    "cache": {
      "hit": false,
      "source": "database"
    },
    "timing": {
      "total": 45,
      "execution": 12,
      "unit": "ms"
    }
  }
}
```

**Response Headers:**
```
X-Cache-Status: MISS
X-Cache-Source: database
X-Response-Time: 45ms
```

**Cached Response Headers:**
```
X-Cache-Status: HIT
X-Cache-Source: kv
X-Cache-TTL: 234
X-Response-Time: 8ms
```

## Content Management

### List All Content

**Endpoint:** `GET /api/content`

Retrieve all content items with pagination.

**Authentication:** None required

**Cache Headers:** Cached for 5 minutes (API cache tier)

**Query Parameters:**
- `limit` (optional): Maximum number of items to return (default: 50, max: 100)

```bash
curl -X GET "http://localhost:8787/api/content?limit=10"
```

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "content-uuid-1",
      "title": "Welcome to SonicJS AI",
      "slug": "welcome-to-sonicjs-ai",
      "status": "published",
      "collectionId": "blog-posts-collection-id",
      "data": {
        "title": "Welcome to SonicJS AI",
        "content": "<p>This is the content of my first blog post...</p>",
        "excerpt": "Getting started with SonicJS AI",
        "featuredImage": {
          "id": "media-id-1",
          "url": "https://pub-sonicjs-media-dev.r2.dev/uploads/image.jpg"
        }
      },
      "created_at": "2025-10-05T10:30:00.000Z",
      "updated_at": "2025-10-05T10:30:00.000Z"
    }
  ],
  "meta": {
    "count": 1,
    "timestamp": "2025-10-06T12:34:56.789Z",
    "cache": {
      "hit": true,
      "source": "memory",
      "ttl": 278
    },
    "timing": {
      "total": 3,
      "execution": 1,
      "unit": "ms"
    }
  }
}
```

**Response Headers:**
```
X-Cache-Status: HIT
X-Cache-Source: memory
X-Cache-TTL: 278
X-Response-Time: 3ms
```

### Get Content by Collection

**Endpoint:** `GET /api/collections/{collection}/content`

Retrieve content for a specific collection.

**Authentication:** None required

**Cache Headers:** Cached for 5 minutes (API cache tier)

**Path Parameters:**
- `collection` (required): Collection name (e.g., "blog-posts")

**Query Parameters:**
- `limit` (optional): Maximum number of items to return (default: 50, max: 100)

```bash
curl -X GET "http://localhost:8787/api/collections/blog-posts/content?limit=25"
```

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "content-uuid-1",
      "title": "Welcome to SonicJS AI",
      "slug": "welcome-to-sonicjs-ai",
      "status": "published",
      "collectionId": "blog-posts-collection-id",
      "data": {
        "title": "Welcome to SonicJS AI",
        "content": "<p>This is my blog post content...</p>"
      },
      "created_at": "2025-10-05T10:30:00.000Z",
      "updated_at": "2025-10-05T10:30:00.000Z"
    }
  ],
  "meta": {
    "collection": {
      "id": "blog-posts-collection-id",
      "name": "blog-posts",
      "display_name": "Blog Posts",
      "schema": {...}
    },
    "count": 1,
    "timestamp": "2025-10-06T12:34:56.789Z",
    "cache": {
      "hit": false,
      "source": "database"
    },
    "timing": {
      "total": 28,
      "execution": 15,
      "unit": "ms"
    }
  }
}
```

**Error Response (404 Not Found):**
```json
{
  "error": "Collection not found"
}
```

## Media Management

All media endpoints require authentication.

### Upload Single File

**Endpoint:** `POST /api/media/upload`

**Authentication:** Required (Bearer token or auth cookie)

**Content-Type:** `multipart/form-data`

**Supported File Types:**
- Images: JPEG, PNG, GIF, WebP, SVG
- Documents: PDF, TXT, DOC, DOCX
- Videos: MP4, WebM, OGG, AVI, MOV
- Audio: MP3, WAV, OGG, M4A

**Max File Size:** 50MB

```bash
curl -X POST "http://localhost:8787/api/media/upload" \
  -H "Authorization: Bearer {token}" \
  -F "file=@/path/to/image.jpg" \
  -F "folder=blog-images"
```

**Request Body (multipart/form-data):**
- `file` (required): The file to upload
- `folder` (optional): Folder path (default: "uploads")

**Response (200 OK):**
```json
{
  "success": true,
  "file": {
    "id": "V1StGXR8_Z5jdHi6B",
    "filename": "V1StGXR8_Z5jdHi6B.jpg",
    "originalName": "my-image.jpg",
    "mimeType": "image/jpeg",
    "size": 245678,
    "width": 1920,
    "height": 1080,
    "publicUrl": "https://pub-sonicjs-media-dev.r2.dev/blog-images/V1StGXR8_Z5jdHi6B.jpg",
    "thumbnailUrl": "https://imagedelivery.net/account-id/blog-images/V1StGXR8_Z5jdHi6B.jpg/thumbnail",
    "uploadedAt": "2025-10-06T12:34:56.789Z"
  }
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "File validation failed",
  "details": [
    {
      "code": "too_big",
      "message": "File size exceeds 50MB limit",
      "path": ["size"]
    }
  ]
}
```

### Upload Multiple Files

**Endpoint:** `POST /api/media/upload-multiple`

**Authentication:** Required

```bash
curl -X POST "http://localhost:8787/api/media/upload-multiple" \
  -H "Authorization: Bearer {token}" \
  -F "files=@/path/to/image1.jpg" \
  -F "files=@/path/to/image2.png" \
  -F "folder=gallery"
```

**Request Body (multipart/form-data):**
- `files` (required): Multiple files to upload
- `folder` (optional): Folder path (default: "uploads")

**Response (200 OK):**
```json
{
  "success": true,
  "uploaded": [
    {
      "id": "file-id-1",
      "filename": "file-id-1.jpg",
      "originalName": "image1.jpg",
      "mimeType": "image/jpeg",
      "size": 123456,
      "publicUrl": "https://pub-sonicjs-media-dev.r2.dev/gallery/file-id-1.jpg",
      "uploadedAt": "2025-10-06T12:34:56.789Z"
    },
    {
      "id": "file-id-2",
      "filename": "file-id-2.png",
      "originalName": "image2.png",
      "mimeType": "image/png",
      "size": 234567,
      "publicUrl": "https://pub-sonicjs-media-dev.r2.dev/gallery/file-id-2.png",
      "uploadedAt": "2025-10-06T12:34:56.789Z"
    }
  ],
  "errors": [],
  "summary": {
    "total": 2,
    "successful": 2,
    "failed": 0
  }
}
```

### Delete File

**Endpoint:** `DELETE /api/media/{id}`

**Authentication:** Required (uploader or admin role)

**Path Parameters:**
- `id` (required): File ID

```bash
curl -X DELETE "http://localhost:8787/api/media/V1StGXR8_Z5jdHi6B" \
  -H "Authorization: Bearer {token}"
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "File deleted successfully"
}
```

**Error Response (403 Forbidden):**
```json
{
  "error": "Permission denied"
}
```

**Error Response (404 Not Found):**
```json
{
  "error": "File not found"
}
```

### Bulk Delete Files

**Endpoint:** `POST /api/media/bulk-delete`

**Authentication:** Required (uploader or admin role)

**Max Files Per Operation:** 50

```bash
curl -X POST "http://localhost:8787/api/media/bulk-delete" \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "fileIds": ["file-id-1", "file-id-2", "file-id-3"]
  }'
```

**Request Body:**
```json
{
  "fileIds": ["file-id-1", "file-id-2"]
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "deleted": [
    {
      "fileId": "file-id-1",
      "filename": "image1.jpg",
      "success": true
    }
  ],
  "errors": [
    {
      "fileId": "file-id-2",
      "error": "Permission denied"
    }
  ],
  "summary": {
    "total": 2,
    "successful": 1,
    "failed": 1
  }
}
```

### Update File Metadata

**Endpoint:** `PATCH /api/media/{id}`

**Authentication:** Required (uploader or admin role)

**Path Parameters:**
- `id` (required): File ID

**Allowed Fields:**
- `alt`: Alt text for images
- `caption`: Image caption
- `tags`: Array of tags
- `folder`: Move file to different folder

```bash
curl -X PATCH "http://localhost:8787/api/media/V1StGXR8_Z5jdHi6B" \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "alt": "Beautiful sunset over the ocean",
    "caption": "Sunset at Malibu Beach",
    "tags": ["nature", "sunset", "ocean"]
  }'
```

**Request Body:**
```json
{
  "alt": "Beautiful sunset over the ocean",
  "caption": "Sunset at Malibu Beach",
  "tags": ["nature", "sunset", "ocean"],
  "folder": "featured-images"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "File updated successfully"
}
```

## Cache System

SonicJS AI features a three-tiered caching system:

### Cache Tiers

1. **Tier 1: In-Memory Cache** (fastest, region-specific)
   - Sub-millisecond access
   - Regional edge location only
   - Used for hot data

2. **Tier 2: Cloudflare KV** (fast, global)
   - 1-10ms access globally
   - Distributed across all edge locations
   - Used for frequently accessed data

3. **Tier 3: Database** (source of truth)
   - Direct database queries
   - Used when cache misses occur

### Cache Headers

All cached responses include the following headers:

- `X-Cache-Status`: `HIT` or `MISS`
- `X-Cache-Source`: `memory`, `kv`, or `database`
- `X-Cache-TTL`: Time remaining in cache (seconds) - only on HIT
- `X-Response-Time`: Total response time in milliseconds

### Cache TTL by Entity

| Entity Type | TTL | Memory Cache | KV Cache |
|-------------|-----|--------------|----------|
| API responses | 5 minutes | ✓ | ✓ |
| Collections | 2 hours | ✓ | ✓ |
| Content | 1 hour | ✓ | ✓ |
| User data | 15 minutes | ✓ | ✓ |
| Media metadata | 1 hour | ✓ | ✓ |
| Configuration | 2 hours | ✓ | ✓ |
| Session data | 30 minutes | ✓ | ✗ |

### Cache Invalidation

Cache is automatically invalidated on:
- Content updates: `content.update`, `content.delete`, `content.publish`
- User updates: `user.update`, `user.delete`, `auth.login`
- Media updates: `media.upload`, `media.delete`, `media.update`
- Collection updates: `collection.update`, `collection.delete`

## Error Handling

The API uses standard HTTP status codes to indicate success or failure:

### Success Codes

- `200 OK` - Request succeeded
- `201 Created` - Resource created successfully
- `204 No Content` - Request succeeded with no content to return

### Client Error Codes

- `400 Bad Request` - Invalid request parameters or body
- `401 Unauthorized` - Authentication required or token invalid
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation failed

### Server Error Codes

- `500 Internal Server Error` - Server error occurred
- `503 Service Unavailable` - Service temporarily unavailable

### Error Response Format

All error responses follow this format:

```json
{
  "error": "Human-readable error message",
  "details": {
    "field": "fieldName",
    "code": "ERROR_CODE",
    "message": "Detailed error description"
  }
}
```

**Examples:**

**Validation Error (400):**
```json
{
  "error": "File validation failed",
  "details": [
    {
      "code": "invalid_type",
      "message": "Unsupported file type",
      "path": ["type"]
    }
  ]
}
```

**Authentication Error (401):**
```json
{
  "error": "Invalid or expired token"
}
```

**Permission Error (403):**
```json
{
  "error": "Permission denied"
}
```

**Not Found Error (404):**
```json
{
  "error": "Collection not found"
}
```

**Server Error (500):**
```json
{
  "error": "Failed to fetch collections"
}
```

## Rate Limiting

**Note:** Rate limiting is planned but not currently implemented. Future versions will include:

- **Authenticated requests**: 1000 requests per hour per user
- **Unauthenticated requests**: 100 requests per hour per IP

Rate limit headers (planned):
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1730000000
```

## Pagination

Most list endpoints support pagination through query parameters.

### Query Parameters

- `limit`: Number of items per page (default: 50, max: 100)
- `offset`: Number of items to skip (default: 0)
- `page`: Page number (alternative to offset, 1-based)

**Example with limit:**
```bash
curl -X GET "http://localhost:8787/api/content?limit=10"
```

**Example with offset:**
```bash
curl -X GET "http://localhost:8787/api/content?limit=10&offset=20"
```

**Example with page:**
```bash
curl -X GET "http://localhost:8787/api/content?limit=10&page=3"
```

### Pagination Response

```json
{
  "data": [...],
  "meta": {
    "count": 10,
    "limit": 10,
    "offset": 20,
    "page": 3,
    "totalPages": 10,
    "totalItems": 95
  }
}
```

## OpenAPI Specification

SonicJS AI provides OpenAPI 3.0 specifications for all endpoints.

### Access Methods

1. **JSON Specification**
   ```bash
   curl -X GET "http://localhost:8787/api/"
   ```

2. **Scalar UI** (Modern interactive documentation)
   - Visit: `http://localhost:8787/docs`
   - Built-in API playground
   - Real-time testing

3. **Swagger UI** (Traditional interface)
   - Visit: `http://localhost:8787/docs/swagger`
   - Classic OpenAPI experience

4. **Raw OpenAPI JSON**
   - Visit: `http://localhost:8787/docs/openapi.json`
   - Download specification file

### Using OpenAPI Specification

Import the specification into tools like:
- **Postman**: Import → Link → `http://localhost:8787/api/`
- **Insomnia**: Import → URL → `http://localhost:8787/api/`
- **OpenAPI Generator**: Generate client SDKs in any language
- **Stoplight Studio**: API design and documentation

## Code Examples

### JavaScript/TypeScript (Fetch API)

**Get Collections:**
```typescript
const response = await fetch('http://localhost:8787/api/collections', {
  headers: {
    'Content-Type': 'application/json'
  }
})

const { data, meta } = await response.json()
console.log(`Retrieved ${meta.count} collections`)
console.log('Cache status:', meta.cache.hit ? 'HIT' : 'MISS')
```

**Authenticated Request:**
```typescript
const token = 'your-jwt-token'

const response = await fetch('http://localhost:8787/api/media/upload', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`
  },
  body: formData
})

const result = await response.json()
if (result.success) {
  console.log('File uploaded:', result.file.publicUrl)
}
```

**Login and Get Content:**
```typescript
// Login
const loginResponse = await fetch('http://localhost:8787/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'admin@sonicjs.com',
    password: 'sonicjs!'
  })
})

const { token } = await loginResponse.json()

// Get content
const contentResponse = await fetch('http://localhost:8787/api/content?limit=25', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
})

const { data } = await contentResponse.json()
console.log(`Retrieved ${data.length} content items`)
```

### Python (Requests Library)

**Install:**
```bash
pip install requests
```

**Get Collections:**
```python
import requests

response = requests.get('http://localhost:8787/api/collections')
data = response.json()

print(f"Retrieved {data['meta']['count']} collections")
print(f"Cache status: {data['meta']['cache']['hit']}")
print(f"Response time: {data['meta']['timing']['total']}ms")

for collection in data['data']:
    print(f"- {collection['display_name']} ({collection['name']})")
```

**Upload File:**
```python
import requests

# Login first
login_response = requests.post(
    'http://localhost:8787/auth/login',
    json={
        'email': 'admin@sonicjs.com',
        'password': 'sonicjs!'
    }
)
token = login_response.json()['token']

# Upload file
files = {'file': open('image.jpg', 'rb')}
headers = {'Authorization': f'Bearer {token}'}

response = requests.post(
    'http://localhost:8787/api/media/upload',
    headers=headers,
    files=files,
    data={'folder': 'uploads'}
)

result = response.json()
if result['success']:
    print(f"File uploaded: {result['file']['publicUrl']}")
    print(f"File ID: {result['file']['id']}")
```

**Paginated Content Fetch:**
```python
import requests

def get_all_content(base_url, token=None, limit=50):
    all_items = []
    offset = 0

    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'

    while True:
        response = requests.get(
            f'{base_url}/api/content',
            params={'limit': limit, 'offset': offset},
            headers=headers
        )
        data = response.json()

        items = data['data']
        all_items.extend(items)

        if len(items) < limit:
            break

        offset += limit

    return all_items

content = get_all_content('http://localhost:8787')
print(f"Total content items: {len(content)}")
```

### cURL Examples

**Get Collections:**
```bash
curl -X GET "http://localhost:8787/api/collections" \
  -H "Content-Type: application/json"
```

**Login:**
```bash
curl -X POST "http://localhost:8787/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@sonicjs.com",
    "password": "sonicjs!"
  }'
```

**Get Content with Authentication:**
```bash
TOKEN="your-jwt-token"

curl -X GET "http://localhost:8787/api/content?limit=25" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

**Upload File:**
```bash
TOKEN="your-jwt-token"

curl -X POST "http://localhost:8787/api/media/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/image.jpg" \
  -F "folder=blog-images"
```

**Get Collection Content:**
```bash
curl -X GET "http://localhost:8787/api/collections/blog-posts/content?limit=10" \
  -H "Content-Type: application/json"
```

**Delete Media File:**
```bash
TOKEN="your-jwt-token"

curl -X DELETE "http://localhost:8787/api/media/V1StGXR8_Z5jdHi6B" \
  -H "Authorization: Bearer $TOKEN"
```

**Bulk Delete Media:**
```bash
TOKEN="your-jwt-token"

curl -X POST "http://localhost:8787/api/media/bulk-delete" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fileIds": ["file-id-1", "file-id-2", "file-id-3"]
  }'
```

**View Response Headers:**
```bash
curl -X GET "http://localhost:8787/api/collections" \
  -H "Content-Type: application/json" \
  -i
```

**Example with Cache Headers:**
```bash
# First request (cache MISS)
curl -X GET "http://localhost:8787/api/content?limit=10" -i

# Response headers:
# X-Cache-Status: MISS
# X-Cache-Source: database
# X-Response-Time: 45ms

# Second request (cache HIT)
curl -X GET "http://localhost:8787/api/content?limit=10" -i

# Response headers:
# X-Cache-Status: HIT
# X-Cache-Source: memory
# X-Cache-TTL: 294
# X-Response-Time: 2ms
```

## Best Practices

### Authentication

1. **Store tokens securely**: Never expose tokens in client-side code or version control
2. **Use HTTPS in production**: Always use secure connections for token transmission
3. **Refresh tokens regularly**: Implement token refresh before expiration
4. **Handle 401 errors**: Redirect to login or refresh token when authentication fails

### Caching

1. **Leverage cache headers**: Check `X-Cache-Status` to monitor cache effectiveness
2. **Use appropriate limits**: Request only the data you need with `limit` parameter
3. **Cache on client side**: Store frequently accessed data in client cache
4. **Monitor cache TTL**: Be aware of cache expiration times

### Performance

1. **Batch operations**: Use bulk endpoints for multiple operations
2. **Optimize queries**: Use filters and limits to reduce data transfer
3. **Monitor response times**: Track `X-Response-Time` header for performance insights
4. **Use collections endpoint**: Fetch specific collection content rather than all content

### Error Handling

1. **Handle all status codes**: Implement proper error handling for 4xx and 5xx responses
2. **Parse error details**: Use error.details for specific validation errors
3. **Implement retry logic**: Retry failed requests with exponential backoff
4. **Log errors**: Track API errors for debugging and monitoring

## Support & Resources

- **Documentation**: [http://localhost:8787/docs](http://localhost:8787/docs)
- **OpenAPI Playground**: [http://localhost:8787/docs](http://localhost:8787/docs)
- **GitHub Repository**: [https://github.com/lane711/sonicjs-ai](https://github.com/lane711/sonicjs-ai)
- **Community Discussions**: [https://github.com/lane711/sonicjs-ai/discussions](https://github.com/lane711/sonicjs-ai/discussions)
- **Report Issues**: [https://github.com/lane711/sonicjs-ai/issues](https://github.com/lane711/sonicjs-ai/issues)

## Version History

### v0.1.0 (Current)
- Initial API implementation
- Session-based authentication (Better Auth)
- Collections and content endpoints
- Media upload and management
- Three-tiered caching system
- OpenAPI 3.0 specification
- Cache headers and metadata
