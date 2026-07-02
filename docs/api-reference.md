# API Reference

SonicJS provides a REST API for managing content, collections, media, and authentication. The API runs on Cloudflare Workers with a three-tiered caching system.

## Base URL

```
https://your-domain.com/api
```

For local development:
```
http://localhost:8787/api
```

## Authentication

SonicJS uses [Better Auth](https://www.better-auth.com/) for session management. Sessions are stored as HTTP-only cookies — no Bearer tokens needed for browser clients.

### Sign In

**Endpoint:** `POST /auth/sign-in/email`

```bash
curl -X POST "http://localhost:8787/auth/sign-in/email" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "admin@sonicjs.com",
    "password": "sonicjs!"
  }'
```

The response sets a `better-auth.session_token` HTTP-only cookie. Use `-b cookies.txt` on subsequent requests.

### Sign Up

**Endpoint:** `POST /auth/sign-up/email`

```bash
curl -X POST "http://localhost:8787/auth/sign-up/email" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "newuser@example.com",
    "password": "securepassword123",
    "name": "John Doe"
  }'
```

The first registered user automatically receives the `admin` role.

### Get Current User

**Endpoint:** `GET /auth/me`

Requires authentication (session cookie).

```bash
curl -X GET "http://localhost:8787/auth/me" -b cookies.txt
```

### Sign Out

**Endpoint:** `POST /auth/sign-out` or `GET /auth/logout`

```bash
curl -X POST "http://localhost:8787/auth/sign-out" -b cookies.txt
```

### Frontend Usage

```typescript
// Sign in (browser — cookie is set automatically)
const res = await fetch('http://localhost:8787/auth/sign-in/email', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
})

// Authenticated requests (cookie sent automatically)
const content = await fetch('http://localhost:8787/api/content', {
  credentials: 'include',
})
```

`credentials: 'include'` is required so the browser sends the session cookie. See [Authentication docs](authentication.md) for CORS configuration.

### Content Access Control

Content visibility is controlled by **base grants** on each collection's document type. Collections default to **deny** for public access — only authenticated users with appropriate roles (admin, editor) can access content unless the collection explicitly opts in via its `access` property.

Anonymous requests that reach a collection without `public: ['read']` in its base grants will receive an empty result set (the documents are filtered out by the ACL layer).

See [Authentication > Content Access Control](authentication.md#content-access-control) for details.

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

**Authentication:** Optional (session cookie). Anonymous requests see only published content from collections with public read access. Authenticated admin/editor requests see drafts too.

**Cache Headers:** Cached for 5 minutes (API cache tier)

**Query Parameters:**
- `limit` (optional): Maximum number of items to return (default: 50, max: 100)
- `status` (optional): Content status filter for admin/editor requests. Anonymous requests are limited to published results.

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

**Authentication:** Optional (session cookie). Anonymous requests see only published content from collections with public read access. Authenticated admin/editor requests see drafts too.

**Cache Headers:** Cached for 5 minutes (API cache tier)

**Path Parameters:**
- `collection` (required): Collection name (e.g., "blog-posts")

**Query Parameters:**
- `limit` (optional): Maximum number of items to return (default: 50, max: 100)
- `status` (optional): Content status filter for admin/editor requests. Anonymous requests are limited to published results.

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

All media endpoints require authentication (session cookie).

### Upload Single File

**Endpoint:** `POST /api/media/upload`

**Authentication:** Required (session cookie)

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

**Authenticated Request (browser):**
```typescript
// Session cookie is sent automatically with credentials: 'include'
const response = await fetch('http://localhost:8787/api/media/upload', {
  method: 'POST',
  credentials: 'include',
  body: formData,
})

const result = await response.json()
if (result.success) {
  console.log('File uploaded:', result.file.publicUrl)
}
```

**Sign In and Get Content:**
```typescript
// Sign in (sets session cookie)
await fetch('http://localhost:8787/auth/sign-in/email', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'admin@sonicjs.com',
    password: 'sonicjs!',
  }),
})

// Get content (session cookie sent automatically)
const contentResponse = await fetch('http://localhost:8787/api/content?limit=25', {
  credentials: 'include',
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

session = requests.Session()

# Sign in (session cookie stored automatically)
session.post(
    'http://localhost:8787/auth/sign-in/email',
    json={
        'email': 'admin@sonicjs.com',
        'password': 'sonicjs!'
    }
)

# Upload file (cookie sent automatically via session)
files = {'file': open('image.jpg', 'rb')}
response = session.post(
    'http://localhost:8787/api/media/upload',
    files=files,
    data={'folder': 'uploads'}
)

result = response.json()
if result['success']:
    print(f"File uploaded: {result['file']['publicUrl']}")
```

**Paginated Content Fetch:**
```python
import requests

def get_all_content(base_url, session=None, limit=50):
    all_items = []
    offset = 0
    getter = session or requests

    while True:
        response = getter.get(
            f'{base_url}/api/content',
            params={'limit': limit, 'offset': offset},
        )
        data = response.json()

        items = data['data']
        all_items.extend(items)

        if len(items) < limit:
            break

        offset += limit

    return all_items

# Public content (no auth needed if collection has public read access)
content = get_all_content('http://localhost:8787')
print(f"Total content items: {len(content)}")
```

### cURL Examples

**Get Collections:**
```bash
curl -X GET "http://localhost:8787/api/collections" \
  -H "Content-Type: application/json"
```

**Sign In (save session cookie):**
```bash
curl -X POST "http://localhost:8787/auth/sign-in/email" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "admin@sonicjs.com",
    "password": "sonicjs!"
  }'
```

**Get Content with Authentication:**
```bash
curl -X GET "http://localhost:8787/api/content?limit=25" \
  -b cookies.txt \
  -H "Content-Type: application/json"
```

**Upload File:**
```bash
curl -X POST "http://localhost:8787/api/media/upload" \
  -b cookies.txt \
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
curl -X DELETE "http://localhost:8787/api/media/V1StGXR8_Z5jdHi6B" \
  -b cookies.txt
```

**Bulk Delete Media:**
```bash
curl -X POST "http://localhost:8787/api/media/bulk-delete" \
  -b cookies.txt \
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

1. **Use `credentials: 'include'`**: Required for browsers to send session cookies cross-origin
2. **Configure CORS_ORIGINS**: List all frontend origins in `wrangler.toml`
3. **Use HTTPS in production**: Session cookies require secure connections
4. **Handle 401 errors**: Redirect to login when the session expires

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

## Related Documentation

- [Authentication & Authorization](authentication.md) — Sessions, RBAC, content ACL
- [Collections Configuration](collections-config.md) — Schema and access config
- [API Filtering](api-filtering.md) — Query parameter reference
- [Content Management](content-management.md) — Draft/publish workflow
