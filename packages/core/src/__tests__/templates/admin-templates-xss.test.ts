import { describe, it, expect } from 'vitest'
import { renderContentListPage } from '../../templates/pages/admin-content-list.template'
import { renderUsersListPage } from '../../templates/pages/admin-users-list.template'
import { renderContentFormPage } from '../../templates/pages/admin-content-form.template'
import { renderMediaFileDetails } from '../../templates/components/media-file-details.template'
import { renderSettingsPage } from '../../templates/pages/admin-settings.template'
import { renderMediaLibraryPage } from '../../templates/pages/admin-media-library.template'

// A payload that breaks out of both element-text and double-quoted-attribute contexts.
const SCRIPT = `<script>alert('xss')</script>`
const ESCAPED_SCRIPT = `&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;`
const ATTR_BREAKOUT = `"><script>alert(1)</script>`
const ESCAPED_ATTR_BREAKOUT = `&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`

describe('admin template XSS escaping', () => {
  describe('content list (stored: any content author → admin viewer)', () => {
    it('escapes the content title and slug', () => {
      const html = renderContentListPage({
        modelName: 'posts',
        status: 'all',
        page: 1,
        models: [],
        newContentCollections: [],
        contentItems: [
          {
            id: 'c1',
            title: SCRIPT,
            slug: `slug-${SCRIPT}`,
            modelName: 'posts',
            statusBadge: '',
            authorName: 'author',
            formattedDate: '',
            availableActions: [],
          },
        ],
        totalItems: 1,
        itemsPerPage: 10,
      })

      expect(html).not.toContain(SCRIPT)
      expect(html).toContain(ESCAPED_SCRIPT)
    })
  })

  describe('users list', () => {
    it('escapes the avatar src (attribute) and the first/last name (alt)', () => {
      const html = renderUsersListPage({
        users: [
          {
            id: 'u1',
            email: 'a@b.c',
            firstName: SCRIPT,
            lastName: 'Smith',
            role: 'admin',
            avatar: ATTR_BREAKOUT,
            isActive: true,
            createdAt: 0,
            updatedAt: 0,
          },
        ],
        currentPage: 1,
        totalPages: 1,
        totalUsers: 1,
      })

      // avatar src attribute breakout must be neutralized
      expect(html).not.toContain(ATTR_BREAKOUT)
      expect(html).toContain(ESCAPED_ATTR_BREAKOUT)
      // firstName rendered into the alt attribute must be escaped
      expect(html).not.toContain(SCRIPT)
      expect(html).toContain(ESCAPED_SCRIPT)
    })
  })

  describe('media file details', () => {
    it('escapes filename, alt, caption, folder and tags', () => {
      const html = renderMediaFileDetails({
        file: {
          id: 'm1',
          filename: 'f.png',
          original_name: `name-${SCRIPT}`,
          mime_type: 'image/png',
          size: 10,
          public_url: 'https://cdn.example/f.png',
          alt: `alt-${ATTR_BREAKOUT}`,
          caption: `caption-${SCRIPT}`,
          tags: [`tag-${SCRIPT}`],
          uploaded_at: '',
          fileSize: '10 B',
          uploadedAt: '',
          isImage: true,
          isVideo: false,
          isDocument: false,
          folder: `folder-${SCRIPT}`,
          width: 1,
          height: 1,
        },
      })

      expect(html).not.toContain(SCRIPT)
      expect(html).not.toContain(ATTR_BREAKOUT)
      // original_name / caption / folder / tags in text or value contexts
      expect(html).toContain(ESCAPED_SCRIPT)
      // alt value attribute breakout neutralized
      expect(html).toContain(ESCAPED_ATTR_BREAKOUT)
    })

    it('escapes public_url in onclick JS string, href attributes, and text content', () => {
      const jsBreakout = `'); alert(document.cookie);//`
      const html = renderMediaFileDetails({
        file: {
          id: 'm2',
          filename: 'f.png',
          original_name: 'f.png',
          mime_type: 'image/png',
          size: 10,
          public_url: jsBreakout,
          alt: '',
          caption: '',
          tags: [],
          uploaded_at: '',
          fileSize: '10 B',
          uploadedAt: '',
          isImage: true,
          isVideo: false,
          isDocument: false,
          folder: '',
          width: 1,
          height: 1,
        },
      })
      // raw breakout string must not appear anywhere
      expect(html).not.toContain(jsBreakout)
      // onclick must use JSON-serialised string (double-quoted, special chars escaped)
      expect(html).toContain('copyToClipboard(')
      expect(html).not.toContain(`copyToClipboard('${jsBreakout}')`)
    })

    it('rejects javascript: scheme in public_url href', () => {
      const html = renderMediaFileDetails({
        file: {
          id: 'm3',
          filename: 'f.png',
          original_name: 'f.png',
          mime_type: 'image/png',
          size: 10,
          public_url: 'javascript:alert(1)',
          alt: '',
          caption: '',
          tags: [],
          uploaded_at: '',
          fileSize: '10 B',
          uploadedAt: '',
          isImage: true,
          isVideo: false,
          isDocument: false,
          folder: '',
          width: 1,
          height: 1,
        },
      })
      // javascript: scheme must not appear in any href
      expect(html).not.toContain('href="javascript:')
    })
  })

  describe('content form (reflected ?ref= referrer param)', () => {
    it('escapes referrerParams in the back-link href and the hidden input value', () => {
      const html = renderContentFormPage({
        collection: { id: 'posts', name: 'posts', display_name: 'Posts', schema: {} },
        fields: [],
        referrerParams: `collection=posts${ATTR_BREAKOUT}`,
      })

      expect(html).not.toContain(ATTR_BREAKOUT)
      expect(html).toContain(ESCAPED_ATTR_BREAKOUT)
    })
  })

  describe('general settings (admin-controlled, stored)', () => {
    it('escapes siteName, adminEmail and siteDescription', () => {
      const html = renderSettingsPage({
        activeTab: 'general',
        settings: {
          general: {
            siteName: `site-${ATTR_BREAKOUT}`,
            adminEmail: `mail-${ATTR_BREAKOUT}`,
            siteDescription: `desc-${SCRIPT}`,
            timezone: 'UTC',
            language: 'en',
            maintenanceMode: false,
          },
        },
      })

      // siteName / adminEmail sit in value="…" attributes
      expect(html).not.toContain(ATTR_BREAKOUT)
      expect(html).toContain(ESCAPED_ATTR_BREAKOUT)
      // siteDescription is textarea element text
      expect(html).not.toContain(SCRIPT)
      expect(html).toContain(ESCAPED_SCRIPT)
    })
  })

  describe('media library folder sidebar', () => {
    it('escapes the folder name in the link body and encodes it in the href', () => {
      const html = renderMediaLibraryPage({
        files: [],
        folders: [{ folder: `folder-${SCRIPT}`, count: 1 }],
        types: [],
        currentFolder: `cur-${ATTR_BREAKOUT}`,
        currentType: '',
        currentView: 'grid',
        currentPage: 1,
        totalFiles: 0,
        hasNextPage: false,
      })

      expect(html).not.toContain(SCRIPT)
      expect(html).toContain(ESCAPED_SCRIPT)
      // href uses encodeURIComponent, so no raw angle bracket or quote reaches the URL
      expect(html).toContain(`folder=${encodeURIComponent(`folder-${SCRIPT}`)}`)
      // the currentFolder/currentType hidden inputs are attribute sinks too
      expect(html).not.toContain(ATTR_BREAKOUT)
      expect(html).toContain(ESCAPED_ATTR_BREAKOUT)
      // the bulk-move onclick is a JS-string sink: the folder goes in as a JSON literal,
      // so a quote cannot close the JS string and start new statements
      expect(html).not.toContain(`performBulkMove('folder-`)
      expect(html).toContain('performBulkMove(&quot;folder-')
    })
  })

  describe('safe values render unchanged', () => {
    it('does not corrupt a normal title', () => {
      const html = renderContentListPage({
        modelName: 'posts',
        status: 'all',
        page: 1,
        models: [],
        newContentCollections: [],
        contentItems: [
          {
            id: 'c1',
            title: 'My First Post',
            slug: 'my-first-post',
            modelName: 'posts',
            statusBadge: '',
            authorName: 'author',
            formattedDate: '',
            availableActions: [],
          },
        ],
        totalItems: 1,
        itemsPerPage: 10,
      })

      expect(html).toContain('My First Post')
      expect(html).toContain('my-first-post')
    })
  })
})
