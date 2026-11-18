# SonicJS E2E Test Specification

## Overview
This document outlines all user journeys that should be covered by end-to-end tests in the SonicJS admin system. These tests focus on complete user workflows and screen navigation rather than individual component behavior.

## Test Scope
- **In Scope**: Complete user workflows, screen navigation, data persistence, integration between features
- **Out of Scope**: Form field validations, individual component behavior, unit-testable logic

---

## 1. Authentication Journeys

### 1.1 Login Flow
- Navigate to root URL → Redirect to login page
- Enter valid credentials → Successfully login → Redirect to dashboard
- Logout → Return to login page
- Access protected route while logged out → Redirect to login with error message

### 1.2 Session Management
- Login → Navigate between pages → Session persists
- Login → Wait for session timeout → Attempt action → Redirect to login
- Login → Open new tab → Session shared across tabs

---

## 2. Dashboard Journey

### 2.1 Dashboard Overview
- Login → View dashboard with statistics cards
- Verify all stat cards load (Collections, Content, Media, Users)
- Click on stat cards → Navigate to respective sections
- Verify recent activity feed displays

---

## 3. Content Management Journeys

### 3.1 Content Listing
- Navigate to Content section → View content list
- Filter by collection type → List updates
- Filter by status (Draft/Published/Archived) → List updates
- Search content → Results update
- Sort columns → Data reorders
- Pagination → Navigate through pages

### 3.2 Content Creation
- Click "New Content" → Select collection type → Fill form → Save
- Verify content appears in list
- Create content as draft → Verify draft status
- Create content as published → Verify published status

### 3.3 Content Editing
- Select existing content → Edit form loads with data
- Modify content → Save → Verify changes persist
- Change content status → Verify workflow updates
- View content history → See version list

### 3.4 Content Workflow
- Create draft → Submit for review → Approve → Publish
- Create content → Schedule for future → Verify scheduled status
- Published content → Archive → Verify archived status

---

## 4. Collections Management Journeys

### 4.1 Collections Listing
- Navigate to Collections → View all collections
- Sort collections by name/date → Verify order changes
- View collection details → See schema information

### 4.2 Collection Creation
- Click "New Collection" → Fill form → Create
- Verify collection appears in list
- Navigate to content → Verify new collection available

### 4.3 Collection Management
- Edit collection → Update display name/description → Save
- View collection content → Navigate to filtered content list
- Attempt to delete collection with content → Verify error
- Delete empty collection → Verify removal

---

## 5. Media Management Journeys

### 5.1 Media Library
- Navigate to Media → View media grid
- Switch between grid/list views → Verify layout changes
- Filter by file type (Images/Documents/Videos) → List updates
- Search media → Results update
- Navigate folders → View folder contents

### 5.2 Media Upload
- Click upload → Select single file → Upload completes
- Upload multiple files → Progress shown → All complete
- Upload different file types → Verify proper handling
- Upload to specific folder → Verify location

### 5.3 Media Operations
- Select media → View details sidebar
- Edit media metadata (alt text, caption) → Save
- Move media between folders → Verify relocation
- Delete media → Confirm → Verify removal
- Copy media URL → Verify clipboard functionality

---

## 6. User Management Journeys

### 6.1 Users Listing
- Navigate to Users → View user list
- Filter by role (Admin/Editor/Viewer) → List updates
- Filter by status (Active/Inactive) → List updates
- Search users → Results update
- Sort by name/email/last login → Verify order
- Export users → Download CSV file

### 6.2 User Operations
- View user details → See complete profile
- Edit user → Change role → Save → Verify update
- Deactivate active user → Verify status change
- Activate inactive user → Verify status change
- Create new user → Verify appears in list

---

## 7. FAQ Management Journeys

### 7.1 FAQ Listing
- Navigate to FAQ → View FAQ list
- Filter by category → List updates
- Filter by published status → List updates
- Search FAQs → Results update
- Sort by question/category/order → Verify sorting

### 7.2 FAQ CRUD Operations
- Click "Add FAQ" → Fill form → Save → Verify in list
- Edit existing FAQ → Update content → Save → Verify changes
- Change FAQ status (Published/Draft) → Verify update
- Delete FAQ → Confirm → Verify removal
- Reorder FAQs → Verify sort order persists

---

## 8. Admin Navigation Journeys

### 8.1 Sidebar Navigation
- Click each menu item → Verify correct page loads
- Verify active menu item highlighting
- Collapse/expand sidebar (mobile) → Verify functionality
- Navigate using breadcrumbs → Verify proper routing

### 8.2 User Menu
- Click user avatar → View dropdown menu
- Navigate to profile → View user profile
- Navigate to settings → View settings page
- Click logout → Return to login page

---

## 9. Search and Filter Journeys

### 9.1 Global Search
- Use global search → View results from all sections
- Click search result → Navigate to item
- Search with no results → View empty state

### 9.2 Advanced Filtering
- Apply multiple filters → Verify cumulative effect
- Clear individual filters → Verify list updates
- Clear all filters → Return to default view
- Bookmark filtered view → Return to same filters

---

## 10. Bulk Operations Journeys

### 10.1 Content Bulk Actions
- Select multiple content items → Bulk actions appear
- Bulk publish selected items → Verify all updated
- Bulk archive selected items → Verify all updated
- Bulk delete selected items → Confirm → Verify removal

### 10.2 Media Bulk Actions
- Select multiple media items → Bulk actions appear
- Bulk move to folder → Verify relocation
- Bulk delete → Confirm → Verify removal

---

## 11. Responsive/Mobile Journeys

### 11.1 Mobile Navigation
- Access on mobile device → Verify responsive layout
- Open mobile menu → Navigate sections → Verify functionality
- Use touch gestures → Verify swipe/tap actions work

### 11.2 Mobile Operations
- Create content on mobile → Verify form usability
- Upload media on mobile → Verify camera integration
- Sort tables on mobile → Verify sort functionality

---

## 12. Error Handling Journeys

### 12.1 Network Errors
- Lose connection → Attempt action → See error message
- Retry failed action → Verify recovery

### 12.2 Permission Errors
- Access unauthorized resource → See permission error
- Attempt restricted action → See appropriate message

---

## 13. Performance Journeys

### 13.1 Large Data Sets
- Load content list with 1000+ items → Verify pagination works
- Load media library with 1000+ files → Verify lazy loading
- Search in large dataset → Verify reasonable response time

### 13.2 Concurrent Operations
- Multiple users editing same content → Verify conflict handling
- Upload multiple large files → Verify queue management

---

## 14. Integration Journeys

### 14.1 Cross-Feature Integration
- Create content with media → Verify media association
- Delete user → Verify content ownership transfer
- Change collection schema → Verify content compatibility

### 14.2 API Integration
- Create content via admin → Verify available via API
- Upload media via admin → Verify accessible via CDN
- Update via API → Verify changes in admin

---

## Test Environment Requirements

### Data Prerequisites
- Minimum 3 user accounts (admin, editor, viewer)
- Minimum 3 collections with different schemas  
- Minimum 50 content items across collections
- Minimum 20 media files of various types
- Minimum 10 FAQ entries across categories

### Browser Coverage
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile Safari (iOS)
- Chrome Mobile (Android)

### Viewport Testing
- Desktop (1920x1080, 1440x900, 1366x768)
- Tablet (768x1024, 1024x768)
- Mobile (375x812, 390x844, 414x896)

---

## Success Criteria

Each journey should verify:
1. **Functional Completeness**: All expected features work
2. **Data Integrity**: Changes persist and display correctly
3. **Navigation Flow**: Users can complete tasks intuitively
4. **Error Recovery**: Graceful handling of edge cases
5. **Performance**: Acceptable response times (<3s for actions)
6. **Accessibility**: Keyboard navigation and screen reader support

---

## Exclusions

The following are explicitly excluded from E2E testing:
- Individual form field validations
- Component-level interactions (hover states, tooltips)
- CSS styling specifics
- Browser console errors (unless affecting functionality)
- Third-party service integrations
- Email notifications
- Background job processing

## Executable suite infrastructure contract

The journey/browser inventory above is a coverage specification, not a statement that
all browsers or dataset sizes are currently exercised in CI. The implemented default
project is Chromium. Full PR regression selection must remain unfiltered; smoke runs
are diagnostic only.

Operational instructions and ownership rules live in `tests/e2e/README.md`. Measured
results, regressions and unverified acceptance criteria are recorded in
`docs/testing/e2e-infrastructure-audit.md`.

- Run only against an explicitly owned disposable target. Use one absolute local
  persist directory for migrations, Wrangler and direct-D1 fixtures. Do not reset shared
  environments. Local server reuse requires explicit opt-in; CI must own its server.
- Setup must prove seed success, authenticated admin readiness and migration state before
  running specs; HTTP 200 at the deployment root is insufficient. Deployed build identity
  and complete Worker/D1/R2/KV ownership remain required, not yet verified draft behavior.
- Allocate prerequisites independently using unique attempt-scoped identifiers. Track
  resource IDs and delete only owned records in teardown, even after failures. Settings
  and plugin mutations must restore their snapshots under narrowly shared coordination.
- Reuse validated worker authentication only for accounts whose mutable state is not
  changed concurrently. Preserve real login/logout coverage and use disposable users for
  credential, role, session and second-factor mutations.
- Register waits before actions; match method and exact endpoint, verify response success,
  await completion and assert the resulting DOM/redirect. Verify saves by independent
  reads or reload. Never use a typed value, suppressed error or retry recovery as proof.
- Keep two CI workers and file-level parallelism until measurements support a change.
  Filesystem locks coordinate one host only; sharding requires isolated environments or
  actual cross-runner coordination. Do not steal locks based solely on elapsed age.
- Retain readable HTML plus JSON/JUnit results and first-attempt failure traces/screenshots.
  Preserve nonzero exits and upload diagnostic artifacts on failure when the runner survives.
- Reliability acceptance targets three consecutive clean full-suite runs with retries
  disabled at intended concurrency, plus the actual CI-policy run and unit/type/tag gates.
  Record every failed attempt and changed candidate; explicitly report incomplete acceptance.

Draft PR #1146 is not ready for sign-off: nested deletion confirmation still fails,
preview storage/build isolation is unfinished, and base-branch workflow rollout prevents
its new disposable-target guard from running under the existing preview job unchanged.