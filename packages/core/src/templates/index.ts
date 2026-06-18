/**
 * Templates Module Exports
 *
 * Reusable HTML template components for SonicJS
 */

// Form templates
export { renderForm, renderFormField } from './form.template'
export type { FormField, FormData } from './form.template'

// Table templates
export { renderTable } from './table.template'
export type { TableColumn, TableData } from './table.template'

// Pagination templates
export { renderPagination } from './pagination.template'
export type { PaginationData } from './pagination.template'

// Alert templates
export { renderAlert } from './alert.template'
export type { AlertData } from './alert.template'

// Confirmation dialog templates
export { renderConfirmationDialog, getConfirmationDialogScript } from './confirmation-dialog.template'
export type { ConfirmationDialogOptions } from './confirmation-dialog.template'

// Filter bar templates
export { renderFilterBar } from './filter-bar.template'
export type { FilterBarData, Filter, FilterOption } from './filter-bar.template'

// Layout templates
export { renderAdminLayout } from './layouts/admin-layout-v2.template'
export { renderAdminLayoutCatalyst } from './layouts/admin-layout-catalyst.template'
export type { AdminLayoutData } from './layouts/admin-layout-v2.template'
export type { AdminLayoutCatalystData } from './layouts/admin-layout-catalyst.template'

// Component templates
export { renderLogo } from './components/logo.template'

// Page templates - Admin
export { renderCheckboxPage } from './pages/admin-checkboxes.template'
export type { CheckboxPageData } from './pages/admin-checkboxes.template'
export { renderFormsDocsPage } from './pages/admin-forms-docs.template'
export type { FormsDocsPageData } from './pages/admin-forms-docs.template'
export { renderFormsExamplesPage } from './pages/admin-forms-examples.template'
export type { FormsExamplesPageData } from './pages/admin-forms-examples.template'