interface FormField {
    name: string;
    label: string;
    type: 'text' | 'email' | 'textarea' | 'select' | 'checkbox' | 'rich_text' | 'number' | 'date' | 'multi_select' | 'file';
    value?: any;
    placeholder?: string;
    required?: boolean;
    readonly?: boolean;
    helpText?: string;
    options?: Array<{
        value: string;
        label: string;
        selected?: boolean;
    }>;
    rows?: number;
    className?: string;
    validation?: {
        min?: number;
        max?: number;
        pattern?: string;
    };
}
interface FormData {
    id?: string;
    action?: string;
    method?: string;
    hxPost?: string;
    hxPut?: string;
    hxTarget?: string;
    fields: FormField[];
    submitButtons: Array<{
        label: string;
        type?: 'submit' | 'button';
        value?: string;
        name?: string;
        className?: string;
        onclick?: string;
    }>;
    title?: string;
    description?: string;
    className?: string;
    csrfToken?: string;
}
declare function renderForm(data: FormData): string;
declare function renderFormField(field: FormField): string;

interface TableColumn {
    key: string;
    label: string;
    sortable?: boolean;
    className?: string;
    sortType?: 'string' | 'number' | 'date' | 'boolean';
    render?: (value: any, row: any) => string;
}
interface TableData<T = any> {
    columns: TableColumn[];
    rows: T[];
    selectable?: boolean;
    className?: string;
    emptyMessage?: string;
    tableId?: string;
    title?: string;
    rowClickable?: boolean;
    rowClickUrl?: (row: T) => string;
}
declare function renderTable<T = any>(data: TableData<T>): string;

interface PaginationData {
    currentPage: number;
    totalPages: number;
    totalItems: number;
    itemsPerPage: number;
    startItem: number;
    endItem: number;
    baseUrl: string;
    queryParams?: Record<string, string>;
    showPageNumbers?: boolean;
    maxPageNumbers?: number;
    showPageSizeSelector?: boolean;
    pageSizeOptions?: number[];
}
declare function renderPagination(data: PaginationData): string;

type AlertType = 'success' | 'error' | 'warning' | 'info';
interface AlertData {
    type: AlertType;
    title?: string;
    message: string;
    dismissible?: boolean;
    className?: string;
    icon?: boolean;
}
declare function renderAlert(data: AlertData): string;

interface ConfirmationDialogOptions {
    id: string;
    title: string;
    message: string;
    confirmText?: string;
    cancelText?: string;
    confirmClass?: string;
    iconColor?: 'red' | 'yellow' | 'blue';
    onConfirm?: string;
}
declare function renderConfirmationDialog(options: ConfirmationDialogOptions): string;
/**
 * Helper function to show a confirmation dialog programmatically
 * Usage in templates: Add this script and call showConfirmDialog()
 */
declare function getConfirmationDialogScript(): string;

interface FilterOption {
    value: string;
    label: string;
    selected?: boolean;
    color?: string;
}
interface Filter {
    name: string;
    label: string;
    options: FilterOption[];
}
interface FilterBarData {
    filters: Filter[];
    actions?: Array<{
        label: string;
        className?: string;
        onclick?: string;
        hxGet?: string;
        hxTarget?: string;
    }>;
    bulkActions?: Array<{
        label: string;
        value: string;
        icon?: string;
        className?: string;
    }>;
}
declare function renderFilterBar(data: FilterBarData): string;

export { type AlertData as A, type ConfirmationDialogOptions as C, type FormField as F, type PaginationData as P, type TableColumn as T, renderFormField as a, renderTable as b, renderPagination as c, renderAlert as d, renderConfirmationDialog as e, renderFilterBar as f, getConfirmationDialogScript as g, type FormData as h, type TableData as i, type FilterBarData as j, type Filter as k, type FilterOption as l, renderForm as r };
