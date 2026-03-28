export { A as AlertData, C as ConfirmationDialogOptions, k as Filter, j as FilterBarData, l as FilterOption, h as FormData, F as FormField, P as PaginationData, T as TableColumn, i as TableData, g as getConfirmationDialogScript, d as renderAlert, e as renderConfirmationDialog, f as renderFilterBar, r as renderForm, a as renderFormField, c as renderPagination, b as renderTable } from './filter-bar.template-Daw8ZDoq.js';
import { HtmlEscapedString } from 'hono/utils/html';

interface AdminLayoutData {
    title: string;
    pageTitle?: string;
    currentPath?: string;
    version?: string;
    enableExperimentalFeatures?: boolean;
    user?: {
        name: string;
        email: string;
        role: string;
    };
    scripts?: string[];
    styles?: string[];
    content: string | HtmlEscapedString;
    dynamicMenuItems?: Array<{
        label: string;
        path: string;
        icon: string;
    }>;
}
declare function renderAdminLayout(data: AdminLayoutData): string;

interface AdminLayoutCatalystData {
    title: string;
    pageTitle?: string;
    currentPath?: string;
    version?: string;
    enableExperimentalFeatures?: boolean;
    user?: {
        name: string;
        email: string;
        role: string;
    };
    scripts?: string[];
    styles?: string[];
    content: string | HtmlEscapedString;
    dynamicMenuItems?: Array<{
        label: string;
        path: string;
        icon: string;
    }>;
}
declare function renderAdminLayoutCatalyst(data: AdminLayoutCatalystData): string;

interface LogoData {
    size?: 'sm' | 'md' | 'lg' | 'xl';
    variant?: 'default' | 'white' | 'dark';
    showText?: boolean;
    showVersion?: boolean;
    version?: string;
    className?: string;
    href?: string;
}
declare function renderLogo(data?: LogoData): string;

interface DesignPageData {
    user?: {
        name: string;
        email: string;
        role: string;
    };
    version?: string;
}
declare function renderDesignPage(data: DesignPageData): string;

interface CheckboxPageData {
    user?: {
        name: string;
        email: string;
        role: string;
    };
}
declare function renderCheckboxPage(data: CheckboxPageData): string;

interface Testimonial {
    id: number;
    author_name: string;
    author_title?: string;
    author_company?: string;
    testimonial_text: string;
    rating?: number;
    isPublished: boolean;
    sortOrder: number;
    created_at: number;
    updated_at: number;
}
interface TestimonialsListData {
    testimonials: Testimonial[];
    totalCount: number;
    currentPage: number;
    totalPages: number;
    user?: {
        name: string;
        email: string;
        role: string;
    };
    message?: string;
    messageType?: 'success' | 'error' | 'warning' | 'info';
}
declare function renderTestimonialsList(data: TestimonialsListData): string;

interface CodeExample {
    id: number;
    title: string;
    description?: string;
    code: string;
    language: string;
    category?: string;
    tags?: string;
    isPublished: boolean;
    sortOrder: number;
    created_at: number;
    updated_at: number;
}
interface CodeExamplesListData {
    codeExamples: CodeExample[];
    totalCount: number;
    currentPage: number;
    totalPages: number;
    user?: {
        name: string;
        email: string;
        role: string;
    };
    message?: string;
    messageType?: 'success' | 'error' | 'warning' | 'info';
}
declare function renderCodeExamplesList(data: CodeExamplesListData): string;

interface FormsDocsPageData {
    user?: {
        name: string;
        email: string;
        role: string;
    };
    version?: string;
}
declare function renderFormsDocsPage(data: FormsDocsPageData): string;

interface FormsExamplesPageData {
    user?: {
        name: string;
        email: string;
        role: string;
    };
    version?: string;
}
declare function renderFormsExamplesPage(data: FormsExamplesPageData): string;

export { type AdminLayoutCatalystData, type AdminLayoutData, type CheckboxPageData, type DesignPageData, type FormsDocsPageData, type FormsExamplesPageData, renderAdminLayout, renderAdminLayoutCatalyst, renderCheckboxPage, renderCodeExamplesList, renderDesignPage, renderFormsDocsPage, renderFormsExamplesPage, renderLogo, renderTestimonialsList };
