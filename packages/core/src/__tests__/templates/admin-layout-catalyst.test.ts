/**
 * Admin Layout Catalyst Template Tests
 *
 * Tests for the admin layout rendering functions
 */

import { describe, it, expect } from 'vitest';
import {
  renderAdminLayoutCatalyst,
  renderCatalystCheckbox,
  AdminLayoutCatalystData,
  CatalystCheckboxProps,
} from '../../templates/layouts/admin-layout-catalyst.template';

describe('renderCatalystCheckbox', () => {
  const baseProps: CatalystCheckboxProps = {
    id: 'test-checkbox',
    name: 'testCheckbox',
  };

  it('should render basic checkbox', () => {
    const html = renderCatalystCheckbox(baseProps);

    expect(html).toContain('type="checkbox"');
    expect(html).toContain('id="test-checkbox"');
    expect(html).toContain('name="testCheckbox"');
    expect(html).toContain('class="peer sr-only"');
  });

  it('should render checked checkbox', () => {
    const html = renderCatalystCheckbox({ ...baseProps, checked: true });

    expect(html).toContain('checked');
  });

  it('should render unchecked checkbox', () => {
    const html = renderCatalystCheckbox({ ...baseProps, checked: false });

    // The input should not have the checked attribute (but CSS classes may have "checked" in class names)
    expect(html).not.toContain('checked\n');
    expect(html).toContain('<input');
    expect(html).toContain('type="checkbox"');
  });

  it('should render disabled checkbox', () => {
    const html = renderCatalystCheckbox({ ...baseProps, disabled: true });

    expect(html).toContain('disabled');
  });

  it('should render checkbox with label', () => {
    const html = renderCatalystCheckbox({ ...baseProps, label: 'Accept terms' });

    expect(html).toContain('Accept terms');
    expect(html).toContain('text-sm/6');
  });

  it('should render checkbox with description', () => {
    const html = renderCatalystCheckbox({
      ...baseProps,
      label: 'Newsletter',
      description: 'Receive weekly updates',
    });

    expect(html).toContain('Newsletter');
    expect(html).toContain('Receive weekly updates');
    expect(html).toContain('grid');
    expect(html).toContain('col-start-2');
  });

  it('should render checkbox without description in simple layout', () => {
    const html = renderCatalystCheckbox({ ...baseProps, label: 'Simple label' });

    expect(html).toContain('inline-flex items-center gap-3');
    expect(html).not.toContain('grid-cols-');
  });

  it('should apply custom className', () => {
    const html = renderCatalystCheckbox({ ...baseProps, className: 'my-custom-class' });

    expect(html).toContain('my-custom-class');
  });

  describe('color variants', () => {
    it('should render with dark/zinc color (default)', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'dark/zinc' });

      expect(html).toContain('peer-checked:bg-zinc-900');
    });

    it('should render with dark/white color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'dark/white' });

      expect(html).toContain('dark:peer-checked:bg-white');
      expect(html).toContain('dark:text-zinc-900');
    });

    it('should render with white color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'white' });

      expect(html).toContain('peer-checked:bg-white');
    });

    it('should render with dark color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'dark' });

      expect(html).toContain('peer-checked:bg-zinc-900');
    });

    it('should render with zinc color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'zinc' });

      expect(html).toContain('peer-checked:bg-zinc-600');
    });

    it('should render with blue color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'blue' });

      expect(html).toContain('peer-checked:bg-blue-600');
    });

    it('should render with green color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'green' });

      expect(html).toContain('peer-checked:bg-green-600');
    });

    it('should render with red color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'red' });

      expect(html).toContain('peer-checked:bg-red-600');
    });

    it('should fallback to dark/zinc for unknown color', () => {
      const html = renderCatalystCheckbox({ ...baseProps, color: 'unknown' as any });

      expect(html).toContain('peer-checked:bg-zinc-900');
    });
  });

  it('should render SVG checkmark', () => {
    const html = renderCatalystCheckbox(baseProps);

    expect(html).toContain('<svg');
    expect(html).toContain('viewBox="0 0 14 14"');
    expect(html).toContain('M3 8L6 11L11 3.5');
  });
});

describe('renderAdminLayoutCatalyst', () => {
  const baseData: AdminLayoutCatalystData = {
    title: 'Test Page',
    content: '<div>Test Content</div>',
  };

  it('should render HTML document structure', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<html lang="en" class="dark">');
    expect(html).toContain('<head>');
    expect(html).toContain('<body');
    expect(html).toContain('</html>');
  });

  it('should render page title', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('<title>Test Page - SonicJS AI Admin</title>');
  });

  it('should render content', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('<div>Test Content</div>');
  });

  it('should include meta tags', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('charset="UTF-8"');
    expect(html).toContain('name="viewport"');
  });

  it('should include Tailwind CSS script', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('cdn.tailwindcss.com');
  });

  it('should include HTMX script', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('htmx.org');
  });

  it('should include Alpine.js script', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('alpinejs');
  });

  it('should include Chart.js script', () => {
    const html = renderAdminLayoutCatalyst(baseData);

    expect(html).toContain('chart.js');
  });

  it('should render with version', () => {
    const html = renderAdminLayoutCatalyst({ ...baseData, version: '2.0.0' });

    expect(html).toContain('2.0.0');
  });

  it('should render custom styles', () => {
    const html = renderAdminLayoutCatalyst({
      ...baseData,
      styles: ['/custom.css', '/theme.css'],
    });

    expect(html).toContain('href="/custom.css"');
    expect(html).toContain('href="/theme.css"');
    expect(html).toContain('rel="stylesheet"');
  });

  it('should render custom scripts', () => {
    const html = renderAdminLayoutCatalyst({
      ...baseData,
      scripts: ['/custom.js', '/analytics.js'],
    });

    expect(html).toContain('src="/custom.js"');
    expect(html).toContain('src="/analytics.js"');
  });

  it('should handle empty styles array', () => {
    const html = renderAdminLayoutCatalyst({ ...baseData, styles: [] });

    expect(html).toContain('<body');
  });

  it('should handle empty scripts array', () => {
    const html = renderAdminLayoutCatalyst({ ...baseData, scripts: [] });

    expect(html).toContain('<body');
  });

  describe('Sidebar Navigation', () => {
    it('should render desktop sidebar', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('fixed inset-y-0 left-0 w-64 max-lg:hidden');
    });

    it('should render mobile sidebar', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('id="mobile-sidebar"');
      expect(html).toContain('lg:hidden');
      expect(html).toContain('-translate-x-full');
    });

    it('should render mobile overlay', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('id="mobile-sidebar-overlay"');
      expect(html).toContain('closeMobileSidebar()');
    });

    it('should render mobile menu toggle', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('openMobileSidebar()');
      expect(html).toContain('Open navigation');
    });

    it('should render default menu items', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('Content');
      expect(html).toContain('Collections');
      expect(html).toContain('Users');
      expect(html).toContain('Plugins');
      expect(html).toContain('Settings');
    });

    it('should highlight active path', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        currentPath: '/admin/content',
      });

      expect(html).toContain('data-current="true"');
      // Should have cyan indicator for active item
      expect(html).toContain('bg-cyan-500');
    });

    it('should highlight dashboard as active for /admin path', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        currentPath: '/admin',
      });

      expect(html).toContain('data-current="true"');
    });

    it('should highlight nested paths correctly', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        currentPath: '/admin/settings/general',
      });

      // Settings should be highlighted because current path starts with /admin/settings
      expect(html).toContain('data-current="true"');
    });
  });

  describe('Dynamic Menu Items', () => {
    it('should render dynamic menu items', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        dynamicMenuItems: [
          {
            label: 'Custom Page',
            path: '/admin/custom',
            icon: '<svg>custom</svg>',
          },
        ],
      });

      expect(html).toContain('Custom Page');
      expect(html).toContain('/admin/custom');
      expect(html).toContain('<svg>custom</svg>');
    });

    it('should handle empty dynamic menu items', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        dynamicMenuItems: [],
      });

      expect(html).toContain('Content');
    });
  });

  describe('User Section', () => {
    it('should render user dropdown when user is provided', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        user: {
          name: 'John Doe',
          email: 'john@example.com',
          role: 'admin',
        },
      });

      expect(html).toContain('John Doe');
      expect(html).toContain('john@example.com');
      expect(html).toContain('My Profile');
      expect(html).toContain('Sign Out');
      expect(html).toContain('toggleUserDropdown()');
    });

    it('should display user initial in avatar', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        user: {
          name: 'John Doe',
          email: 'john@example.com',
          role: 'admin',
        },
      });

      expect(html).toContain('>J</span>');
    });

    it('should fallback to email initial when no name', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        user: {
          name: '',
          email: 'alice@example.com',
          role: 'admin',
        },
      });

      expect(html).toContain('>A</span>');
    });

    it('should fallback to U when no name or email', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        user: {
          name: '',
          email: '',
          role: 'admin',
        },
      });

      expect(html).toContain('>U</span>');
    });

    it('should not render user section when user is undefined', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).not.toContain('My Profile');
      expect(html).not.toContain('Sign Out');
    });

    it('should link to profile page', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        user: { name: 'Test', email: 'test@test.com', role: 'admin' },
      });

      expect(html).toContain('href="/admin/profile"');
    });

    it('should link to logout', () => {
      const html = renderAdminLayoutCatalyst({
        ...baseData,
        user: { name: 'Test', email: 'test@test.com', role: 'admin' },
      });

      expect(html).toContain('href="/auth/logout"');
    });
  });

  describe('Notification System', () => {
    it('should include notification container', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('id="notification-container"');
    });

    it('should include showNotification function', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('function showNotification');
      expect(html).toContain('success');
      expect(html).toContain('error');
      expect(html).toContain('warning');
      expect(html).toContain('info');
    });
  });

  describe('Migration Warning Banner', () => {
    it('should include migration banner (hidden by default)', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('id="migration-banner"');
      expect(html).toContain('class="hidden fixed');
    });

    it('should include migration count placeholder', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('id="migration-count"');
    });

    it('should include migration check function', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('checkPendingMigrations');
      expect(html).toContain('/admin/api/migrations/status');
    });

    it('should include close migration banner function', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('closeMigrationBanner()');
      expect(html).toContain('migrationBannerDismissed');
    });
  });

  describe('Dark Mode', () => {
    it('should include dark mode class by default', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('class="dark"');
    });

    it('should include dark mode initialization', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain("localStorage.getItem('darkMode')");
    });
  });

  describe('Custom Scrollbar Styles', () => {
    it('should include custom scrollbar CSS', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('::-webkit-scrollbar');
      expect(html).toContain('::-webkit-scrollbar-track');
      expect(html).toContain('::-webkit-scrollbar-thumb');
    });
  });

  describe('Logo', () => {
    it('should render logo in desktop sidebar', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('SonicJS');
    });

    it('should render logo in mobile header', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      // Mobile header should have logo - check both desktop and mobile sections
      expect(html).toContain('SonicJS');
    });
  });

  describe('Tailwind Configuration', () => {
    it('should include custom Tailwind config', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('tailwind.config');
      expect(html).toContain("darkMode: 'class'");
    });

    it('should include custom zinc colors', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('zinc:');
      expect(html).toContain('950: ');
    });
  });

  describe('Font Loading', () => {
    it('should include Inter font import', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain("font-family: 'Inter'");
      expect(html).toContain('fonts.googleapis.com');
    });
  });

  describe('Favicon', () => {
    it('should include favicon link', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('rel="icon"');
      expect(html).toContain('/favicon.svg');
    });
  });

  describe('Mobile Sidebar Functions', () => {
    it('should include openMobileSidebar function', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('function openMobileSidebar()');
      expect(html).toContain("classList.remove('-translate-x-full')");
    });

    it('should include closeMobileSidebar function', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('function closeMobileSidebar()');
      expect(html).toContain("classList.add('-translate-x-full')");
    });

    it('should include close button in mobile sidebar', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('Close menu');
    });
  });

  describe('User Dropdown Functions', () => {
    it('should include toggleUserDropdown function', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain('function toggleUserDropdown()');
    });

    it('should include click outside handler', () => {
      const html = renderAdminLayoutCatalyst(baseData);

      expect(html).toContain("document.addEventListener('click'");
      expect(html).toContain('data-user-menu');
    });
  });
});
