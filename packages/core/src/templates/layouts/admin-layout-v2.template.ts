import { HtmlEscapedString } from "hono/utils/html";
import { renderLogo } from "../components/logo.template";

export interface AdminLayoutData {
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

export function renderAdminLayout(data: AdminLayoutData): string {
  // Import and use the new Catalyst layout
  const {
    renderAdminLayoutCatalyst,
  } = require("./admin-layout-catalyst.template");
  return renderAdminLayoutCatalyst(data);
}

export function adminLayoutV2(data: AdminLayoutData): string {
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${data.title} - SonicJS AI Admin</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  
  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          backdropBlur: {
            xs: '2px',
          },
          colors: {
            primary: '#465FFF',
            secondary: '#212A3E',
            dark: '#1C1C24',
            'dark-2': '#1A1A27',
            'dark-3': '#2C2C54',
            'dark-4': '#40407A',
            'dark-5': '#706FD3',
            'gray-1': '#F7F9FC',
            'gray-2': '#E4E6EA',
            'gray-3': '#D2D4D9',
            'gray-4': '#9CA3AF',
            'gray-5': '#6B7280',
            'gray-6': '#4B5563',
            'gray-7': '#374151',
            'gray-8': '#1F2937',
            'gray-9': '#111827',
            success: '#10B981',
            warning: '#F59E0B',
            error: '#EF4444',
            info: '#3B82F6'
          },
          fontFamily: {
            satoshi: ['Satoshi', 'sans-serif'],
          },
          spacing: {
            '4.5': '1.125rem',
            '5.5': '1.375rem',
            '6.5': '1.625rem',
            '7.5': '1.875rem'
          },
          boxShadow: {
            'default': '0px 8px 13px -3px rgba(0, 0, 0, 0.07)',
            'card': '0px 1px 3px rgba(0, 0, 0, 0.12)',
            'card-2': '0px 1px 2px rgba(0, 0, 0, 0.05)',
            'switcher': '0px 2px 4px rgba(0, 0, 0, 0.2), inset 0px 2px 2px #FFFFFF, inset 0px -1px 1px rgba(0, 0, 0, 0.1)',
          },
          dropShadow: {
            1: '0px 1px 0px #E2E8F0',
            2: '0px 1px 4px rgba(0, 0, 0, 0.12)',
          }
        }
      }
    }
  </script>
  
  <!-- Additional Styles -->
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
      width: 6px;
    }
    
    ::-webkit-scrollbar-track {
      background: #1F2937;
    }
    
    ::-webkit-scrollbar-thumb {
      background: #465FFF;
      border-radius: 3px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
      background: #3B4EE8;
    }
    
    /* Sidebar animations */
    .sidebar-item {
      transition: all 0.3s ease;
    }
    
    .sidebar-item:hover {
      transform: translateX(4px);
    }
    
    /* Card animations */
    .card-hover {
      transition: all 0.3s ease;
    }
    
    .card-hover:hover {
      transform: translateY(-2px);
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }
    
    /* Button gradients */
    .btn-gradient {
      background: linear-gradient(135deg, #465FFF 0%, #9333EA 100%);
    }
    
    .btn-gradient:hover {
      background: linear-gradient(135deg, #3B4EE8 0%, #7C2D12 100%);
    }
    
    /* Dark mode form elements */
    .form-input {
      background-color: #1F2937;
      border-color: #374151;
      color: #F9FAFB;
    }
    
    .form-input:focus {
      border-color: #465FFF;
      box-shadow: 0 0 0 3px rgba(70, 95, 255, 0.1);
    }
    
    /* Notification styles */
    .notification {
      -webkit-backdrop-filter: blur(15px);
      backdrop-filter: blur(15px);
      animation: slideInRight 0.3s ease-out;
    }
    
    @keyframes slideInRight {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }
    
    /* Custom slider styles */
    .slider::-webkit-slider-thumb {
      appearance: none;
      height: 16px;
      width: 16px;
      border-radius: 50%;
      background: #465FFF;
      cursor: pointer;
      border: 2px solid white;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }
    
    .slider::-moz-range-thumb {
      height: 16px;
      width: 16px;
      border-radius: 50%;
      background: #465FFF;
      cursor: pointer;
      border: 2px solid white;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }
    
    .slider::-webkit-slider-track {
      height: 8px;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.2);
    }
    
    .slider::-moz-range-track {
      height: 8px;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.2);
      border: none;
    }
    
    /* PNG Background Images */
    .svg-pattern-blue-waves {
      background-color: #111827;
      background-image: url('/images/backgrounds/blue-waves.png');
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
    }
    
    .svg-pattern-blue-crescent {
      background-color: #111827;
      background-image: url('/images/backgrounds/blue-crescent.png');
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
    }
    
    .svg-pattern-blue-stars {
      background-color: #111827;
      background-image: url('/images/backgrounds/blue-stars.png');
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
    }
    
    .svg-pattern-blue-waves-3d {
      background-color: #111827;
      background-image: url('/images/backgrounds/blue-waves-3d.png');
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
    }
  </style>
  
  <!-- Scripts -->
  <script src="https://unpkg.com/htmx.org@2.0.3"></script>
  <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  
  ${data.styles ? data.styles.map((style) => `<link rel="stylesheet" href="${style}">`).join("\n  ") : ""}
  ${data.scripts ? data.scripts.map((script) => `<script src="${script}"></script>`).join("\n  ") : ""}
</head>
<body class="bg-gradient-to-br from-slate-900 via-gray-900 to-black min-h-screen text-gray-1">
  <!-- Background overlay with glass effect -->
  <div id="background-overlay" class="fixed inset-0 backdrop-blur-sm" style="background-color: rgba(0, 0, 0, 0.2);"></div>
  <!-- Main container -->
  <div class="relative z-10 min-h-screen">
    <!-- Header -->
    ${renderTopBar(data.pageTitle || "Dashboard", data.user)}

    <!-- Main content area -->
    <div class="px-4 sm:px-6 lg:px-8 py-8">
      <div class="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <!-- Sidebar -->
        <div class="lg:col-span-1">
          ${renderSidebar(data.currentPath || "/", data.user, data.dynamicMenuItems)}
        </div>
        
        <!-- Main content -->
        <div class="lg:col-span-4">
          ${data.content}
        </div>
      </div>
    </div>
  </div>
  
  <!-- Notification Container -->
  <div id="notification-container" class="fixed top-4 right-4 z-50 space-y-2"></div>
  
  <script>
    // Dark mode toggle functionality
    function toggleDarkMode() {
      document.documentElement.classList.toggle('dark');
      localStorage.setItem('darkMode', document.documentElement.classList.contains('dark'));
    }
    
    // Initialize dark mode from localStorage
    if (localStorage.getItem('darkMode') === 'true' || (!('darkMode' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    }
    
    // Sidebar toggle for mobile
    function toggleSidebar() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('sidebar-overlay');
      sidebar.classList.toggle('-translate-x-full');
      overlay.classList.toggle('hidden');
    }
    
    // Close sidebar on overlay click
    function closeSidebar() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('sidebar-overlay');
      sidebar.classList.add('-translate-x-full');
      overlay.classList.add('hidden');
    }
    
    // User dropdown toggle
    function toggleUserDropdown() {
      const dropdown = document.getElementById('userDropdown');
      dropdown.classList.toggle('hidden');
    }
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
      const dropdown = document.getElementById('userDropdown');
      const button = event.target.closest('button');
      if (!button || !button.getAttribute('onclick')) {
        dropdown.classList.add('hidden');
      }
    });
    
    // Show notification
    function showNotification(message, type = 'info') {
      const container = document.getElementById('notification-container');
      const notification = document.createElement('div');
      const colors = {
        success: 'bg-success text-white',
        error: 'bg-error text-white',
        warning: 'bg-warning text-white',
        info: 'bg-info text-white'
      };
      
      notification.className = \`notification px-6 py-4 rounded-lg shadow-lg \${colors[type] || colors.info} max-w-sm\`;
      notification.innerHTML = \`
        <div class="flex items-center justify-between">
          <span>\${message}</span>
          <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-white/80 hover:text-white">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>
      \`;
      
      container.appendChild(notification);
      
      // Auto remove after 5 seconds
      setTimeout(() => {
        if (notification.parentElement) {
          notification.remove();
        }
      }, 5000);
    }
    
    // Background customizer functionality
    function toggleBackgroundCustomizer() {
      const dropdown = document.getElementById('backgroundCustomizer');
      dropdown.classList.toggle('hidden');
    }
    
    // Background themes
    const backgroundThemes = {
      'default': 'bg-gradient-to-br from-slate-900 via-gray-900 to-black',
      'cosmic-blue': 'bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900',
      'matrix-green': 'bg-gradient-to-br from-gray-900 via-emerald-900 to-green-900',
      'cyber-pink': 'bg-gradient-to-br from-gray-900 via-pink-900 to-rose-900',
      'neon-orange': 'bg-gradient-to-br from-gray-900 via-orange-900 to-amber-900',
      'purple-space': 'bg-gradient-to-br from-gray-900 via-purple-900 to-violet-800',
      'blue-waves': 'svg-pattern-blue-waves',
      'blue-crescent': 'svg-pattern-blue-crescent',
      'blue-stars': 'svg-pattern-blue-stars',
      'blue-waves-3d': 'svg-pattern-blue-waves-3d'
    };
    
    // Set background theme
    function setBackground(theme) {
      const body = document.body;
      
      // Remove all existing background classes and SVG patterns
      Object.values(backgroundThemes).forEach(bgClass => {
        if (bgClass.startsWith('svg-pattern-')) {
          body.classList.remove(bgClass);
        } else {
          body.classList.remove(...bgClass.split(' ').slice(1)); // Remove 'bg-gradient-to-br' prefix
        }
      });
      body.classList.remove('bg-gradient-to-br');
      
      // Add new background
      const themeClass = backgroundThemes[theme];
      if (themeClass.startsWith('svg-pattern-')) {
        body.classList.add(themeClass);
      } else {
        const newClasses = themeClass.split(' ').slice(1); // Remove 'bg-gradient-to-br' prefix
        body.classList.add('bg-gradient-to-br', ...newClasses);
      }
      
      // Save preference
      localStorage.setItem('backgroundTheme', theme);
      
      // Close dropdown
      toggleBackgroundCustomizer();
      
      // Show notification
      showNotification('Background changed to ' + theme.replace('-', ' '), 'success');
    }
    
    // Adjust background darkness
    function adjustDarkness(value) {
      const overlay = document.getElementById('background-overlay');
      if (overlay) {
        const opacity = value / 100; // Convert percentage to decimal
        overlay.style.backgroundColor = 'rgba(0, 0, 0, ' + opacity + ')';
        localStorage.setItem('backgroundDarkness', value);
        console.log('Darkness adjusted to:', value + '%', 'Opacity:', opacity);
      } else {
        console.log('Overlay element not found');
      }
    }
    
    // Initialize background on page load
    function initializeBackground() {
      const savedTheme = localStorage.getItem('backgroundTheme') || 'default';
      const savedDarkness = localStorage.getItem('backgroundDarkness') || '20';
      
      // Set background theme
      if (savedTheme !== 'default') {
        const body = document.body;
        const themeClass = backgroundThemes[savedTheme];
        
        // Remove all existing backgrounds first
        Object.values(backgroundThemes).forEach(bgClass => {
          if (bgClass.startsWith('svg-pattern-')) {
            body.classList.remove(bgClass);
          } else {
            body.classList.remove(...bgClass.split(' ').slice(1));
          }
        });
        body.classList.remove('bg-gradient-to-br');
        
        // Apply saved theme
        if (themeClass.startsWith('svg-pattern-')) {
          body.classList.add(themeClass);
        } else {
          const newClasses = themeClass.split(' ').slice(1);
          body.classList.add('bg-gradient-to-br', ...newClasses);
        }
      }
      
      // Set darkness
      const overlay = document.getElementById('background-overlay');
      if (overlay) {
        const opacity = savedDarkness / 100;
        overlay.style.backgroundColor = 'rgba(0, 0, 0, ' + opacity + ')';
      }
      
      // Set slider value
      const slider = document.getElementById('darknessSlider');
      if (slider) {
        slider.value = savedDarkness;
      }
    }
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
      const dropdown = document.getElementById('backgroundCustomizer');
      const button = event.target.closest('button');
      const slider = event.target.closest('#darknessSlider');
      const dropdownContainer = event.target.closest('#backgroundCustomizer');
      
      // Don't close if clicking inside the dropdown, on the toggle button, or on the slider
      if (!button?.getAttribute('onclick')?.includes('toggleBackgroundCustomizer') && 
          !slider && !dropdownContainer) {
        dropdown?.classList.add('hidden');
      }
    });
    
    // Initialize background when page loads
    document.addEventListener('DOMContentLoaded', initializeBackground);
  </script>
</body>
</html>`;
}

function renderSidebar(
  currentPath: string,
  user?: any,
  dynamicMenuItems?: Array<{
    label: string;
    path: string;
    icon: string;
  }>
): string {
  const baseMenuItems = [
    {
      label: "Dashboard",
      path: "/admin",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
      </svg>`,
    },
    {
      label: "Content",
      path: "/admin/content",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`,
    },
    {
      label: "Collections",
      path: "/admin/collections",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3z"/>
      </svg>`,
    },
    {
      label: "Media",
      path: "/admin/media",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11.707 4.707a1 1 0 00-1.414-1.414L10 9.586 8.707 8.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
      </svg>`,
    },
    {
      label: "Users",
      path: "/admin/users",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3z"/>
      </svg>`,
    },
    {
      label: "Redirects",
      path: "/admin/redirects",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
      </svg>`,
    },
    {
      label: "QR Codes",
      path: "/admin/qr-codes",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"/>
      </svg>`,
    },
    {
      label: "Plugins",
      path: "/admin/plugins",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
      </svg>`,
    },
    {
      label: "Cache",
      path: "/admin/cache",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
      </svg>`,
    },
    {
      label: "Design",
      path: "/admin/design",
      icon: `<svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M4.098 19.902a3.75 3.75 0 0 0 5.304 0l6.401-6.402M6.75 21A3.75 3.75 0 0 1 3 17.25V4.125C3 3.504 3.504 3 4.125 3h5.25c.621 0 1.125.504 1.125 1.125v4.072M6.75 21a3.75 3.75 0 0 0 3.75-3.75V8.197M6.75 21h13.125c.621 0 1.125-.504 1.125-1.125v-5.25c0-.621-.504-1.125-1.125-1.125h-4.072M10.5 8.197l2.88-2.88c.438-.439 1.15-.439 1.59 0l3.712 3.713c.44.44.44 1.152 0 1.59l-2.879 2.88M6.75 17.25h.008v.008H6.75v-.008Z" />
      </svg>`,
    },
    {
      label: "Logs",
      path: "/admin/logs",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`,
    },
    {
      label: "Settings",
      path: "/admin/settings",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/>
      </svg>`,
    },
    {
      label: "API Reference",
      path: "/admin/api-reference",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
      </svg>`,
    },
    {
      label: "Field Types",
      path: "/admin/field-types",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
      </svg>`,
    },
    {
      label: "API Spec",
      path: "/api",
      target: "_blank",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`,
    },
  ];

  // Combine base menu items with dynamic menu items from active plugins
  const allMenuItems = [...baseMenuItems];

  // Insert dynamic menu items after "Users"
  if (dynamicMenuItems && dynamicMenuItems.length > 0) {
    const usersIndex = allMenuItems.findIndex(
      (item) => item.path === "/admin/users"
    );
    if (usersIndex !== -1) {
      allMenuItems.splice(usersIndex + 1, 0, ...dynamicMenuItems);
    } else {
      // Fallback: add to end if Users not found
      allMenuItems.push(...dynamicMenuItems);
    }
  }

  return `
    <nav class="backdrop-blur-md bg-black/30 rounded-xl border border-white/10 shadow-xl p-6 h-[calc(100vh-9.5rem)] sticky top-8">
      <div class="space-y-4">
        ${allMenuItems
          .map((item) => {
            const isActive =
              currentPath === item.path ||
              (item.path !== "/admin" && currentPath.startsWith(item.path));
            const targetAttr = (item as any).target
              ? ` target="${(item as any).target}"`
              : "";
            return `
            <a href="${item.path}"${targetAttr} class="flex items-center space-x-3 ${isActive ? "text-white bg-white/20" : "text-gray-300 hover:text-white"} rounded-lg px-3 py-2 transition-all hover:bg-white/10">
              ${item.icon}
              <span>${item.label}</span>
            </a>
          `;
          })
          .join("")}
      </div>
    </nav>
  `;
}

function renderTopBar(pageTitle: string, user?: any): string {
  return `
    <header class="backdrop-blur-md bg-white/10 border-b border-white/20 shadow-lg relative z-[9998]">
      <div class="px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between items-center py-4">
          <div class="flex items-center space-x-4">
            ${renderLogo({ size: "md", showText: true, variant: "white" })}
          </div>
          
          <div class="flex items-center space-x-4">
            <!-- Notifications -->
            <button class="p-2 text-gray-300 hover:text-white transition-colors rounded-lg hover:bg-white/10 relative">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/>
              </svg>
              <span class="absolute top-1 right-1 w-2 h-2 bg-red-400 rounded-full"></span>
            </button>

            <!-- Background Customizer -->
            <div class="relative z-[9999]">
              <button class="p-2 text-gray-300 hover:text-white transition-colors rounded-lg hover:bg-white/10" onclick="toggleBackgroundCustomizer()">
                <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M4.098 19.902a3.75 3.75 0 0 0 5.304 0l6.401-6.402M6.75 21A3.75 3.75 0 0 1 3 17.25V4.125C3 3.504 3.504 3 4.125 3h5.25c.621 0 1.125.504 1.125 1.125v4.072M6.75 21a3.75 3.75 0 0 0 3.75-3.75V8.197M6.75 21h13.125c.621 0 1.125-.504 1.125-1.125v-5.25c0-.621-.504-1.125-1.125-1.125h-4.072M10.5 8.197l2.88-2.88c.438-.439 1.15-.439 1.59 0l3.712 3.713c.44.44.44 1.152 0 1.59l-2.879 2.88M6.75 17.25h.008v.008H6.75v-.008Z" />
                </svg>
              </button>
              
              <!-- Background Customizer Dropdown -->
              <div id="backgroundCustomizer" class="hidden absolute right-0 mt-2 w-80 backdrop-blur-md bg-black/95 rounded-xl border border-white/10 shadow-xl z-[9999]">
                <div class="p-6">
                  <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-white">Background Themes</h3>
                    <button onclick="toggleBackgroundCustomizer()" class="text-gray-400 hover:text-white">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                      </svg>
                    </button>
                  </div>
                  
                  <!-- Background Options -->
                  <div class="space-y-3 mb-6">
                    <div class="grid grid-cols-2 gap-3">
                      <!-- Default (Deep Space) -->
                      <button onclick="setBackground('default')" class="bg-preview bg-gradient-to-br from-slate-900 via-gray-900 to-black h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group">
                        <div class="absolute inset-0 bg-black/20 rounded-lg"></div>
                        <div class="absolute bottom-1 left-2 text-xs text-white font-medium">Default</div>
                      </button>
                      
                      <!-- Cosmic Blue -->
                      <button onclick="setBackground('cosmic-blue')" class="bg-preview bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group">
                        <div class="absolute inset-0 bg-black/20 rounded-lg"></div>
                        <div class="absolute bottom-1 left-2 text-xs text-white font-medium">Cosmic</div>
                      </button>
                      
                      <!-- Matrix Green -->
                      <button onclick="setBackground('matrix-green')" class="bg-preview bg-gradient-to-br from-gray-900 via-emerald-900 to-green-900 h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group">
                        <div class="absolute inset-0 bg-black/20 rounded-lg"></div>
                        <div class="absolute bottom-1 left-2 text-xs text-white font-medium">Matrix</div>
                      </button>
                      
                      <!-- Cyber Pink -->
                      <button onclick="setBackground('cyber-pink')" class="bg-preview bg-gradient-to-br from-gray-900 via-pink-900 to-rose-900 h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group">
                        <div class="absolute inset-0 bg-black/20 rounded-lg"></div>
                        <div class="absolute bottom-1 left-2 text-xs text-white font-medium">Cyber</div>
                      </button>
                      
                      <!-- Neon Orange -->
                      <button onclick="setBackground('neon-orange')" class="bg-preview bg-gradient-to-br from-gray-900 via-orange-900 to-amber-900 h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group">
                        <div class="absolute inset-0 bg-black/20 rounded-lg"></div>
                        <div class="absolute bottom-1 left-2 text-xs text-white font-medium">Neon</div>
                      </button>
                      
                      <!-- Purple Space -->
                      <button onclick="setBackground('purple-space')" class="bg-preview bg-gradient-to-br from-gray-900 via-purple-900 to-violet-800 h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group">
                        <div class="absolute inset-0 bg-black/20 rounded-lg"></div>
                        <div class="absolute bottom-1 left-2 text-xs text-white font-medium">Purple</div>
                      </button>
                    </div>
                    
                    <!-- Custom Backgrounds -->
                    <div class="mt-4">
                      <h4 class="text-sm font-medium text-gray-300 mb-3">Custom Backgrounds</h4>
                      <div class="grid grid-cols-2 gap-3">
                        <!-- Blue Waves -->
                        <button onclick="setBackground('blue-waves')" class="h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group overflow-hidden">
                          <div class="absolute inset-0">
                            <img src="/images/backgrounds/blue-waves.png" alt="Blue Waves" class="w-full h-full object-cover opacity-60">
                          </div>
                          <div class="absolute bottom-1 left-2 text-xs text-white font-medium bg-black/50 px-2 py-1 rounded">Waves</div>
                        </button>
                        
                        <!-- Blue Crescent -->
                        <button onclick="setBackground('blue-crescent')" class="h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group overflow-hidden">
                          <div class="absolute inset-0">
                            <img src="/images/backgrounds/blue-crescent.png" alt="Blue Crescent" class="w-full h-full object-cover opacity-60">
                          </div>
                          <div class="absolute bottom-1 left-2 text-xs text-white font-medium bg-black/50 px-2 py-1 rounded">Crescent</div>
                        </button>
                        
                        <!-- Blue Stars -->
                        <button onclick="setBackground('blue-stars')" class="h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group overflow-hidden">
                          <div class="absolute inset-0">
                            <img src="/images/backgrounds/blue-stars.png" alt="Blue Stars" class="w-full h-full object-cover opacity-60">
                          </div>
                          <div class="absolute bottom-1 left-2 text-xs text-white font-medium bg-black/50 px-2 py-1 rounded">Stars</div>
                        </button>
                        
                        <!-- Blue Waves 3D -->
                        <button onclick="setBackground('blue-waves-3d')" class="h-16 rounded-lg border-2 border-white/20 hover:border-white/40 transition-all relative group overflow-hidden">
                          <div class="absolute inset-0">
                            <img src="/images/backgrounds/blue-waves-3d.png" alt="Blue Waves 3D" class="w-full h-full object-cover opacity-60">
                          </div>
                          <div class="absolute bottom-1 left-2 text-xs text-white font-medium bg-black/50 px-2 py-1 rounded">3D Waves</div>
                        </button>
                      </div>
                    </div>
                  </div>
                  
                  <!-- Darkness Slider -->
                  <div class="space-y-3">
                    <label class="block text-sm font-medium text-white">Background Darkness</label>
                    <div class="flex items-center space-x-3">
                      <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707"/>
                      </svg>
                      <input 
                        type="range" 
                        id="darknessSlider" 
                        min="10" 
                        max="100" 
                        value="20" 
                        class="flex-1 h-2 bg-white/20 rounded-lg appearance-none cursor-pointer slider"
                        oninput="adjustDarkness(this.value)"
                        onchange="adjustDarkness(this.value)"
                      >
                      <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                      </svg>
                    </div>
                    <div class="text-xs text-gray-400 text-center">Adjust overlay darkness</div>
                  </div>
                </div>
              </div>
            </div>
          
            <!-- User Dropdown -->
            ${
              user
                ? `
              <div class="relative z-[9999]">
                <button class="flex items-center space-x-3 p-2 rounded-lg hover:bg-white/10 transition-colors group" onclick="toggleUserDropdown()">
                  <div class="w-8 h-8 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center">
                    <span class="text-white text-sm font-medium">${(user.name || user.email || "U").charAt(0).toUpperCase()}</span>
                  </div>
                  <div class="hidden md:block text-left">
                    <div class="text-white text-sm font-medium">${user.name || user.email || "User"}</div>
                    <div class="text-gray-400 text-xs">${user.role || "Administrator"}</div>
                  </div>
                  <svg class="w-4 h-4 text-gray-400 group-hover:text-white transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                  </svg>
                </button>
                
                <!-- Dropdown Menu -->
                <div id="userDropdown" class="hidden absolute right-0 mt-2 w-48 backdrop-blur-md bg-black/95 rounded-xl border border-white/10 shadow-xl z-[9999]">
                  <div class="py-2">
                    <div class="px-4 py-2 border-b border-white/10">
                      <p class="text-sm font-medium text-gray-1">${user.name || user.email || "User"}</p>
                      <p class="text-xs text-gray-4">${user.email || ""}</p>
                    </div>
                    <a href="/admin/profile" class="flex items-center gap-3 px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-colors">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                      </svg>
                      My Profile
                    </a>
                    <a href="/auth/logout" class="flex items-center gap-3 px-4 py-2 text-sm text-red-300 hover:bg-red-500/10 hover:text-red-200 transition-colors">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                      </svg>
                      Sign Out
                    </a>
                  </div>
                </div>
              </div>
            `
                : `
              <a href="/auth/login" class="backdrop-blur-md bg-white/10 px-4 py-2 rounded-lg text-white font-medium hover:bg-white/20 transition-all">
                Sign In
              </a>
            `
            }
        </div>
      </div>
    </header>
  `;
}
