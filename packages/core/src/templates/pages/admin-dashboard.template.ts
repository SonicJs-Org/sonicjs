import {
  AdminLayoutData,
  renderAdminLayout,
} from "../layouts/admin-layout-v2.template";

export interface DashboardStats {
  collections: number;
  contentItems: number;
  mediaFiles: number;
  users: number;
  databaseSize?: number; // Size in bytes
  mediaSize?: number; // Total size of all media files in bytes
  recentActivity?: ActivityItem[];
  analytics?: AnalyticsData;
}

export interface ActivityItem {
  id: string;
  type: "content" | "media" | "user" | "collection";
  action: string;
  description: string;
  timestamp: string;
  user: string;
}

export interface AnalyticsData {
  pageViews: number;
  uniqueVisitors: number;
  contentPublished: number;
  mediaUploaded: number;
  weeklyGrowth: {
    pageViews: number;
    visitors: number;
    content: number;
    media: number;
  };
}

export interface DashboardPageData {
  user?: {
    name: string;
    email: string;
    role: string;
  };
  stats?: DashboardStats;
  version?: string;
  enableExperimentalFeatures?: boolean;
}

export function renderDashboardPage(data: DashboardPageData): string {
  const pageContent = `
    <div class="mb-8 flex flex-col sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Dashboard</h1>
        <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Welcome to your SonicJS AI admin dashboard</p>
      </div>
    </div>

    <!-- Stats Cards -->
    <div
      id="stats-container"
      class="mb-8"
      hx-get="/admin/dashboard/stats"
      hx-trigger="load"
      hx-swap="innerHTML"
    >
      ${renderStatsCardsSkeleton()}
    </div>

    <!-- Dashboard Grid -->
    <div class="grid grid-cols-1 gap-6 xl:grid-cols-3 mb-8">
      <!-- Analytics Chart -->
      <div class="xl:col-span-2">
        ${renderAnalyticsChart()}
      </div>

      <!-- Recent Activity -->
      <div
        class="xl:col-span-1"
        id="recent-activity-container"
        hx-get="/admin/dashboard/recent-activity"
        hx-trigger="load"
        hx-swap="innerHTML"
      >
        ${renderRecentActivitySkeleton()}
      </div>
    </div>

    <!-- Secondary Grid -->
    <div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
      <!-- Quick Actions -->
      ${renderQuickActions()}

      <!-- System Status -->
      ${renderSystemStatus()}

      <!-- Storage Usage -->
      <div id="storage-usage-container" hx-get="/admin/dashboard/storage" hx-trigger="load" hx-swap="innerHTML">
        ${renderStorageUsage()}
      </div>
    </div>

    <script>
      function refreshDashboard() {
        htmx.trigger('#stats-container', 'htmx:load');
        showNotification('Dashboard refreshed', 'success');
      }
    </script>
  `;

  const layoutData: AdminLayoutData = {
    title: "Dashboard",
    pageTitle: "Dashboard",
    currentPath: "/admin",
    user: data.user,
    version: data.version,
    content: pageContent,
  };

  return renderAdminLayout(layoutData);
}

export function renderDashboardPageWithDynamicMenu(
  data: DashboardPageData,
  dynamicMenuItems: Array<{ label: string; path: string; icon: string }>
): string {
  const pageContent = `
    <div class="mb-8 flex flex-col sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Dashboard</h1>
        <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Welcome to your SonicJS AI admin dashboard</p>
      </div>
    </div>

    <div id="stats-container" class="mb-8" hx-get="/admin/dashboard/stats" hx-trigger="load">
      ${renderStatsCards({
        collections: 0,
        contentItems: 0,
        mediaFiles: 0,
        users: 0,
      })}
    </div>

    <div class="grid grid-cols-1 gap-6 xl:grid-cols-3 mb-8">
      <!-- Analytics Chart -->
      <div class="xl:col-span-2">
        ${renderAnalyticsChart()}
      </div>

      <!-- Recent Activity -->
      <div
        class="xl:col-span-1"
        id="recent-activity-container"
        hx-get="/admin/dashboard/recent-activity"
        hx-trigger="load"
        hx-swap="innerHTML"
      >
        ${renderRecentActivitySkeleton()}
      </div>
    </div>

    <div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
      <!-- Quick Actions -->
      ${renderQuickActions()}

      <!-- System Status -->
      ${renderSystemStatus()}

      <!-- Storage Usage -->
      <div id="storage-usage-container" hx-get="/admin/dashboard/storage" hx-trigger="load" hx-swap="innerHTML">
        ${renderStorageUsage()}
      </div>
    </div>

    <script>
      function refreshDashboard() {
        htmx.trigger('#stats-container', 'htmx:load');
        showNotification('Dashboard refreshed', 'success');
      }
    </script>
  `;

  const layoutData: AdminLayoutData = {
    title: "Dashboard",
    pageTitle: "Dashboard",
    currentPath: "/admin",
    user: data.user,
    version: data.version,
    enableExperimentalFeatures: data.enableExperimentalFeatures,
    content: pageContent,
    dynamicMenuItems,
  };

  return renderAdminLayout(layoutData);
}

export function renderStatsCards(stats: DashboardStats): string {
  const cards = [
    {
      title: "Total Collections",
      value: stats.collections.toString(),
      change: "12.5",
      isPositive: true,
    },
    {
      title: "Content Items",
      value: stats.contentItems.toString(),
      change: "8.2",
      isPositive: true,
    },
    {
      title: "Media Files",
      value: stats.mediaFiles.toString(),
      change: "15.3",
      isPositive: true,
    },
    {
      title: "Active Users",
      value: stats.users.toString(),
      change: "2.4",
      isPositive: false,
    },
  ];

  const cardColors = ['text-cyan-400', 'text-lime-400', 'text-pink-400', 'text-purple-400'];

  return `
    <div>
      <h3 class="text-base font-semibold text-zinc-950 dark:text-white">Last 30 days</h3>
      <dl class="mt-5 grid grid-cols-1 divide-zinc-950/5 dark:divide-white/10 overflow-hidden rounded-lg bg-zinc-800/75 dark:bg-zinc-800/75 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 md:grid-cols-4 md:divide-x md:divide-y-0">
        ${cards.map((card, index) => `
          <div class="px-4 py-5 sm:p-6">
            <dt class="text-base font-normal text-zinc-700 dark:text-zinc-100">${card.title}</dt>
            <dd class="mt-1 flex items-baseline justify-between md:block lg:flex">
              <div class="flex items-baseline text-2xl font-semibold ${cardColors[index]}">
                ${card.value}
              </div>
              <div class="inline-flex items-baseline rounded-full ${card.isPositive ? 'bg-lime-400/10 text-lime-600 dark:text-lime-400' : 'bg-pink-400/10 text-pink-600 dark:text-pink-400'} px-2.5 py-0.5 text-sm font-medium md:mt-2 lg:mt-0">
                <svg viewBox="0 0 20 20" fill="currentColor" class="-ml-1 mr-0.5 size-5 shrink-0 self-center">
                  ${card.isPositive
                    ? '<path d="M10 17a.75.75 0 0 1-.75-.75V5.612L5.29 9.77a.75.75 0 0 1-1.08-1.04l5.25-5.5a.75.75 0 0 1 1.08 0l5.25 5.5a.75.75 0 1 1-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0 1 10 17Z" clip-rule="evenodd" fill-rule="evenodd" />'
                    : '<path d="M10 3a.75.75 0 0 1 .75.75v10.638l3.96-4.158a.75.75 0 1 1 1.08 1.04l-5.25 5.5a.75.75 0 0 1-1.08 0l-5.25-5.5a.75.75 0 1 1 1.08-1.04l3.96 4.158V3.75A.75.75 0 0 1 10 3Z" clip-rule="evenodd" fill-rule="evenodd" />'
                  }
                </svg>
                <span class="sr-only">${card.isPositive ? 'Increased' : 'Decreased'} by</span>
                ${card.change}%
              </div>
            </dd>
          </div>
        `).join('')}
      </dl>
    </div>
  `;
}

function renderStatsCardsSkeleton(): string {
  return `
    <div>
      <div class="h-6 w-32 bg-zinc-200 dark:bg-zinc-700 rounded animate-pulse mb-5"></div>
      <div class="grid grid-cols-1 divide-zinc-950/5 dark:divide-white/10 overflow-hidden rounded-lg bg-zinc-800/75 dark:bg-zinc-800/75 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 md:grid-cols-4 md:divide-x md:divide-y-0">
        ${Array(4)
          .fill(0)
          .map(
            () => `
            <div class="px-4 py-5 sm:p-6 animate-pulse">
              <div class="h-4 w-24 bg-zinc-200 dark:bg-zinc-700 rounded mb-3"></div>
              <div class="h-8 w-16 bg-zinc-200 dark:bg-zinc-700 rounded"></div>
            </div>
          `
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderAnalyticsChart(): string {
  return `
    <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="border-b border-zinc-950/5 dark:border-white/10 px-6 py-6">
        <div class="flex flex-wrap items-start justify-between gap-3 sm:flex-nowrap">
          <div>
            <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white">Real-Time Analytics</h3>
            <p class="mt-1 text-sm/6 text-zinc-500 dark:text-zinc-400">Requests per second (live)</p>
          </div>
          <div class="flex items-center gap-2">
            <div class="h-2 w-2 rounded-full bg-lime-500 animate-pulse"></div>
            <span class="text-xs text-zinc-500 dark:text-zinc-400">Live</span>
          </div>
        </div>
        <div class="mt-4 flex items-baseline gap-2">
          <span id="current-rps" class="text-4xl font-bold text-cyan-500 dark:text-cyan-400">0</span>
          <span class="text-sm text-zinc-500 dark:text-zinc-400">req/s</span>
        </div>
      </div>

      <div class="px-6 py-6">
        <canvas id="requestsChart" class="w-full" style="height: 300px;"></canvas>
      </div>

      <!-- Hidden div to trigger HTMX polling -->
      <div
        hx-get="/admin/dashboard/api/metrics"
        hx-trigger="every 1s"
        hx-swap="none"
        style="display: none;"
      ></div>
    </div>

    <script>
      // Initialize Chart.js for Real-time Requests
      (function() {
        const ctx = document.getElementById('requestsChart');
        if (!ctx) return;

        // Initialize with last 60 seconds of data (1 data point per second)
        const maxDataPoints = 60;
        const labels = [];
        const data = [];

        for (let i = maxDataPoints - 1; i >= 0; i--) {
          labels.push(\`-\${i}s\`);
          data.push(0);
        }

        const isDark = document.documentElement.classList.contains('dark');

        const chart = new Chart(ctx, {
          type: 'line',
          data: {
            labels: labels,
            datasets: [{
              label: 'Requests/sec',
              data: data,
              borderColor: isDark ? 'rgb(34, 211, 238)' : 'rgb(6, 182, 212)',
              backgroundColor: isDark ? 'rgba(34, 211, 238, 0.1)' : 'rgba(6, 182, 212, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.4,
              pointRadius: 0,
              pointHoverRadius: 4,
              pointBackgroundColor: isDark ? 'rgb(34, 211, 238)' : 'rgb(6, 182, 212)',
              pointBorderColor: isDark ? 'rgb(17, 24, 39)' : 'rgb(255, 255, 255)',
              pointBorderWidth: 2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                display: false
              },
              tooltip: {
                backgroundColor: isDark ? 'rgb(39, 39, 42)' : 'rgb(255, 255, 255)',
                titleColor: isDark ? 'rgb(255, 255, 255)' : 'rgb(9, 9, 11)',
                bodyColor: isDark ? 'rgb(161, 161, 170)' : 'rgb(113, 113, 122)',
                borderColor: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(9, 9, 11, 0.05)',
                borderWidth: 1,
                padding: 12,
                displayColors: false,
                callbacks: {
                  label: function(context) {
                    return 'Requests/sec: ' + context.parsed.y.toFixed(2);
                  }
                }
              }
            },
            scales: {
              y: {
                beginAtZero: true,
                border: {
                  display: false
                },
                grid: {
                  color: isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)',
                  drawBorder: false
                },
                ticks: {
                  color: isDark ? 'rgb(161, 161, 170)' : 'rgb(113, 113, 122)',
                  padding: 8,
                  callback: function(value) {
                    return value.toFixed(1);
                  }
                }
              },
              x: {
                border: {
                  display: false
                },
                grid: {
                  display: false
                },
                ticks: {
                  color: isDark ? 'rgb(161, 161, 170)' : 'rgb(113, 113, 122)',
                  padding: 8,
                  maxTicksLimit: 6
                }
              }
            }
          }
        });

        // Listen for metrics updates from HTMX
        window.addEventListener('htmx:afterRequest', function(event) {
          console.log('[Dashboard] HTMX request completed:', event.detail.pathInfo.requestPath);

          if (event.detail.pathInfo.requestPath === '/admin/dashboard/api/metrics') {
            try {
              const metrics = JSON.parse(event.detail.xhr.responseText);
              console.log('[Dashboard] Metrics received:', metrics);

              // Update current RPS display
              const rpsElement = document.getElementById('current-rps');
              if (rpsElement) {
                rpsElement.textContent = metrics.requestsPerSecond.toFixed(2);
              }

              // Add new data point to chart
              chart.data.datasets[0].data.shift();
              chart.data.datasets[0].data.push(metrics.requestsPerSecond);

              // Regenerate labels to maintain -60s to now format
              const newLabels = [];
              for (let i = maxDataPoints - 1; i >= 1; i--) {
                newLabels.push(\`-\${i}s\`);
              }
              newLabels.push('now');
              chart.data.labels = newLabels;

              chart.update('none'); // Update without animation for smoother real-time updates
              console.log('[Dashboard] Chart updated with RPS:', metrics.requestsPerSecond);
            } catch (e) {
              console.error('[Dashboard] Error updating metrics:', e);
            }
          }
        });
      })();
    </script>
  `;
}

export function renderRecentActivitySkeleton(): string {
  return `
    <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 animate-pulse">
      <div class="border-b border-zinc-950/5 dark:border-white/10 px-6 py-6">
        <div class="h-5 w-32 bg-zinc-200 dark:bg-zinc-700 rounded"></div>
      </div>
      <div class="px-6 py-6">
        <div class="space-y-6">
          ${Array(3).fill(0).map(() => `
            <div class="flex gap-x-4">
              <div class="h-10 w-10 rounded-full bg-zinc-200 dark:bg-zinc-700"></div>
              <div class="flex-auto space-y-2">
                <div class="h-4 w-48 bg-zinc-200 dark:bg-zinc-700 rounded"></div>
                <div class="h-3 w-32 bg-zinc-200 dark:bg-zinc-700 rounded"></div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `
}

export function renderRecentActivity(activities?: ActivityItem[]): string {
  // Helper to get user initials
  const getInitials = (user: string): string => {
    const parts = user.split(' ').filter(p => p.length > 0)
    if (parts.length >= 2) {
      const first = parts[0]?.[0] || ''
      const second = parts[1]?.[0] || ''
      return (first + second).toUpperCase()
    }
    return user.substring(0, 2).toUpperCase()
  }

  // Helper to get relative time
  const getRelativeTime = (timestamp: string): string => {
    const date = new Date(timestamp)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMins / 60)
    const diffDays = Math.floor(diffHours / 24)

    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`
    return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`
  }

  // Helper to get color classes based on activity type
  const getColorClasses = (type: string): { bgColor: string; textColor: string } => {
    switch (type) {
      case 'content':
        return {
          bgColor: 'bg-lime-500/10 dark:bg-lime-400/10',
          textColor: 'text-lime-700 dark:text-lime-300'
        }
      case 'media':
        return {
          bgColor: 'bg-cyan-500/10 dark:bg-cyan-400/10',
          textColor: 'text-cyan-700 dark:text-cyan-300'
        }
      case 'user':
        return {
          bgColor: 'bg-pink-500/10 dark:bg-pink-400/10',
          textColor: 'text-pink-700 dark:text-pink-300'
        }
      case 'collection':
        return {
          bgColor: 'bg-purple-500/10 dark:bg-purple-400/10',
          textColor: 'text-purple-700 dark:text-purple-300'
        }
      default:
        return {
          bgColor: 'bg-gray-500/10 dark:bg-gray-400/10',
          textColor: 'text-gray-700 dark:text-gray-300'
        }
    }
  }

  // Format activities with colors and times
  const formattedActivities = (activities || []).map(activity => {
    const colors = getColorClasses(activity.type)
    return {
      ...activity,
      initials: getInitials(activity.user),
      time: getRelativeTime(activity.timestamp),
      ...colors
    }
  })

  // If no activities, show empty state
  if (formattedActivities.length === 0) {
    formattedActivities.push({
      type: 'content' as const,
      description: 'No recent activity',
      user: 'System',
      time: '',
      initials: 'SY',
      bgColor: 'bg-gray-500/10 dark:bg-gray-400/10',
      textColor: 'text-gray-700 dark:text-gray-300',
      id: '0',
      action: '',
      timestamp: new Date().toISOString()
    })
  }

  return `
    <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="border-b border-zinc-950/5 dark:border-white/10 px-6 py-6">
        <div class="flex items-center justify-between">
          <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white">Recent Activity</h3>
          <button class="text-xs/5 font-medium text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-300 transition-colors">
            View all
          </button>
        </div>
      </div>

      <div class="px-6 py-6">
        <ul role="list" class="space-y-6">
          ${formattedActivities
            .map(
              (activity) => `
            <li class="relative flex gap-x-4">
              <div class="flex h-10 w-10 flex-none items-center justify-center rounded-full ${activity.bgColor}">
                <span class="text-xs font-semibold ${activity.textColor}">${activity.initials}</span>
              </div>
              <div class="flex-auto">
                <p class="text-sm/6 font-medium text-zinc-950 dark:text-white">${activity.description}</p>
                <p class="mt-1 text-xs/5 text-zinc-500 dark:text-zinc-400">
                  <span class="font-medium text-zinc-950 dark:text-white">${activity.user}</span>
                  <span class="text-zinc-400 dark:text-zinc-500"> · </span>
                  ${activity.time}
                </p>
              </div>
            </li>
          `
            )
            .join("")}
        </ul>
      </div>
    </div>
  `;
}

function renderQuickActions(): string {
  const actions = [
    {
      title: "Create Content",
      description: "Add new blog post or page",
      href: "/admin/content/new",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
      </svg>`,
    },
    {
      title: "Upload Media",
      description: "Add images and files",
      href: "/admin/media",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
      </svg>`,
    },
    {
      title: "Manage Users",
      description: "Add or edit user accounts",
      href: "/admin/users",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
      </svg>`,
    },
  ];

  return `
    <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="border-b border-zinc-950/5 dark:border-white/10 px-6 py-6">
        <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white">Quick Actions</h3>
      </div>

      <div class="p-6">
        <div class="space-y-2">
          ${actions
            .map(
              (action) => `
            <a href="${action.href}" class="group flex items-center gap-x-3 rounded-lg px-3 py-2 hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors">
              <div class="flex h-10 w-10 flex-none items-center justify-center text-zinc-400 dark:text-zinc-500 group-hover:text-zinc-600 dark:group-hover:text-zinc-400">
                ${action.icon}
              </div>
              <div class="flex-auto">
                <p class="text-sm/6 font-medium text-zinc-950 dark:text-white">${action.title}</p>
                <p class="text-xs/5 text-zinc-500 dark:text-zinc-400">${action.description}</p>
              </div>
              <svg class="h-5 w-5 flex-none text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8.25 4.5l7.5 7.5-7.5 7.5"/>
              </svg>
            </a>
          `
            )
            .join("")}
        </div>
      </div>
    </div>
  `;
}

function renderSystemStatus(): string {
  return `
    <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
      <div class="border-b border-zinc-950/5 dark:border-white/10 px-6 py-6">
        <div class="flex items-center justify-between">
          <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white">System Status</h3>
          <div class="flex items-center gap-2">
            <div class="h-2 w-2 rounded-full bg-lime-500 animate-pulse"></div>
            <span class="text-xs text-zinc-500 dark:text-zinc-400">Live</span>
          </div>
        </div>
      </div>

      <div
        id="system-status-container"
        class="p-6"
        hx-get="/admin/dashboard/system-status"
        hx-trigger="load, every 30s"
        hx-swap="innerHTML"
      >
        <!-- Loading skeleton with gradient -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          ${[
            { color: 'from-blue-500/20 to-cyan-500/20', darkColor: 'dark:from-blue-500/10 dark:to-cyan-500/10' },
            { color: 'from-purple-500/20 to-pink-500/20', darkColor: 'dark:from-purple-500/10 dark:to-pink-500/10' },
            { color: 'from-amber-500/20 to-orange-500/20', darkColor: 'dark:from-amber-500/10 dark:to-orange-500/10' },
            { color: 'from-lime-500/20 to-emerald-500/20', darkColor: 'dark:from-lime-500/10 dark:to-emerald-500/10' }
          ].map((gradient, i) => `
            <div class="relative group">
              <div class="absolute inset-0 bg-gradient-to-br ${gradient.color} ${gradient.darkColor} rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <div class="relative bg-zinc-50 dark:bg-zinc-800/50 rounded-xl p-5 border border-zinc-200/50 dark:border-zinc-700/50 animate-pulse">
                <div class="flex items-center justify-between mb-3">
                  <div class="h-4 w-24 bg-zinc-200 dark:bg-zinc-700 rounded"></div>
                  <div class="h-6 w-6 bg-zinc-200 dark:bg-zinc-700 rounded-full"></div>
                </div>
                <div class="h-3 w-20 bg-zinc-200 dark:bg-zinc-700 rounded"></div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>

    <style>
      @keyframes ping-slow {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
      }
      .animate-ping-slow {
        animation: ping-slow 3s cubic-bezier(0.4, 0, 0.6, 1) infinite;
      }
    </style>
  `;
}

export function renderStorageUsage(databaseSizeBytes?: number, mediaSizeBytes?: number): string {
  // Helper to format bytes to human readable
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  const dbSizeGB = databaseSizeBytes ? databaseSizeBytes / (1024 ** 3) : 0
  const dbMaxGB = 10
  const dbPercentageRaw = (dbSizeGB / dbMaxGB) * 100
  // Ensure minimum 0.5% visibility for progress bar, max 100%
  const dbPercentage = Math.min(Math.max(dbPercentageRaw, 0.5), 100)
  const dbUsedFormatted = databaseSizeBytes ? formatBytes(databaseSizeBytes) : 'Unknown'

  const mediaUsedFormatted = mediaSizeBytes ? formatBytes(mediaSizeBytes) : '0 B'

  const storageItems = [
    {
      label: "Database",
      used: dbUsedFormatted,
      total: "10 GB",
      percentage: dbPercentage,
      color: dbPercentage > 80 ? "bg-red-500 dark:bg-red-400" : dbPercentage > 60 ? "bg-amber-500 dark:bg-amber-400" : "bg-cyan-500 dark:bg-cyan-400",
    },
    {
      label: "Media Files",
      used: mediaUsedFormatted,
      total: "∞",
      percentage: 0,
      color: "bg-lime-500 dark:bg-lime-400",
      note: "Stored in R2"
    },
    {
      label: "Cache (KV)",
      used: "N/A",
      total: "∞",
      percentage: 0,
      color: "bg-purple-500 dark:bg-purple-400",
      note: "Unlimited"
    },
  ];

  return `
    <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="border-b border-zinc-950/5 dark:border-white/10 px-6 py-6">
        <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white">Storage Usage</h3>
      </div>

      <div class="px-6 py-6">
        <dl class="space-y-6">
          ${storageItems
            .map(
              (item: any) => `
            <div>
              <div class="flex items-center justify-between mb-2">
                <dt class="text-sm/6 text-zinc-500 dark:text-zinc-400">
                  ${item.label}
                  ${item.note ? `<span class="ml-2 text-xs text-zinc-400 dark:text-zinc-500">(${item.note})</span>` : ''}
                </dt>
                <dd class="text-sm/6 font-medium text-zinc-950 dark:text-white">${item.used} / ${item.total}</dd>
              </div>
              <div class="w-full bg-zinc-100 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                <div class="${item.color} h-full rounded-full transition-all duration-300" style="width: ${item.percentage}%"></div>
              </div>
            </div>
          `
            )
            .join("")}
        </dl>
      </div>
    </div>
  `;
}