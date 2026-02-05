import { __esm, __export, __toCommonJS } from './chunk-V4OQ3NZ2.js';

// src/templates/components/logo.template.ts
function renderLogo(data = {}) {
  const {
    size = "md",
    variant = "default",
    showText = true,
    showVersion = true,
    version,
    className = "",
    href
  } = data;
  const sizeClass = sizeClasses[size];
  const logoSvg = `
    <svg class="${sizeClass} ${className}" viewBox="380 1300 2250 400" aria-hidden="true">
      <path fill="${variant === "white" ? "#ffffff" : variant === "dark" ? "#1f2937" : "#F1F2F2"}" d="M476.851,1404.673h168.536c4.714,0,8.695-1.618,11.944-4.866c3.241-3.241,4.866-7.222,4.866-11.943    c0-2.357-0.443-4.569-1.327-6.636c-0.885-2.06-2.067-3.829-3.539-5.308c-1.479-1.472-3.249-2.654-5.308-3.538    c-2.067-0.885-4.279-1.327-6.635-1.327H476.851c-20.057,0-37.158,7.154-51.313,21.454c-14.155,14.308-21.233,31.483-21.233,51.534    c0,20.058,7.078,37.234,21.233,51.534c14.155,14.308,31.255,21.454,51.313,21.454h112.357c10.907,0,20.196,3.837,27.868,11.502    c7.666,7.672,11.502,16.885,11.502,27.646c0,10.769-3.836,19.982-11.502,27.647c-7.672,7.673-16.961,11.502-27.868,11.502H421.115    c-4.721,0-8.702,1.624-11.944,4.865c-3.248,3.249-4.866,7.23-4.866,11.944c0,3.248,0.733,6.123,2.212,8.626    c1.472,2.509,3.462,4.499,5.971,5.972c2.502,1.472,5.378,2.212,8.626,2.212h168.094c20.052,0,37.227-7.078,51.534-21.234    c14.3-14.155,21.454-31.331,21.454-51.534c0-20.196-7.154-37.379-21.454-51.534c-14.308-14.156-31.483-21.234-51.534-21.234    H476.851c-10.616,0-19.76-3.905-27.426-11.721c-7.672-7.811-11.501-17.101-11.501-27.87c0-10.761,3.829-19.975,11.501-27.647    C457.091,1408.508,466.235,1404.673,476.851,1404.673z"></path>
      <path fill="${variant === "white" ? "#ffffff" : variant === "dark" ? "#1f2937" : "#F1F2F2"}" d="M974.78,1398.211c-5.016,6.574-10.034,13.146-15.048,19.721c-1.828,2.398-3.657,4.796-5.487,7.194    c1.994,1.719,3.958,3.51,5.873,5.424c18.724,18.731,28.089,41.216,28.089,67.459c0,26.251-9.366,48.658-28.089,67.237    c-18.731,18.579-41.215,27.868-67.459,27.868c-9.848,0-19.156-1.308-27.923-3.923l-4.185,3.354    c-8.587,6.885-17.154,13.796-25.725,20.702c17.52,8.967,36.86,13.487,58.054,13.487c35.533,0,65.91-12.608,91.124-37.821    c25.214-25.215,37.821-55.584,37.821-91.125c0-35.534-12.607-65.911-37.821-91.126    C981.004,1403.663,977.926,1400.854,974.78,1398.211z"></path>
      <path fill="${variant === "white" ? "#ffffff" : variant === "dark" ? "#1f2937" : "#F1F2F2"}" d="M1364.644,1439.619c-4.72,0-8.702,1.624-11.943,4.865c-3.249,3.249-4.866,7.23-4.866,11.944v138.014    l-167.651-211.003c-0.297-0.586-0.74-1.03-1.327-1.326c-4.721-4.714-10.249-7.742-16.588-9.069    c-6.346-1.326-12.608-0.732-18.801,1.77c-6.192,2.509-11.059,6.49-14.598,11.944c-3.539,5.46-5.308,11.577-5.308,18.357v208.348    c0,4.721,1.618,8.703,4.866,11.944c3.241,3.241,7.222,4.865,11.943,4.865c2.945,0,5.751-0.738,8.405-2.211    c2.654-1.472,4.713-3.463,6.193-5.971c1.473-2.503,2.212-5.378,2.212-8.627v-205.251l166.325,209.675    c2.06,2.654,4.423,4.865,7.078,6.635c5.308,3.829,11.349,5.75,18.137,5.75c5.308,0,10.464-1.182,15.482-3.538    c3.539-1.769,6.56-4.127,9.069-7.078c2.502-2.945,4.491-6.338,5.971-10.175c1.473-3.829,2.212-7.664,2.212-11.501v-141.552    c0-4.714-1.624-8.695-4.865-11.944C1373.339,1441.243,1369.359,1439.619,1364.644,1439.619z"></path>
      <path fill="${variant === "white" ? "#ffffff" : variant === "dark" ? "#1f2937" : "#F1F2F2"}" d="M1508.406,1432.983c-2.654-1.472-5.46-2.212-8.404-2.212c-4.721,0-8.703,1.7-11.944,5.087    c-3.249,3.395-4.865,7.3-4.865,11.723v163.228c0,4.721,1.616,8.702,4.865,11.943c3.241,3.249,7.223,4.866,11.944,4.866    c2.944,0,5.751-0.732,8.404-2.212c2.655-1.472,4.714-3.539,6.193-6.194c1.473-2.654,2.213-5.453,2.213-8.404V1447.58    c0-2.945-0.74-5.75-2.213-8.405C1513.12,1436.522,1511.06,1434.462,1508.406,1432.983z"></path>
      <path fill="${variant === "white" ? "#ffffff" : variant === "dark" ? "#1f2937" : "#F1F2F2"}" d="M1499.78,1367.957c-4.575,0-8.481,1.625-11.722,4.866c-3.249,3.249-4.865,7.23-4.865,11.943    c0,2.951,0.732,5.75,2.212,8.405c1.472,2.654,3.463,4.721,5.971,6.193c2.503,1.479,5.378,2.212,8.627,2.212    c4.423,0,8.328-1.618,11.721-4.865c3.387-3.243,5.088-7.224,5.088-11.944c0-4.713-1.701-8.694-5.088-11.943    C1508.33,1369.582,1504.349,1367.957,1499.78,1367.957z"></path>
      <path fill="${variant === "white" ? "#ffffff" : variant === "dark" ? "#1f2937" : "#F1F2F2"}" d="M1859.627,1369.727H1747.27c-35.388,0-65.69,12.607-90.904,37.821    c-25.213,25.215-37.82,55.591-37.82,91.125c0,35.54,12.607,65.911,37.82,91.125c25.215,25.215,55.516,37.821,90.904,37.821h56.178    c4.714,0,8.695-1.618,11.944-4.866c3.241-3.241,4.865-7.222,4.865-11.943c0-4.714-1.624-8.695-4.865-11.943    c-3.249-3.243-7.23-4.866-11.944-4.866h-56.178c-26.251,0-48.659-9.359-67.237-28.09c-18.579-18.723-27.868-41.207-27.868-67.459    c0-26.243,9.29-48.659,27.868-67.237c18.579-18.579,40.987-27.868,67.237-27.868h112.357c4.714,0,8.696-1.693,11.944-5.087    c3.241-3.387,4.865-7.368,4.865-11.943c0-4.569-1.624-8.475-4.865-11.723C1868.322,1371.351,1864.341,1369.727,1859.627,1369.727z    "></path>
      <path fill="#06b6d4" d="M2219.256,1371.054h-112.357c-4.423,0-8.336,1.624-11.723,4.865c-3.393,3.249-5.087,7.23-5.087,11.944    c0,4.721,1.694,8.702,5.087,11.943c3.387,3.249,7.3,4.866,11.723,4.866h95.547v95.105c0,26.251-9.365,48.659-28.088,67.237    c-18.731,18.579-41.215,27.868-67.459,27.868c-26.251,0-48.659-9.289-67.237-27.868c-18.579-18.579-27.868-40.987-27.868-67.237    c0-4.713-1.701-8.771-5.088-12.165c-3.393-3.387-7.374-5.087-11.943-5.087c-4.575,0-8.481,1.7-11.722,5.087    c-3.249,3.393-4.865,7.451-4.865,12.165c0,35.388,12.607,65.69,37.82,90.904c25.215,25.213,55.584,37.82,91.126,37.82    c35.532,0,65.91-12.607,91.125-37.82c25.214-25.215,37.82-55.516,37.82-90.904v-111.915c0-4.714-1.624-8.695-4.865-11.944    C2227.951,1372.678,2223.971,1371.054,2219.256,1371.054z"></path>
      <path fill="#06b6d4" d="M2574.24,1502.875c-14.306-14.156-31.483-21.234-51.533-21.234H2410.35    c-10.617,0-19.762-3.829-27.426-11.501c-7.672-7.664-11.501-16.954-11.501-27.868c0-10.907,3.829-20.196,11.501-27.868    c7.664-7.664,16.809-11.501,27.426-11.501h112.357c4.714,0,8.695-1.617,11.944-4.866c3.241-3.241,4.865-7.222,4.865-11.943    c0-4.714-1.624-8.695-4.865-11.944c-3.249-3.241-7.23-4.865-11.944-4.865H2410.35c-20.058,0-37.158,7.154-51.313,21.454    c-14.156,14.308-21.232,31.483-21.232,51.534c0,20.058,7.077,37.234,21.232,51.534c14.156,14.308,31.255,21.454,51.313,21.454    h112.357c7.078,0,13.637,1.77,19.684,5.308c6.042,3.539,10.838,8.336,14.377,14.377c3.538,6.047,5.307,12.607,5.307,19.685    c0,10.616-3.835,19.76-11.501,27.425c-7.672,7.673-16.961,11.502-27.868,11.502h-168.094c-4.721,0-8.703,1.7-11.944,5.087    c-3.249,3.393-4.865,7.374-4.865,11.943c0,4.576,1.616,8.481,4.865,11.723c3.241,3.249,7.223,4.866,11.944,4.866h168.094    c20.051,0,37.227-7.078,51.533-21.234c14.302-14.155,21.454-31.331,21.454-51.534    C2595.695,1534.213,2588.542,1517.03,2574.24,1502.875z"></path>
      <path fill="#06b6d4" d="M854.024,1585.195l20.001-16.028c16.616-13.507,33.04-27.265,50.086-40.251    c1.13-0.861,2.9-1.686,2.003-3.516c-0.843-1.716-2.481-2.302-4.484-2.123c-8.514,0.765-17.016-0.538-25.537-0.353    c-1.124,0.024-2.768,0.221-3.163-1.25c-0.371-1.369,1.088-2.063,1.919-2.894c6.26-6.242,12.574-12.43,18.816-18.691    c9.303-9.327,18.565-18.714,27.851-28.066c1.848-1.859,3.701-3.713,5.549-5.572c2.655-2.661,5.309-5.315,7.958-7.982    c0.574-0.579,1.259-1.141,1.246-1.94c-0.004-0.257-0.078-0.538-0.254-0.853c-0.556-0.981-1.441-1.1-2.469-0.957    c-0.658,0.096-1.315,0.185-1.973,0.275c-3.844,0.538-7.689,1.076-11.533,1.608c-3.641,0.505-7.281,1.02-10.922,1.529    c-4.162,0.582-8.324,1.158-12.486,1.748c-1.142,0.161-2.409,1.662-3.354,0.508c-0.419-0.508-0.431-1.028-0.251-1.531    c0.269-0.741,0.957-1.441,1.387-2.021c3.414-4.58,6.882-9.124,10.356-13.662c1.74-2.272,3.48-4.544,5.214-6.822    c4.682-6.141,9.369-12.281,14.051-18.422c0.09-0.119,0.181-0.237,0.271-0.355c6.848-8.98,13.7-17.958,20.553-26.936    c0.488-0.64,0.977-1.28,1.465-1.92c2.159-2.828,4.315-5.658,6.476-8.486c4.197-5.501,8.454-10.954,12.67-16.442    c0.263-0.347,0.538-0.718,0.717-1.106c0.269-0.586,0.299-1.196-0.335-1.776c-0.825-0.753-1.8-0.15-2.595,0.419    c-0.67,0.472-1.333,0.957-1.955,1.489c-2.206,1.889-4.401,3.797-6.595,5.698c-3.958,3.438-7.922,6.876-11.976,10.194    c-2.443,2.003-4.865,4.028-7.301,6.038c-18.689-10.581-39.53-15.906-62.549-15.906c-35.54,0-65.911,12.607-91.125,37.82    c-25.214,25.215-37.821,55.592-37.821,91.126c0,35.54,12.607,65.91,37.821,91.125c4.146,4.146,8.445,7.916,12.87,11.381    c-9.015,11.14-18.036,22.277-27.034,33.429c-1.208,1.489-3.755,3.151-2.745,4.891c0.078,0.144,0.173,0.281,0.305,0.425    c1.321,1.429,3.492-1.303,4.933-2.457c6.673-5.333,13.333-10.685,19.982-16.042c3.707-2.984,7.417-5.965,11.124-8.952    c1.474-1.188,2.951-2.373,4.425-3.561c6.41-5.164,12.816-10.333,19.238-15.481L854.024,1585.195z M797.552,1498.009    c0-26.243,9.29-48.728,27.868-67.459c18.579-18.723,40.987-28.089,67.238-28.089c12.273,0,23.712,2.075,34.34,6.171    c-3.37,2.905-6.734,5.816-10.069,8.762c-6.075,5.351-12.365,10.469-18.667,15.564c-4.179,3.378-8.371,6.744-12.514,10.164    c-7.54,6.23-15.037,12.52-22.529,18.804c-7.091,5.955-14.182,11.904-21.19,17.949c-1.136,0.974-3.055,1.907-2.135,3.94    c0.831,1.836,2.774,1.417,4.341,1.578l12.145-0.599l14.151-0.698c1.031-0.102,2.192-0.257,2.89,0.632    c0.034,0.044,0.073,0.078,0.106,0.127c1.017,1.561-0.67,2.105-1.387,2.942c-6.308,7.318-12.616,14.637-18.978,21.907    c-8.161,9.339-16.353,18.649-24.544,27.958c-2.146,2.433-4.275,4.879-6.422,7.312c-1.034,1.172-2.129,2.272-1.238,3.922    c0.933,1.728,2.685,1.752,4.323,1.602c4.134-0.367,8.263-0.489,12.396-0.492c0.242,0,0.485-0.005,0.728-0.004    c2.711,0.009,5.422,0.068,8.134,0.145c2.582,0.074,5.166,0.165,7.752,0.249c0.275,1.62-0.879,2.356-1.62,3.259    c-1.333,1.626-2.667,3.247-4,4.867c-4.315,5.252-8.62,10.514-12.928,15.772c-3.562-2.725-7.007-5.733-10.324-9.051    C806.842,1546.667,797.552,1524.26,797.552,1498.009z"></path>
    </svg>
  `;
  const versionBadge = showVersion && version ? `
    <span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${variant === "white" ? "bg-white/10 text-white/80 ring-white/20" : "bg-cyan-50 text-cyan-700 ring-cyan-700/10 dark:bg-cyan-500/10 dark:text-cyan-400 dark:ring-cyan-500/20"}">
      ${version}
    </span>
  ` : "";
  const logoContent = showText ? `
    <div class="flex items-center gap-2 ${className}">
      ${logoSvg}
      ${versionBadge}
    </div>
  ` : logoSvg;
  if (href) {
    return `<a href="${href}" class="inline-block hover:opacity-80 transition-opacity">${logoContent}</a>`;
  }
  return logoContent;
}
var sizeClasses;
var init_logo_template = __esm({
  "src/templates/components/logo.template.ts"() {
    sizeClasses = {
      sm: "h-6 w-auto",
      md: "h-8 w-auto",
      lg: "h-12 w-auto",
      xl: "h-16 w-auto"
    };
  }
});

// src/templates/layouts/admin-layout-catalyst.template.ts
var admin_layout_catalyst_template_exports = {};
__export(admin_layout_catalyst_template_exports, {
  renderAdminLayoutCatalyst: () => renderAdminLayoutCatalyst,
  renderCatalystCheckbox: () => renderCatalystCheckbox
});
function renderCatalystCheckbox(props) {
  const {
    id,
    name,
    checked = false,
    disabled = false,
    label,
    description,
    color = "dark/zinc",
    className = ""
  } = props;
  const colorClasses = {
    "dark/zinc": "peer-checked:bg-zinc-900 peer-checked:before:bg-zinc-900 dark:peer-checked:bg-zinc-600",
    "dark/white": "peer-checked:bg-zinc-900 peer-checked:before:bg-zinc-900 dark:peer-checked:bg-white",
    white: "peer-checked:bg-white peer-checked:before:bg-white",
    dark: "peer-checked:bg-zinc-900 peer-checked:before:bg-zinc-900",
    zinc: "peer-checked:bg-zinc-600 peer-checked:before:bg-zinc-600",
    blue: "peer-checked:bg-blue-600 peer-checked:before:bg-blue-600",
    green: "peer-checked:bg-green-600 peer-checked:before:bg-green-600",
    red: "peer-checked:bg-red-600 peer-checked:before:bg-red-600"
  };
  const checkColor = color === "dark/white" ? "dark:text-zinc-900" : "text-white";
  const baseClasses = `
    relative isolate flex w-4 h-4 items-center justify-center rounded-[0.3125rem]
    before:absolute before:inset-0 before:-z-10 before:rounded-[calc(0.3125rem-1px)] before:bg-white before:shadow-sm
    dark:before:hidden
    dark:bg-white/5
    border border-zinc-950/15 peer-checked:border-transparent
    dark:border-white/15 dark:peer-checked:border-white/5
    peer-focus:outline peer-focus:outline-2 peer-focus:outline-offset-2 peer-focus:outline-blue-500
    peer-disabled:opacity-50
    peer-disabled:border-zinc-950/25 peer-disabled:bg-zinc-950/5
    dark:peer-disabled:border-white/20 dark:peer-disabled:bg-white/2.5
  `.trim().replace(/\s+/g, " ");
  const checkIconClasses = `
    w-4 h-4 opacity-0 peer-checked:opacity-100 pointer-events-none
  `.trim().replace(/\s+/g, " ");
  if (description) {
    return `
      <div class="grid grid-cols-[1.125rem_1fr] gap-x-4 gap-y-1 sm:grid-cols-[1rem_1fr] ${className}">
        <div class="col-start-1 row-start-1 mt-0.75 sm:mt-1">
          <input
            type="checkbox"
            id="${id}"
            name="${name}"
            ${checked ? "checked" : ""}
            ${disabled ? "disabled" : ""}
            class="peer sr-only"
          />
          <label for="${id}" class="inline-flex cursor-pointer">
            <span class="${baseClasses} ${colorClasses[color] || colorClasses["dark/zinc"]}">
              <svg class="${checkIconClasses} ${checkColor}" viewBox="0 0 14 14" fill="none" stroke="currentColor">
                <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </span>
          </label>
        </div>
        ${label ? `<label for="${id}" class="col-start-2 row-start-1 text-sm/6 font-medium text-zinc-950 dark:text-white cursor-pointer">${label}</label>` : ""}
        ${description ? `<p class="col-start-2 row-start-2 text-sm/6 text-zinc-500 dark:text-zinc-400">${description}</p>` : ""}
      </div>
    `;
  } else {
    return `
      <label class="inline-flex items-center gap-3 cursor-pointer ${className}">
        <input
          type="checkbox"
          id="${id}"
          name="${name}"
          ${checked ? "checked" : ""}
          ${disabled ? "disabled" : ""}
          class="peer sr-only"
        />
        <span class="${baseClasses} ${colorClasses[color] || colorClasses["dark/zinc"]}">
          <svg class="${checkIconClasses} ${checkColor}" viewBox="0 0 14 14" fill="none" stroke="currentColor">
            <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        ${label ? `<span class="text-sm/6 font-medium text-zinc-950 dark:text-white">${label}</span>` : ""}
      </label>
    `;
  }
}
function renderAdminLayoutCatalyst(data) {
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
          colors: {
            zinc: {
              50: '#fafafa',
              100: '#f4f4f5',
              200: '#e4e4e7',
              300: '#d4d4d8',
              400: '#a1a1aa',
              500: '#71717a',
              600: '#52525b',
              700: '#3f3f46',
              800: '#27272a',
              900: '#18181b',
              950: '#09090b'
            }
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
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    /* Custom scrollbar */
    ::-webkit-scrollbar {
      width: 8px;
      height: 8px;
    }

    ::-webkit-scrollbar-track {
      background: #27272a;
    }

    ::-webkit-scrollbar-thumb {
      background: #52525b;
      border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
      background: #71717a;
    }

    /* Smooth transitions */
    * {
      transition-property: color, background-color, border-color, text-decoration-color, fill, stroke;
      transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
      transition-duration: 150ms;
    }
  </style>

  <!-- Scripts -->
  <script src="https://unpkg.com/htmx.org@2.0.3"></script>
  <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

  ${data.styles ? data.styles.map((style) => `<link rel="stylesheet" href="${style}">`).join("\n  ") : ""}
  ${data.scripts ? data.scripts.map((script) => `<script src="${script}"></script>`).join("\n  ") : ""}
</head>
<body class="min-h-screen bg-white dark:bg-zinc-900">
  <div class="relative isolate flex min-h-svh w-full max-lg:flex-col lg:bg-zinc-100 dark:lg:bg-zinc-950">
    <!-- Sidebar on desktop -->
    <div class="fixed inset-y-0 left-0 w-64 max-lg:hidden">
      ${renderCatalystSidebar(
    data.currentPath,
    data.user,
    data.dynamicMenuItems,
    false,
    data.version,
    data.enableExperimentalFeatures
  )}
    </div>

    <!-- Mobile sidebar (hidden by default) -->
    <div id="mobile-sidebar-overlay" class="fixed inset-0 bg-black/30 lg:hidden hidden z-40" onclick="closeMobileSidebar()"></div>
    <div id="mobile-sidebar" class="fixed inset-y-0 left-0 w-80 transform -translate-x-full transition-transform duration-300 ease-in-out lg:hidden z-50">
      ${renderCatalystSidebar(
    data.currentPath,
    data.user,
    data.dynamicMenuItems,
    true,
    data.version,
    data.enableExperimentalFeatures
  )}
    </div>

    <!-- Main content area -->
    <main class="flex flex-1 flex-col pb-2 lg:min-w-0 lg:pr-2 lg:pl-64">
      <!-- Mobile header with menu toggle -->
      <header class="flex items-center px-4 py-2.5 lg:hidden border-b border-zinc-950/5 dark:border-white/5">
        <button onclick="openMobileSidebar()" class="relative flex items-center justify-center rounded-lg p-2 text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5" aria-label="Open navigation">
          <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path d="M2 6.75C2 6.33579 2.33579 6 2.75 6H17.25C17.6642 6 18 6.33579 18 6.75C18 7.16421 17.6642 7.5 17.25 7.5H2.75C2.33579 7.5 2 7.16421 2 6.75ZM2 13.25C2 12.8358 2.33579 12.5 2.75 12.5H17.25C17.6642 12.5 18 12.8358 18 13.25C18 13.6642 17.6642 14 17.25 14H2.75C2.33579 14 2 13.6642 2 13.25Z" />
          </svg>
        </button>
        <div class="ml-4 flex-1">
          ${renderLogo({ size: "sm", showText: true, variant: "white", version: data.version, href: "/admin" })}
        </div>
      </header>

      <!-- Content -->
      <div class="grow p-6 lg:rounded-lg lg:bg-white lg:p-10 lg:shadow-sm lg:ring-1 lg:ring-zinc-950/5 dark:lg:bg-zinc-900 dark:lg:ring-white/10">
        ${data.content}
      </div>
    </main>
  </div>

  <!-- Notification Container -->
  <div id="notification-container" class="fixed top-4 right-4 z-50 space-y-2"></div>

  <!-- Migration Warning Banner (hidden by default) -->
  <div id="migration-banner" class="hidden fixed top-0 left-0 right-0 z-50 bg-amber-500 dark:bg-amber-600 shadow-lg">
    <div class="max-w-7xl mx-auto px-4 py-3 sm:px-6 lg:px-8">
      <div class="flex items-center justify-between flex-wrap">
        <div class="flex items-center flex-1">
          <span class="flex p-2 rounded-lg bg-amber-600 dark:bg-amber-700">
            <svg class="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
          </span>
          <div class="ml-3">
            <p class="text-sm font-medium text-white">
              <span id="migration-count"></span> pending database migration(s) detected
            </p>
            <p class="text-xs text-amber-100 dark:text-amber-200 mt-1">
              Run: <code class="bg-amber-700 dark:bg-amber-800 px-2 py-0.5 rounded font-mono text-white">wrangler d1 migrations apply DB --local</code>
            </p>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <a href="/admin/settings/migrations" class="text-xs font-semibold text-white hover:text-amber-100 underline">
            View Details
          </a>
          <button onclick="closeMigrationBanner()" class="p-1 rounded-md text-white hover:bg-amber-600 dark:hover:bg-amber-700 focus:outline-none focus:ring-2 focus:ring-white">
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
  </div>

  <script>
    // Mobile sidebar toggle
    function openMobileSidebar() {
      const sidebar = document.getElementById('mobile-sidebar');
      const overlay = document.getElementById('mobile-sidebar-overlay');
      sidebar.classList.remove('-translate-x-full');
      overlay.classList.remove('hidden');
    }

    function closeMobileSidebar() {
      const sidebar = document.getElementById('mobile-sidebar');
      const overlay = document.getElementById('mobile-sidebar-overlay');
      sidebar.classList.add('-translate-x-full');
      overlay.classList.add('hidden');
    }

    // User dropdown toggle
    function toggleUserDropdown() {
      const dropDowns = document.querySelectorAll('.userDropdown');
      dropDowns.forEach(dropdown => {
        dropdown.classList.toggle('hidden');
      });
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
      const dropdown = document.getElementById('userDropdown');
      const button = event.target.closest('[data-user-menu]');
      if (!button && dropdown && !dropdown.contains(event.target)) {
        dropdown.classList.add('hidden');
      }
    });

    // Show notification
    function showNotification(message, type = 'info') {
      const container = document.getElementById('notification-container');
      const notification = document.createElement('div');
      const colors = {
        success: 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-green-600/20 dark:ring-green-500/20',
        error: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-red-600/20 dark:ring-red-500/20',
        warning: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 ring-amber-600/20 dark:ring-amber-500/20',
        info: 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 ring-blue-600/20 dark:ring-blue-500/20'
      };

      notification.className = \`rounded-lg p-4 ring-1 \${colors[type] || colors.info} max-w-sm shadow-lg\`;
      notification.innerHTML = \`
        <div class="flex items-center justify-between">
          <span class="text-sm">\${message}</span>
          <button onclick="this.parentElement.parentElement.remove()" class="ml-4 hover:opacity-70">
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

    // Initialize dark mode
    if (localStorage.getItem('darkMode') === 'false') {
      document.documentElement.classList.remove('dark');
    }

    // Migration banner functions
    function closeMigrationBanner() {
      const banner = document.getElementById('migration-banner');
      if (banner) {
        banner.classList.add('hidden');
        // Store in session storage so it doesn't show again during this session
        sessionStorage.setItem('migrationBannerDismissed', 'true');
      }
    }

    // Check for pending migrations on page load
    async function checkPendingMigrations() {
      // Don't check if user dismissed the banner in this session
      if (sessionStorage.getItem('migrationBannerDismissed') === 'true') {
        return;
      }

      try {
        const response = await fetch('/admin/api/migrations/status');
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data && data.data.pendingMigrations > 0) {
            const banner = document.getElementById('migration-banner');
            const countElement = document.getElementById('migration-count');
            if (banner && countElement) {
              countElement.textContent = data.data.pendingMigrations;
              banner.classList.remove('hidden');
            }
          }
        }
      } catch (error) {
        console.error('Failed to check migration status:', error);
      }
    }

    // Check for pending migrations when the page loads
    document.addEventListener('DOMContentLoaded', checkPendingMigrations);
  </script>
</body>
</html>`;
}
function renderCatalystSidebar(currentPath = "", user, dynamicMenuItems, isMobile = false, version, enableExperimentalFeatures) {
  let baseMenuItems = [
    {
      label: "Dashboard",
      path: "/admin",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
      </svg>`
    },
    {
      label: "Collections",
      path: "/admin/collections",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M7 3a1 1 0 000 2h6a1 1 0 100-2H7zM4 7a1 1 0 011-1h10a1 1 0 110 2H5a1 1 0 01-1-1zM2 11a2 2 0 012-2h12a2 2 0 012 2v4a2 2 0 01-2 2H4a2 2 0 01-2-2v-4z"/>
      </svg>`
    },
    {
      label: "Forms",
      path: "/admin/forms",
      icon: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`
    },
    {
      label: "Content",
      path: "/admin/content",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clip-rule="evenodd"/>
      </svg>`
    },
    {
      label: "Media",
      path: "/admin/media",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clip-rule="evenodd"/>
      </svg>`
    },
    {
      label: "Users",
      path: "/admin/users",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/>
      </svg>`
    },
    {
      label: "Plugins",
      path: "/admin/plugins",
      icon: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
      </svg>`
    },
    {
      label: "Cache",
      path: "/admin/cache",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm14 1a1 1 0 11-2 0 1 1 0 012 0zM2 13a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2v-2zm14 1a1 1 0 11-2 0 1 1 0 012 0z" clip-rule="evenodd"/>
      </svg>`
    }
  ];
  const settingsMenuItem = {
    label: "Settings",
    path: "/admin/settings",
    icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
      <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/>
    </svg>`
  };
  const allMenuItems = [...baseMenuItems];
  if (dynamicMenuItems && dynamicMenuItems.length > 0) {
    const usersIndex = allMenuItems.findIndex(
      (item) => item.path === "/admin/users"
    );
    if (usersIndex !== -1) {
      allMenuItems.splice(usersIndex + 1, 0, ...dynamicMenuItems);
    } else {
      allMenuItems.push(...dynamicMenuItems);
    }
  }
  const closeButton = isMobile ? `
    <div class="-mb-3 px-4 pt-3">
      <button onclick="closeMobileSidebar()" class="relative flex w-full items-center gap-3 rounded-lg p-2 text-left text-base/6 font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5 sm:text-sm/5" aria-label="Close navigation">
        <svg class="h-5 w-5 shrink-0 fill-zinc-500 dark:fill-zinc-400" viewBox="0 0 20 20">
          <path d="M6.28 5.22a.75.75 0 0 0-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 1 0 1.06 1.06L10 11.06l3.72 3.72a.75.75 0 1 0 1.06-1.06L11.06 10l3.72-3.72a.75.75 0 0 0-1.06-1.06L10 8.94 6.28 5.22Z" />
        </svg>
        <span>Close menu</span>
      </button>
    </div>
  ` : "";
  return `
    <nav class="flex h-full min-h-0 flex-col bg-white shadow-sm ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:ring-white/10 ${isMobile ? "is-mobile rounded-lg p-2 m-2" : ""}">
      ${closeButton}

      <!-- Sidebar Header -->
      <div class="flex flex-col border-b border-zinc-950/5 p-4 dark:border-white/5">
        ${renderLogo({ size: "md", showText: true, variant: "white", version, href: "/admin" })}
      </div>

      <!-- Sidebar Body -->
      <div class="flex flex-1 flex-col overflow-y-auto p-4">
        <div class="flex flex-col gap-0.5">
          ${allMenuItems.map((item) => {
    const isActive = currentPath === item.path || item.path !== "/admin" && currentPath?.startsWith(item.path);
    return `
              <span class="relative">
                ${isActive ? `
                  <span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>
                ` : ""}
                <a
                  href="${item.path}"
                  class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium ${isActive ? "text-zinc-950 dark:text-white" : "text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5"}"
                  ${isActive ? 'data-current="true"' : ""}
                >
                  <span class="shrink-0 ${isActive ? "fill-zinc-950 dark:fill-white" : "fill-zinc-500 dark:fill-zinc-400"}">
                    ${item.icon}
                  </span>
                  <span class="truncate">${item.label}</span>
                </a>
              </span>
            `;
  }).join("")}
        </div>
      </div>

      <!-- Settings Menu Item (Bottom) -->
      <div class="border-t border-zinc-950/5 p-4 dark:border-white/5">
        ${(() => {
    const isActive = currentPath === settingsMenuItem.path || currentPath?.startsWith(settingsMenuItem.path);
    return `
            <span class="relative">
              ${isActive ? `
                <span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>
              ` : ""}
              <a
                href="${settingsMenuItem.path}"
                class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium ${isActive ? "text-zinc-950 dark:text-white" : "text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5"}"
                ${isActive ? 'data-current="true"' : ""}
              >
                <span class="shrink-0 ${isActive ? "fill-zinc-950 dark:fill-white" : "fill-zinc-500 dark:fill-zinc-400"}">
                  ${settingsMenuItem.icon}
                </span>
                <span class="truncate">${settingsMenuItem.label}</span>
              </a>
            </span>
          `;
  })()}
      </div>

      <!-- Sidebar Footer (User) -->
      ${user ? `
        <div class="flex flex-col border-t border-zinc-950/5 p-4 dark:border-white/5">
          <div class="relative">
            <button
              data-user-menu
              onclick="toggleUserDropdown()"
              class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5"
            >
              <div class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-zinc-950 text-white dark:bg-white dark:text-zinc-950">
                <span class="text-xs font-semibold">${(user.name || user.email || "U").charAt(0).toUpperCase()}</span>
              </div>
              <span class="flex-1 truncate">${user.name || user.email || "User"}</span>
              <svg class="h-4 w-4 shrink-0 fill-zinc-500 dark:fill-zinc-400" viewBox="0 0 20 20">
                <path d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z" />
              </svg>
            </button>

            <!-- User Dropdown -->
            <div class="userDropdown hidden absolute bottom-full mb-2 left-0 right-0 mx-2 rounded-xl bg-white shadow-lg ring-1 ring-zinc-950/10 dark:bg-zinc-800 dark:ring-white/10 z-50">
              <div class="p-2">
                <div class="px-3 py-2 border-b border-zinc-950/5 dark:border-white/5">
                  <p class="text-sm font-medium text-zinc-950 dark:text-white">${user.name || user.email || "User"}</p>
                  <p class="text-xs text-zinc-500 dark:text-zinc-400">${user.email || ""}</p>
                </div>
                <a href="/admin/profile" class="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                  </svg>
                  My Profile
                </a>
                <a href="/auth/logout" class="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-500/10">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                  </svg>
                  Sign Out
                </a>
              </div>
            </div>
          </div>
        </div>
      ` : ""}
    </nav>
  `;
}
var init_admin_layout_catalyst_template = __esm({
  "src/templates/layouts/admin-layout-catalyst.template.ts"() {
    init_logo_template();
  }
});

// src/templates/alert.template.ts
function renderAlert(data) {
  const typeClasses = {
    success: "bg-green-50 dark:bg-green-500/10 border border-green-600/20 dark:border-green-500/20",
    error: "bg-error/10 border border-red-600/20 dark:border-red-500/20",
    warning: "bg-amber-50 dark:bg-amber-500/10 border border-amber-600/20 dark:border-amber-500/20",
    info: "bg-blue-50 dark:bg-blue-500/10 border border-blue-600/20 dark:border-blue-500/20"
  };
  const iconClasses = {
    success: "text-green-600 dark:text-green-400",
    error: "text-red-600 dark:text-red-400",
    warning: "text-amber-600 dark:text-amber-400",
    info: "text-blue-600 dark:text-blue-400"
  };
  const textClasses = {
    success: "text-green-900 dark:text-green-300",
    error: "text-red-900 dark:text-red-300",
    warning: "text-amber-900 dark:text-amber-300",
    info: "text-blue-900 dark:text-blue-300"
  };
  const messageTextClasses = {
    success: "text-green-700 dark:text-green-400",
    error: "text-red-700 dark:text-red-400",
    warning: "text-amber-700 dark:text-amber-400",
    info: "text-blue-700 dark:text-blue-400"
  };
  const icons = {
    success: `<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />`,
    error: `<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />`,
    warning: `<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />`,
    info: `<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />`
  };
  return `
    <div class="rounded-lg p-4 ${typeClasses[data.type]} ${data.className || ""}" ${data.dismissible ? 'id="dismissible-alert"' : ""}>
      <div class="flex">
        ${data.icon !== false ? `
          <div class="flex-shrink-0">
            <svg class="h-5 w-5 ${iconClasses[data.type]}" viewBox="0 0 20 20" fill="currentColor">
              ${icons[data.type]}
            </svg>
          </div>
        ` : ""}
        <div class="${data.icon !== false ? "ml-3" : ""}">
          ${data.title ? `
            <h3 class="text-sm font-semibold ${textClasses[data.type]}">
              ${data.title}
            </h3>
          ` : ""}
          <div class="${data.title ? "mt-1 text-sm" : "text-sm"} ${messageTextClasses[data.type]}">
            <p>${data.message}</p>
          </div>
        </div>
        ${data.dismissible ? `
          <div class="ml-auto pl-3">
            <div class="-mx-1.5 -my-1.5">
              <button
                type="button"
                class="inline-flex rounded-md p-1.5 ${iconClasses[data.type]} hover:bg-opacity-20 focus:outline-none focus:ring-2 focus:ring-offset-2"
                onclick="document.getElementById('dismissible-alert').remove()"
              >
                <span class="sr-only">Dismiss</span>
                <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          </div>
        ` : ""}
      </div>
    </div>
  `;
}

// src/templates/confirmation-dialog.template.ts
function renderConfirmationDialog(options) {
  const {
    id,
    title,
    message,
    confirmText = "Confirm",
    cancelText = "Cancel",
    confirmClass = "bg-red-500 hover:bg-red-400",
    iconColor = "red",
    onConfirm = ""
  } = options;
  const iconColorClasses = {
    red: "bg-red-500/10 text-red-400",
    yellow: "bg-yellow-500/10 text-yellow-400",
    blue: "bg-blue-500/10 text-blue-400"
  };
  return `
    <el-dialog>
      <dialog
        id="${id}"
        aria-labelledby="${id}-title"
        class="fixed inset-0 m-0 size-auto max-h-none max-w-none overflow-y-auto bg-transparent p-0 backdrop:bg-transparent"
      >
        <el-dialog-backdrop class="fixed inset-0 bg-gray-900/50 transition-opacity data-[closed]:opacity-0 data-[enter]:duration-300 data-[leave]:duration-200 data-[enter]:ease-out data-[leave]:ease-in"></el-dialog-backdrop>

        <div tabindex="0" class="flex min-h-full items-end justify-center p-4 text-center focus:outline focus:outline-0 sm:items-center sm:p-0">
          <el-dialog-panel class="relative transform overflow-hidden rounded-lg bg-gray-800 px-4 pb-4 pt-5 text-left shadow-xl outline outline-1 -outline-offset-1 outline-white/10 transition-all data-[closed]:translate-y-4 data-[closed]:opacity-0 data-[enter]:duration-300 data-[leave]:duration-200 data-[enter]:ease-out data-[leave]:ease-in sm:my-8 sm:w-full sm:max-w-lg sm:p-6 data-[closed]:sm:translate-y-0 data-[closed]:sm:scale-95">
            <div class="sm:flex sm:items-start">
              <div class="mx-auto flex size-12 shrink-0 items-center justify-center rounded-full ${iconColorClasses[iconColor]} sm:mx-0 sm:size-10">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" data-slot="icon" aria-hidden="true" class="size-6">
                  <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
              </div>
              <div class="mt-3 text-center sm:ml-4 sm:mt-0 sm:text-left">
                <h3 id="${id}-title" class="text-base font-semibold text-white">${title}</h3>
                <div class="mt-2">
                  <p class="text-sm text-gray-400">${message}</p>
                </div>
              </div>
            </div>
            <div class="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
              <button
                type="button"
                onclick="${onConfirm}; document.getElementById('${id}').close()"
                command="close"
                commandfor="${id}"
                class="confirm-button inline-flex w-full justify-center rounded-md ${confirmClass} px-3 py-2 text-sm font-semibold text-white sm:ml-3 sm:w-auto"
              >
                ${confirmText}
              </button>
              <button
                type="button"
                command="close"
                commandfor="${id}"
                class="mt-3 inline-flex w-full justify-center rounded-md bg-white/10 px-3 py-2 text-sm font-semibold text-white ring-1 ring-inset ring-white/5 hover:bg-white/20 sm:mt-0 sm:w-auto"
              >
                ${cancelText}
              </button>
            </div>
          </el-dialog-panel>
        </div>
      </dialog>
    </el-dialog>
  `;
}
function getConfirmationDialogScript() {
  return `
    <script src="https://cdn.jsdelivr.net/npm/@tailwindplus/elements@1" type="module"></script>
    <script>
      function showConfirmDialog(dialogId) {
        const dialog = document.getElementById(dialogId);
        if (dialog) {
          dialog.showModal();
        }
      }
    </script>
  `;
}

// src/templates/pagination.template.ts
function renderPagination(data) {
  const shouldShowPagination = data.totalPages > 1 || data.showPageSizeSelector !== false && data.totalItems > 0;
  if (!shouldShowPagination) {
    return "";
  }
  const buildUrl = (page, limit) => {
    const params = new URLSearchParams(data.queryParams || {});
    params.set("page", page.toString());
    if (data.itemsPerPage !== 20) {
      params.set("limit", data.itemsPerPage.toString());
    }
    return `${data.baseUrl}?${params.toString()}`;
  };
  const buildPageSizeUrl = (limit) => {
    const params = new URLSearchParams(data.queryParams || {});
    params.set("page", "1");
    params.set("limit", limit.toString());
    return `${data.baseUrl}?${params.toString()}`;
  };
  const generatePageNumbers = () => {
    const maxNumbers = data.maxPageNumbers || 5;
    const half = Math.floor(maxNumbers / 2);
    let start = Math.max(1, data.currentPage - half);
    let end = Math.min(data.totalPages, start + maxNumbers - 1);
    if (end - start + 1 < maxNumbers) {
      start = Math.max(1, end - maxNumbers + 1);
    }
    const pages = [];
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }
    return pages;
  };
  return `
    <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-4 py-3 flex items-center justify-between mt-4">
      ${data.totalPages > 1 ? `
        <!-- Mobile Pagination -->
        <div class="flex-1 flex justify-between sm:hidden">
          ${data.currentPage > 1 ? `
            <a href="${buildUrl(data.currentPage - 1)}" class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Previous
            </a>
          ` : `
            <span class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-400 dark:text-zinc-600 shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 opacity-50 cursor-not-allowed">Previous</span>
          `}

          ${data.currentPage < data.totalPages ? `
            <a href="${buildUrl(data.currentPage + 1)}" class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Next
            </a>
          ` : `
            <span class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-400 dark:text-zinc-600 shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 opacity-50 cursor-not-allowed">Next</span>
          `}
        </div>
      ` : ""}

      <!-- Desktop Pagination -->
      <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
        <div class="flex items-center gap-4">
          <p class="text-sm text-zinc-500 dark:text-zinc-400">
            Showing <span class="font-medium text-zinc-950 dark:text-white">${data.startItem}</span> to
            <span class="font-medium text-zinc-950 dark:text-white">${data.endItem}</span> of
            <span class="font-medium text-zinc-950 dark:text-white">${data.totalItems}</span> results
          </p>
          ${data.showPageSizeSelector !== false ? `
            <div class="flex items-center gap-2">
              <label for="page-size" class="text-sm text-zinc-500 dark:text-zinc-400">Per page:</label>
              <div class="grid grid-cols-1">
                <select
                  id="page-size"
                  onchange="window.location.href = this.value"
                  class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400"
                >
                  ${(data.pageSizeOptions || [10, 20, 50, 100]).map((size) => `
                    <option value="${buildPageSizeUrl(size)}" ${size === data.itemsPerPage ? "selected" : ""}>
                      ${size}
                    </option>
                  `).join("")}
                </select>
                <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-4 self-center justify-self-end text-zinc-600 dark:text-zinc-400">
                  <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
              </div>
            </div>
          ` : ""}
        </div>

        ${data.totalPages > 1 ? `
          <div class="flex items-center gap-x-1">
            <!-- Previous Button -->
            ${data.currentPage > 1 ? `
            <a href="${buildUrl(data.currentPage - 1)}"
               class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Previous
            </a>
          ` : ""}

          <!-- Page Numbers -->
          ${data.showPageNumbers !== false ? `
            <!-- First page if not in range -->
            ${(() => {
    const pageNumbers = generatePageNumbers();
    const firstPage = pageNumbers.length > 0 ? pageNumbers[0] : null;
    return firstPage && firstPage > 1 ? `
                <a href="${buildUrl(1)}"
                   class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  1
                </a>
                ${firstPage > 2 ? `
                  <span class="px-2 text-sm text-zinc-500 dark:text-zinc-400">...</span>
                ` : ""}
              ` : "";
  })()}

            <!-- Page number buttons -->
            ${generatePageNumbers().map((pageNum) => `
              ${pageNum === data.currentPage ? `
                <span class="rounded-lg bg-zinc-950 dark:bg-white px-3 py-2 text-sm font-semibold text-white dark:text-zinc-950">
                  ${pageNum}
                </span>
              ` : `
                <a href="${buildUrl(pageNum)}"
                   class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  ${pageNum}
                </a>
              `}
            `).join("")}

            <!-- Last page if not in range -->
            ${(() => {
    const pageNumbers = generatePageNumbers();
    const lastPageNum = pageNumbers.length > 0 ? pageNumbers.slice(-1)[0] : null;
    return lastPageNum && lastPageNum < data.totalPages ? `
                ${lastPageNum < data.totalPages - 1 ? `
                  <span class="px-2 text-sm text-zinc-500 dark:text-zinc-400">...</span>
                ` : ""}
                <a href="${buildUrl(data.totalPages)}"
                   class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  ${data.totalPages}
                </a>
              ` : "";
  })()}
          ` : ""}

          <!-- Next Button -->
          ${data.currentPage < data.totalPages ? `
            <a href="${buildUrl(data.currentPage + 1)}"
               class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Next
            </a>
          ` : ""}
          </div>
        ` : ""}
      </div>
    </div>
  `;
}

// src/templates/table.template.ts
function renderTable(data) {
  const tableId = data.tableId || `table-${Math.random().toString(36).substr(2, 9)}`;
  if (data.rows.length === 0) {
    return `
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8 text-center">
        <div class="text-zinc-500 dark:text-zinc-400">
          <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">${data.emptyMessage || "No data available"}</p>
        </div>
      </div>
    `;
  }
  return `
    <div class="${data.className || ""}" id="${tableId}">
      ${data.title ? `
        <div class="px-4 sm:px-0 mb-4">
          <h3 class="text-base font-semibold text-zinc-950 dark:text-white">${data.title}</h3>
        </div>
      ` : ""}
      <div class="overflow-x-auto">
        <table class="min-w-full sortable-table">
          <thead>
            <tr>
              ${data.selectable ? `
                <th class="px-4 py-3.5 text-center sm:pl-0">
                  <div class="flex items-center justify-center">
                    <div class="group grid size-4 grid-cols-1">
                      <input type="checkbox" id="select-all-${tableId}" class="col-start-1 row-start-1 appearance-none rounded border border-white/10 bg-white/5 checked:border-cyan-500 checked:bg-cyan-500 indeterminate:border-cyan-500 indeterminate:bg-cyan-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 disabled:border-white/5 disabled:bg-white/10 disabled:checked:bg-white/10 forced-colors:appearance-auto row-checkbox" />
                      <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-white/25">
                        <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                      </svg>
                    </div>
                  </div>
                </th>
              ` : ""}
              ${data.columns.map((column, index) => {
    const isFirst = index === 0 && !data.selectable;
    const isLast = index === data.columns.length - 1;
    return `
                <th class="px-4 py-3.5 text-left text-sm font-semibold text-zinc-950 dark:text-white ${isFirst ? "sm:pl-0" : ""} ${isLast ? "sm:pr-0" : ""} ${column.className || ""}">
                  ${column.sortable ? `
                    <button
                      class="flex items-center gap-x-2 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors sort-btn text-left"
                      data-column="${column.key}"
                      data-sort-type="${column.sortType || "string"}"
                      data-sort-direction="none"
                      onclick="sortTable('${tableId}', '${column.key}', '${column.sortType || "string"}')"
                    >
                      <span>${column.label}</span>
                      <div class="sort-icons flex flex-col">
                        <svg class="w-3 h-3 sort-up opacity-30" fill="currentColor" viewBox="0 0 20 20">
                          <path fill-rule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clip-rule="evenodd" />
                        </svg>
                        <svg class="w-3 h-3 sort-down opacity-30 -mt-1" fill="currentColor" viewBox="0 0 20 20">
                          <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                        </svg>
                      </div>
                    </button>
                  ` : column.label}
                </th>
              `;
  }).join("")}
            </tr>
          </thead>
          <tbody>
            ${data.rows.map((row) => {
    if (!row) return "";
    const clickableClass = data.rowClickable ? "cursor-pointer" : "";
    const clickHandler = data.rowClickable && data.rowClickUrl ? `onclick="window.location.href='${data.rowClickUrl(row)}'"` : "";
    return `
                <tr class="group border-t border-zinc-950/5 dark:border-white/5 hover:bg-gradient-to-r hover:from-cyan-50/50 hover:via-blue-50/30 hover:to-purple-50/50 dark:hover:from-cyan-900/20 dark:hover:via-blue-900/10 dark:hover:to-purple-900/20 hover:shadow-sm hover:shadow-cyan-500/5 dark:hover:shadow-cyan-400/5 transition-all duration-300 ${clickableClass}" ${clickHandler}>
                  ${data.selectable ? `
                    <td class="px-4 py-4 sm:pl-0" onclick="event.stopPropagation()">
                      <div class="flex items-center justify-center">
                        <div class="group grid size-4 grid-cols-1">
                          <input type="checkbox" value="${row.id || ""}" class="col-start-1 row-start-1 appearance-none rounded border border-white/10 bg-white/5 checked:border-cyan-500 checked:bg-cyan-500 indeterminate:border-cyan-500 indeterminate:bg-cyan-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 disabled:border-white/5 disabled:bg-white/10 disabled:checked:bg-white/10 forced-colors:appearance-auto row-checkbox" />
                          <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-white/25">
                            <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                            <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                          </svg>
                        </div>
                      </div>
                    </td>
                  ` : ""}
                  ${data.columns.map((column, colIndex) => {
      const value = row[column.key];
      const displayValue = column.render ? column.render(value, row) : value;
      const stopPropagation = column.key === "actions" ? 'onclick="event.stopPropagation()"' : "";
      const isFirst = colIndex === 0 && !data.selectable;
      const isLast = colIndex === data.columns.length - 1;
      return `
                      <td class="px-4 py-4 text-sm text-zinc-500 dark:text-zinc-400 ${isFirst ? "sm:pl-0 font-medium text-zinc-950 dark:text-white" : ""} ${isLast ? "sm:pr-0" : ""} ${column.className || ""}" ${stopPropagation}>
                        ${displayValue || ""}
                      </td>
                    `;
    }).join("")}
                </tr>
              `;
  }).join("")}
          </tbody>
        </table>
      </div>

      <script>
        // Table sorting functionality
        window.sortTable = function(tableId, column, sortType) {
          const tableContainer = document.getElementById(tableId);
          const table = tableContainer.querySelector('.sortable-table');
          const tbody = table.querySelector('tbody');
          const rows = Array.from(tbody.querySelectorAll('tr'));
          const headerBtn = table.querySelector(\`[data-column="\${column}"]\`);

          // Get current sort direction
          let direction = headerBtn.getAttribute('data-sort-direction');

          // Reset all sort indicators
          table.querySelectorAll('.sort-btn').forEach(btn => {
            btn.setAttribute('data-sort-direction', 'none');
            btn.querySelectorAll('.sort-up, .sort-down').forEach(icon => {
              icon.classList.add('opacity-30');
              icon.classList.remove('opacity-100', 'text-zinc-950', 'dark:text-white');
            });
          });

          // Determine new direction
          if (direction === 'none' || direction === 'desc') {
            direction = 'asc';
          } else {
            direction = 'desc';
          }

          // Update current header
          headerBtn.setAttribute('data-sort-direction', direction);
          const upIcon = headerBtn.querySelector('.sort-up');
          const downIcon = headerBtn.querySelector('.sort-down');

          if (direction === 'asc') {
            upIcon.classList.remove('opacity-30');
            upIcon.classList.add('opacity-100', 'text-zinc-950', 'dark:text-white');
            downIcon.classList.add('opacity-30');
            downIcon.classList.remove('opacity-100', 'text-zinc-950', 'dark:text-white');
          } else {
            downIcon.classList.remove('opacity-30');
            downIcon.classList.add('opacity-100', 'text-zinc-950', 'dark:text-white');
            upIcon.classList.add('opacity-30');
            upIcon.classList.remove('opacity-100', 'text-zinc-950', 'dark:text-white');
          }

          // Find column index (accounting for potential select column)
          const headers = Array.from(table.querySelectorAll('th'));
          const selectableOffset = table.querySelector('input[id^="select-all"]') ? 1 : 0;
          const columnIndex = headers.findIndex(th => th.querySelector(\`[data-column="\${column}"]\`)) - selectableOffset;

          // Sort rows
          rows.sort((a, b) => {
            const aCell = a.children[columnIndex + selectableOffset];
            const bCell = b.children[columnIndex + selectableOffset];

            if (!aCell || !bCell) return 0;

            let aValue = aCell.textContent.trim();
            let bValue = bCell.textContent.trim();

            // Handle different sort types
            switch (sortType) {
              case 'number':
                aValue = parseFloat(aValue.replace(/[^0-9.-]/g, '')) || 0;
                bValue = parseFloat(bValue.replace(/[^0-9.-]/g, '')) || 0;
                break;
              case 'date':
                aValue = new Date(aValue).getTime() || 0;
                bValue = new Date(bValue).getTime() || 0;
                break;
              case 'boolean':
                aValue = aValue.toLowerCase() === 'true' || aValue.toLowerCase() === 'published' || aValue.toLowerCase() === 'active';
                bValue = bValue.toLowerCase() === 'true' || bValue.toLowerCase() === 'published' || bValue.toLowerCase() === 'active';
                break;
              default: // string
                aValue = aValue.toLowerCase();
                bValue = bValue.toLowerCase();
            }

            if (aValue < bValue) return direction === 'asc' ? -1 : 1;
            if (aValue > bValue) return direction === 'asc' ? 1 : -1;
            return 0;
          });

          // Re-append sorted rows
          rows.forEach(row => tbody.appendChild(row));
        };

        // Select all functionality
        document.addEventListener('DOMContentLoaded', function() {
          document.querySelectorAll('[id^="select-all"]').forEach(selectAll => {
            selectAll.addEventListener('change', function() {
              const tableId = this.id.replace('select-all-', '');
              const table = document.getElementById(tableId);
              if (table) {
                const checkboxes = table.querySelectorAll('.row-checkbox');
                checkboxes.forEach(checkbox => {
                  checkbox.checked = this.checked;
                });
              }
            });
          });
        });
      </script>
    </div>
  `;
}

// src/templates/layouts/admin-layout-v2.template.ts
init_logo_template();
function renderAdminLayout(data) {
  const {
    renderAdminLayoutCatalyst: renderAdminLayoutCatalyst2
  } = (init_admin_layout_catalyst_template(), __toCommonJS(admin_layout_catalyst_template_exports));
  return renderAdminLayoutCatalyst2(data);
}
function adminLayoutV2(data) {
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
function renderSidebar(currentPath, user, dynamicMenuItems) {
  const baseMenuItems = [
    {
      label: "Dashboard",
      path: "/admin",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
      </svg>`
    },
    {
      label: "Content",
      path: "/admin/content",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`
    },
    {
      label: "Collections",
      path: "/admin/collections",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3z"/>
      </svg>`
    },
    {
      label: "Media",
      path: "/admin/media",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11.707 4.707a1 1 0 00-1.414-1.414L10 9.586 8.707 8.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
      </svg>`
    },
    {
      label: "Users",
      path: "/admin/users",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3z"/>
      </svg>`
    },
    {
      label: "Plugins",
      path: "/admin/plugins",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
      </svg>`
    },
    {
      label: "Cache",
      path: "/admin/cache",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
      </svg>`
    },
    {
      label: "Design",
      path: "/admin/design",
      icon: `<svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M4.098 19.902a3.75 3.75 0 0 0 5.304 0l6.401-6.402M6.75 21A3.75 3.75 0 0 1 3 17.25V4.125C3 3.504 3.504 3 4.125 3h5.25c.621 0 1.125.504 1.125 1.125v4.072M6.75 21a3.75 3.75 0 0 0 3.75-3.75V8.197M6.75 21h13.125c.621 0 1.125-.504 1.125-1.125v-5.25c0-.621-.504-1.125-1.125-1.125h-4.072M10.5 8.197l2.88-2.88c.438-.439 1.15-.439 1.59 0l3.712 3.713c.44.44.44 1.152 0 1.59l-2.879 2.88M6.75 17.25h.008v.008H6.75v-.008Z" />
      </svg>`
    },
    {
      label: "Logs",
      path: "/admin/logs",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`
    },
    {
      label: "Settings",
      path: "/admin/settings",
      icon: `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/>
      </svg>`
    },
    {
      label: "API Reference",
      path: "/admin/api-reference",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
      </svg>`
    },
    {
      label: "Field Types",
      path: "/admin/field-types",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
      </svg>`
    },
    {
      label: "API Spec",
      path: "/api",
      target: "_blank",
      icon: `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`
    }
  ];
  const allMenuItems = [...baseMenuItems];
  if (dynamicMenuItems && dynamicMenuItems.length > 0) {
    const usersIndex = allMenuItems.findIndex(
      (item) => item.path === "/admin/users"
    );
    if (usersIndex !== -1) {
      allMenuItems.splice(usersIndex + 1, 0, ...dynamicMenuItems);
    } else {
      allMenuItems.push(...dynamicMenuItems);
    }
  }
  return `
    <nav class="backdrop-blur-md bg-black/30 rounded-xl border border-white/10 shadow-xl p-6 h-[calc(100vh-9.5rem)] sticky top-8">
      <div class="space-y-4">
        ${allMenuItems.map((item) => {
    const isActive = currentPath === item.path || item.path !== "/admin" && currentPath.startsWith(item.path);
    const targetAttr = item.target ? ` target="${item.target}"` : "";
    return `
            <a href="${item.path}"${targetAttr} class="flex items-center space-x-3 ${isActive ? "text-white bg-white/20" : "text-gray-300 hover:text-white"} rounded-lg px-3 py-2 transition-all hover:bg-white/10">
              ${item.icon}
              <span>${item.label}</span>
            </a>
          `;
  }).join("")}
      </div>
    </nav>
  `;
}
function renderTopBar(pageTitle, user) {
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
            ${user ? `
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
            ` : `
              <a href="/auth/login" class="backdrop-blur-md bg-white/10 px-4 py-2 rounded-lg text-white font-medium hover:bg-white/20 transition-all">
                Sign In
              </a>
            `}
        </div>
      </div>
    </header>
  `;
}

// src/templates/pages/admin-design.template.ts
init_admin_layout_catalyst_template();
function renderDesignPage(data) {
  const pageContent = `
    <div class="space-y-8">
      <!-- Header -->
      <div class="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Catalyst Design System</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            A comprehensive showcase of all UI components and design patterns
          </p>
        </div>
        <div class="mt-4 sm:mt-0 flex gap-x-2">
          <a
            href="/docs/design-system"
            class="inline-flex items-center gap-x-2 rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white hover:bg-zinc-50 dark:hover:bg-zinc-700 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 transition-colors shadow-sm"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
            Documentation
          </a>
        </div>
      </div>

      <!-- Quick Navigation -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
        <div class="flex items-center justify-between mb-6">
          <div>
            <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Component Library</h2>
            <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Browse all available components</p>
          </div>
          <span class="inline-flex items-center gap-x-1.5 rounded-lg bg-zinc-950 dark:bg-white px-3 py-1.5 text-xs font-semibold text-white dark:text-zinc-950">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
            </svg>
            Quick Nav
          </span>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
          <a href="#modern" class="text-sm font-medium text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors">Modern Patterns</a>
          <a href="#typography" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Typography</a>
          <a href="#colors" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Colors</a>
          <a href="#buttons" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Buttons</a>
          <a href="#forms" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Forms</a>
          <a href="#checkboxes" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Checkboxes</a>
          <a href="#tables" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Tables</a>
          <a href="#alerts" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Alerts</a>
          <a href="#badges" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Badges</a>
          <a href="#cards" class="text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">Cards</a>
        </div>
      </div>

      <!-- Modern Patterns Section -->
      <div id="modern">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Modern UI Patterns</h2>

        <!-- Gradient Filter Bar -->
        <div class="space-y-6">
          <div>
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Gradient Filter Bar</h3>
            <div class="relative rounded-xl overflow-hidden">
              <div class="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-purple-500/10 dark:from-cyan-400/20 dark:via-blue-400/20 dark:to-purple-400/20"></div>
              <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
                <div class="px-6 py-5">
                  <div class="flex items-center gap-x-4">
                    <div class="relative group flex-1 max-w-sm">
                      <div class="absolute left-3.5 top-2.5 flex items-center justify-center w-5 h-5 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 dark:from-cyan-300 dark:to-blue-400 opacity-90 group-focus-within:opacity-100 transition-opacity">
                        <svg class="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                      </div>
                      <input
                        type="text"
                        placeholder="Search with gradient icon..."
                        class="w-full rounded-full bg-transparent pl-11 pr-4 py-2 text-sm text-zinc-950 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 border-2 border-cyan-200/50 dark:border-cyan-700/50 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400 focus:shadow-lg focus:shadow-cyan-500/20 dark:focus:shadow-cyan-400/20 transition-all duration-300"
                      />
                    </div>
                    <button class="inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-cyan-200/50 dark:ring-cyan-700/50 hover:bg-gradient-to-r hover:from-cyan-50 hover:to-blue-50 dark:hover:from-cyan-900/30 dark:hover:to-blue-900/30 hover:ring-cyan-300 dark:hover:ring-cyan-600 transition-all duration-200">
                      <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                      </svg>
                      Refresh
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Colored Badges -->
          <div>
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Colored Category Badges</h3>
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
              <div class="flex flex-wrap gap-2">
                <span class="inline-flex items-center rounded-md bg-lime-50 dark:bg-lime-500/10 px-2.5 py-1 text-sm font-medium text-lime-700 dark:text-lime-300 ring-1 ring-inset ring-lime-700/10 dark:ring-lime-400/20">
                  Collection Name
                </span>
                <span class="inline-flex items-center rounded-md bg-pink-50 dark:bg-pink-500/10 px-2.5 py-1 text-sm font-medium text-pink-700 dark:text-pink-300 ring-1 ring-inset ring-pink-700/10 dark:ring-pink-400/20">
                  5 fields
                </span>
                <span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-500/10 px-2.5 py-1 text-sm font-medium text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-700/10 dark:ring-cyan-400/20">
                  Interactive
                </span>
                <span class="inline-flex items-center rounded-md bg-purple-50 dark:bg-purple-500/10 px-2.5 py-1 text-sm font-medium text-purple-700 dark:text-purple-300 ring-1 ring-inset ring-purple-700/10 dark:ring-purple-400/20">
                  Category
                </span>
              </div>
            </div>
          </div>

          <!-- Enhanced Table Row -->
          <div>
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Enhanced Table with Gradient Hover</h3>
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
              <table class="min-w-full">
                <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                  <tr>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Name</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Type</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr class="group border-t border-zinc-950/5 dark:border-white/5 hover:bg-gradient-to-r hover:from-cyan-50/50 hover:via-blue-50/30 hover:to-purple-50/50 dark:hover:from-cyan-900/20 dark:hover:via-blue-900/10 dark:hover:to-purple-900/20 hover:shadow-sm hover:shadow-cyan-500/5 dark:hover:shadow-cyan-400/5 hover:border-l-2 hover:border-l-cyan-500 dark:hover:border-l-cyan-400 transition-all duration-300">
                    <td class="px-6 py-4 text-sm font-medium text-zinc-950 dark:text-white">Example Item</td>
                    <td class="px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                      <span class="inline-flex items-center rounded-md bg-lime-50 dark:bg-lime-500/10 px-2.5 py-1 text-sm font-medium text-lime-700 dark:text-lime-300 ring-1 ring-inset ring-lime-700/10 dark:ring-lime-400/20">
                        Collection
                      </span>
                    </td>
                    <td class="px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                      <span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">
                        Active
                      </span>
                    </td>
                  </tr>
                  <tr class="group border-t border-zinc-950/5 dark:border-white/5 hover:bg-gradient-to-r hover:from-cyan-50/50 hover:via-blue-50/30 hover:to-purple-50/50 dark:hover:from-cyan-900/20 dark:hover:via-blue-900/10 dark:hover:to-purple-900/20 hover:shadow-sm hover:shadow-cyan-500/5 dark:hover:shadow-cyan-400/5 hover:border-l-2 hover:border-l-cyan-500 dark:hover:border-l-cyan-400 transition-all duration-300">
                    <td class="px-6 py-4 text-sm font-medium text-zinc-950 dark:text-white">Another Item</td>
                    <td class="px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                      <span class="inline-flex items-center rounded-md bg-pink-50 dark:bg-pink-500/10 px-2.5 py-1 text-sm font-medium text-pink-700 dark:text-pink-300 ring-1 ring-inset ring-pink-700/10 dark:ring-pink-400/20">
                        Content
                      </span>
                    </td>
                    <td class="px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                      <span class="inline-flex items-center rounded-md bg-amber-50 dark:bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-400 ring-1 ring-inset ring-amber-600/20 dark:ring-amber-500/20">
                        Draft
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- Typography Section -->
      <div id="typography">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Typography</h2>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
          <div class="space-y-8">
            <div>
              <h1 class="text-3xl font-semibold text-zinc-950 dark:text-white">Heading 1</h1>
              <code class="mt-2 block text-xs text-zinc-500 dark:text-zinc-400">text-3xl font-semibold</code>
            </div>

            <div>
              <h2 class="text-2xl font-semibold text-zinc-950 dark:text-white">Heading 2</h2>
              <code class="mt-2 block text-xs text-zinc-500 dark:text-zinc-400">text-2xl font-semibold</code>
            </div>

            <div>
              <h3 class="text-xl font-semibold text-zinc-950 dark:text-white">Heading 3</h3>
              <code class="mt-2 block text-xs text-zinc-500 dark:text-zinc-400">text-xl font-semibold</code>
            </div>

            <div>
              <p class="text-base text-zinc-950 dark:text-white">Body text - This is the standard body text used throughout the interface for content and descriptions.</p>
              <code class="mt-2 block text-xs text-zinc-500 dark:text-zinc-400">text-base</code>
            </div>

            <div>
              <p class="text-sm text-zinc-500 dark:text-zinc-400">Small text - Used for secondary information and metadata.</p>
              <code class="mt-2 block text-xs text-zinc-500 dark:text-zinc-400">text-sm text-zinc-500</code>
            </div>
          </div>
        </div>
      </div>

      <!-- Colors Section -->
      <div id="colors">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Color Palette</h2>

        <div class="space-y-6">
          <!-- Pastel Brand Colors -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Pastel Brand Colors (Currently Used)</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <div class="h-20 rounded-lg bg-cyan-400 dark:bg-cyan-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">cyan-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#22d3ee</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-pink-400 dark:bg-pink-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">pink-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#f472b6</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-purple-400 dark:bg-purple-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">purple-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#c084fc</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-lime-400 dark:bg-lime-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">lime-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#a3e635</span>
              </div>
            </div>
          </div>

          <!-- Full Pastel Palette -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Complete Pastel Color Set</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              <div>
                <div class="h-20 rounded-lg bg-cyan-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">cyan-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#22d3ee</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-sky-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">sky-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#38bdf8</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-blue-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">blue-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#60a5fa</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-indigo-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">indigo-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#818cf8</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-purple-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">purple-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#c084fc</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-fuchsia-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">fuchsia-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#e879f9</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-pink-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">pink-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#f472b6</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-rose-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">rose-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#fb7185</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-red-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">red-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#f87171</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-orange-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">orange-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#fb923c</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-amber-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">amber-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#fbbf24</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-yellow-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">yellow-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#facc15</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-lime-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">lime-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#a3e635</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-green-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">green-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#4ade80</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-emerald-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">emerald-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#34d399</span>
              </div>
              <div>
                <div class="h-20 rounded-lg bg-teal-400 shadow-sm"></div>
                <span class="text-xs font-medium text-zinc-950 dark:text-white mt-2 block">teal-400</span>
                <span class="text-xs text-zinc-500 dark:text-zinc-400">#2dd4bf</span>
              </div>
            </div>
          </div>

          <!-- Zinc Scale & Semantic Colors -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <!-- Zinc Scale -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Zinc (Neutral Scale)</h3>
              <div class="space-y-2">
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-zinc-50 ring-1 ring-inset ring-zinc-950/10"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">zinc-50</span>
                </div>
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-zinc-100 ring-1 ring-inset ring-zinc-950/10"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">zinc-100</span>
                </div>
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-zinc-500"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">zinc-500</span>
                </div>
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-zinc-900"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">zinc-900</span>
                </div>
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-zinc-950"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">zinc-950</span>
                </div>
              </div>
            </div>

            <!-- Semantic Colors -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Semantic Colors</h3>
              <div class="space-y-2">
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-blue-500"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">Info - blue-500</span>
                </div>
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-green-500"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">Success - green-500</span>
                </div>
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-amber-500"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">Warning - amber-500</span>
                </div>
                <div class="flex items-center gap-x-3">
                  <div class="h-10 w-10 rounded-lg bg-red-500"></div>
                  <span class="text-sm text-zinc-950 dark:text-white">Error - red-500</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Buttons Section -->
      <div id="buttons">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Buttons</h2>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
          <div class="space-y-8">
            <!-- Primary Buttons -->
            <div>
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Primary</h3>
              <div class="flex flex-wrap gap-3">
                <button class="inline-flex items-center gap-x-2 rounded-lg bg-zinc-950 dark:bg-white px-4 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                  </svg>
                  Create New
                </button>
                <button class="rounded-lg bg-zinc-950 dark:bg-white px-5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
                  Save Changes
                </button>
              </div>
            </div>

            <!-- Secondary Buttons -->
            <div>
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Secondary</h3>
              <div class="flex flex-wrap gap-3">
                <button class="inline-flex items-center gap-x-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                  </svg>
                  Edit
                </button>
                <button class="rounded-lg bg-white dark:bg-zinc-800 px-5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  Cancel
                </button>
              </div>
            </div>

            <!-- Danger Buttons -->
            <div>
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Danger</h3>
              <div class="flex flex-wrap gap-3">
                <button class="inline-flex items-center gap-x-2 rounded-lg bg-red-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-red-700 transition-colors">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                  </svg>
                  Delete
                </button>
              </div>
            </div>

            <!-- Link Buttons -->
            <div>
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Link Style</h3>
              <div class="flex flex-wrap gap-3">
                <button class="text-sm font-semibold text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">
                  Learn more \u2192
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Forms Section -->
      <div id="forms">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Form Components</h2>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
          <form class="space-y-6">
            <!-- Text Input -->
            <div>
              <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">
                Text Input
              </label>
              <input
                type="text"
                placeholder="Enter text..."
                class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
              />
            </div>

            <!-- Select -->
            <div>
              <label for="select-demo" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">
                Select Dropdown
              </label>
              <div class="mt-2 grid grid-cols-1">
                <select id="select-demo" class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400 sm:text-sm/6">
                  <option value="">Choose an option</option>
                  <option value="1">Option 1</option>
                  <option value="2" selected>Option 2</option>
                  <option value="3">Option 3</option>
                </select>
                <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-600 dark:text-zinc-400 sm:size-4">
                  <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
              </div>
            </div>

            <!-- Textarea -->
            <div>
              <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">
                Textarea
              </label>
              <textarea
                rows="3"
                placeholder="Enter description..."
                class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
              ></textarea>
            </div>

            <!-- Radio -->
            <div>
              <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-3">
                Radio Group
              </label>
              <div class="space-y-2">
                <div class="flex items-center gap-x-2">
                  <input
                    type="radio"
                    id="radio-1"
                    name="radio-demo"
                    class="h-4 w-4 border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-950 dark:text-white focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white focus:ring-offset-0"
                  />
                  <label for="radio-1" class="text-sm text-zinc-950 dark:text-white">
                    Option 1
                  </label>
                </div>
                <div class="flex items-center gap-x-2">
                  <input
                    type="radio"
                    id="radio-2"
                    name="radio-demo"
                    class="h-4 w-4 border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-950 dark:text-white focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white focus:ring-offset-0"
                  />
                  <label for="radio-2" class="text-sm text-zinc-950 dark:text-white">
                    Option 2
                  </label>
                </div>
              </div>
            </div>
          </form>
        </div>
      </div>

      <!-- Checkboxes Section -->
      <div id="checkboxes">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Checkboxes</h2>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
          <div class="space-y-8">
            <!-- Simple Checkboxes -->
            <div>
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Simple Checkboxes</h3>
              <fieldset>
                <legend class="sr-only">Simple Checkboxes</legend>
                <div class="space-y-3">
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input id="checkbox-1" type="checkbox" name="simple" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto" />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6"><label for="checkbox-1" class="font-medium text-zinc-950 dark:text-white">Default checkbox</label></div>
                  </div>
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input id="checkbox-2" type="checkbox" name="simple" checked class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto" />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6"><label for="checkbox-2" class="font-medium text-zinc-950 dark:text-white">Checked checkbox</label></div>
                  </div>
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input id="checkbox-3" type="checkbox" name="simple" disabled class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto" />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6"><label for="checkbox-3" class="font-medium text-zinc-500 dark:text-zinc-500">Disabled checkbox</label></div>
                  </div>
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input id="checkbox-4" type="checkbox" name="simple" checked disabled class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto" />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6"><label for="checkbox-4" class="font-medium text-zinc-500 dark:text-zinc-500">Disabled & checked</label></div>
                  </div>
                </div>
              </fieldset>
            </div>

            <!-- Checkboxes with Descriptions -->
            <div>
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">With Descriptions</h3>
              <fieldset>
                <legend class="sr-only">Notifications</legend>
                <div class="space-y-5">
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input id="email-notif" type="checkbox" name="notifications" checked aria-describedby="email-desc" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto" />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6">
                      <label for="email-notif" class="font-medium text-zinc-950 dark:text-white">Email notifications</label>
                      <p id="email-desc" class="text-zinc-500 dark:text-zinc-400">Receive email updates about new features and product announcements.</p>
                    </div>
                  </div>
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input id="marketing" type="checkbox" name="notifications" aria-describedby="marketing-desc" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto" />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6">
                      <label for="marketing" class="font-medium text-zinc-950 dark:text-white">Marketing communications</label>
                      <p id="marketing-desc" class="text-zinc-500 dark:text-zinc-400">Get tips, special offers, and news about our products and services.</p>
                    </div>
                  </div>
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input id="security" type="checkbox" name="notifications" checked disabled aria-describedby="security-desc" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 forced-colors:appearance-auto" />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6">
                      <label for="security" class="font-medium text-zinc-500 dark:text-zinc-500">Security alerts</label>
                      <p id="security-desc" class="text-zinc-500 dark:text-zinc-400">Important notifications about your account security and privacy.</p>
                    </div>
                  </div>
                </div>
              </fieldset>
            </div>
          </div>
        </div>
      </div>

      <!-- Tables Section -->
      <div id="tables">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Tables</h2>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
          <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/5">
            <thead class="bg-zinc-50 dark:bg-zinc-800/50">
              <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  Name
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  Status
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  Created
                </th>
                <th scope="col" class="relative px-6 py-3">
                  <span class="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
              <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors">
                <td class="whitespace-nowrap px-6 py-4 text-sm font-medium text-zinc-950 dark:text-white">
                  Sample Item 1
                </td>
                <td class="whitespace-nowrap px-6 py-4">
                  <span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">
                    Published
                  </span>
                </td>
                <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                  Jan 15, 2025
                </td>
                <td class="whitespace-nowrap px-6 py-4 text-right text-sm font-medium">
                  <div class="flex justify-end gap-x-2">
                    <a href="#" class="text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">
                      Edit
                    </a>
                    <a href="#" class="text-red-600 hover:text-red-700 dark:hover:text-red-500 transition-colors">
                      Delete
                    </a>
                  </div>
                </td>
              </tr>
              <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors">
                <td class="whitespace-nowrap px-6 py-4 text-sm font-medium text-zinc-950 dark:text-white">
                  Sample Item 2
                </td>
                <td class="whitespace-nowrap px-6 py-4">
                  <span class="inline-flex items-center rounded-md bg-amber-50 dark:bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-400 ring-1 ring-inset ring-amber-600/20 dark:ring-amber-500/20">
                    Draft
                  </span>
                </td>
                <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                  Jan 14, 2025
                </td>
                <td class="whitespace-nowrap px-6 py-4 text-right text-sm font-medium">
                  <div class="flex justify-end gap-x-2">
                    <a href="#" class="text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">
                      Edit
                    </a>
                    <a href="#" class="text-red-600 hover:text-red-700 dark:hover:text-red-500 transition-colors">
                      Delete
                    </a>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Alerts Section -->
      <div id="alerts">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Alerts</h2>

        <div class="space-y-4">
          <!-- Success Alert -->
          <div class="rounded-lg bg-green-50 dark:bg-green-500/10 p-4 ring-1 ring-green-600/20 dark:ring-green-500/20">
            <div class="flex items-start gap-x-3">
              <svg class="h-5 w-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              <div>
                <h3 class="text-sm font-semibold text-green-900 dark:text-green-300">Success</h3>
                <p class="mt-1 text-sm text-green-700 dark:text-green-400">Your changes have been saved successfully.</p>
              </div>
            </div>
          </div>

          <!-- Error Alert -->
          <div class="rounded-lg bg-red-50 dark:bg-red-500/10 p-4 ring-1 ring-red-600/20 dark:ring-red-500/20">
            <div class="flex items-start gap-x-3">
              <svg class="h-5 w-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              <div>
                <h3 class="text-sm font-semibold text-red-900 dark:text-red-300">Error</h3>
                <p class="mt-1 text-sm text-red-700 dark:text-red-400">There was a problem with your request.</p>
              </div>
            </div>
          </div>

          <!-- Warning Alert -->
          <div class="rounded-lg bg-amber-50 dark:bg-amber-500/10 p-4 ring-1 ring-amber-600/20 dark:ring-amber-500/20">
            <div class="flex items-start gap-x-3">
              <svg class="h-5 w-5 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.865-.833-2.632 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"/>
              </svg>
              <div>
                <h3 class="text-sm font-semibold text-amber-900 dark:text-amber-300">Warning</h3>
                <p class="mt-1 text-sm text-amber-700 dark:text-amber-400">Please review your changes before continuing.</p>
              </div>
            </div>
          </div>

          <!-- Info Alert -->
          <div class="rounded-lg bg-blue-50 dark:bg-blue-500/10 p-4 ring-1 ring-blue-600/20 dark:ring-blue-500/20">
            <div class="flex items-start gap-x-3">
              <svg class="h-5 w-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              <div>
                <h3 class="text-sm font-semibold text-blue-900 dark:text-blue-300">Information</h3>
                <p class="mt-1 text-sm text-blue-700 dark:text-blue-400">Here's some helpful information about this feature.</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Badges Section -->
      <div id="badges">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Badges</h2>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
          <div class="flex flex-wrap gap-2">
            <span class="inline-flex items-center rounded-md bg-zinc-50 dark:bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/10 dark:ring-zinc-400/20">
              Default
            </span>
            <span class="inline-flex items-center rounded-md bg-blue-50 dark:bg-blue-500/10 px-2 py-1 text-xs font-medium text-blue-700 dark:text-blue-400 ring-1 ring-inset ring-blue-700/10 dark:ring-blue-400/20">
              Info
            </span>
            <span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">
              Success
            </span>
            <span class="inline-flex items-center rounded-md bg-amber-50 dark:bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-400 ring-1 ring-inset ring-amber-600/20 dark:ring-amber-500/20">
              Warning
            </span>
            <span class="inline-flex items-center rounded-md bg-red-50 dark:bg-red-500/10 px-2 py-1 text-xs font-medium text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20">
              Error
            </span>
          </div>
        </div>
      </div>

      <!-- Cards Section -->
      <div id="cards">
        <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-6">Cards</h2>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <!-- Basic Card -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-2">Basic Card</h3>
            <p class="text-sm text-zinc-500 dark:text-zinc-400">
              A simple card with a title and description.
            </p>
          </div>

          <!-- Interactive Card -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 hover:shadow-md hover:ring-zinc-950/10 dark:hover:ring-white/20 transition-all cursor-pointer">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-2">Interactive Card</h3>
            <p class="text-sm text-zinc-500 dark:text-zinc-400">
              This card has hover effects and is clickable.
            </p>
          </div>

          <!-- Card with Icon -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="flex items-center gap-x-3 mb-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-950 dark:bg-white">
                <svg class="h-5 w-5 text-white dark:text-zinc-950" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
              </div>
              <h3 class="text-base font-semibold text-zinc-950 dark:text-white">With Icon</h3>
            </div>
            <p class="text-sm text-zinc-500 dark:text-zinc-400">
              Card with an icon in the header.
            </p>
          </div>
        </div>
      </div>

    </div>
  `;
  const layoutData = {
    title: "Catalyst Design System",
    currentPath: "/admin/design",
    user: data.user,
    version: data.version,
    content: pageContent
  };
  return renderAdminLayoutCatalyst(layoutData);
}

// src/templates/pages/admin-checkboxes.template.ts
init_admin_layout_catalyst_template();
function renderCheckboxPage(data) {
  const pageContent = `
    <div class="space-y-8">
      <!-- Header -->
      <div class="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Catalyst Checkboxes</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Interactive examples using the official Catalyst checkbox component
          </p>
        </div>
        <div class="mt-4 sm:mt-0">
          <a
            href="/admin/design"
            class="inline-flex items-center gap-x-2 rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white hover:bg-zinc-50 dark:hover:bg-zinc-700 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 transition-colors shadow-sm"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
            </svg>
            Back to Design System
          </a>
        </div>
      </div>

      <!-- Example 1: Discoverability -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
        <h3 class="text-base/6 font-semibold text-zinc-950 dark:text-white mb-2">Discoverability</h3>
        <p class="text-sm/6 text-zinc-500 dark:text-zinc-400 mb-6">Decide where your events can be found across the web.</p>

        <fieldset>
          <legend class="sr-only">Discoverability</legend>
          <div class="space-y-5">
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="show_on_events_page" type="checkbox" name="discoverability" checked aria-describedby="show-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="show_on_events_page" class="font-medium text-zinc-950 dark:text-white">Show on events page</label>
                <p id="show-description" class="text-zinc-500 dark:text-zinc-400">Make this event visible on your profile.</p>
              </div>
            </div>
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="allow_embedding" type="checkbox" name="discoverability" aria-describedby="embedding-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="allow_embedding" class="font-medium text-zinc-950 dark:text-white">Allow embedding</label>
                <p id="embedding-description" class="text-zinc-500 dark:text-zinc-400">Allow others to embed your event details on their own site.</p>
              </div>
            </div>
          </div>
        </fieldset>
      </div>

      <!-- Example 2: Newsletter Preferences -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
        <h3 class="text-base/6 font-semibold text-zinc-950 dark:text-white mb-2">Newsletter Preferences</h3>
        <p class="text-sm/6 text-zinc-500 dark:text-zinc-400 mb-6">Choose which updates you'd like to receive.</p>

        <fieldset>
          <legend class="sr-only">Newsletter Preferences</legend>
          <div class="space-y-5">
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="product_updates" type="checkbox" name="newsletter" checked aria-describedby="product-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="product_updates" class="font-medium text-zinc-950 dark:text-white">Product Updates</label>
                <p id="product-description" class="text-zinc-500 dark:text-zinc-400">Get notified about new features and improvements.</p>
              </div>
            </div>
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="weekly_digest" type="checkbox" name="newsletter" aria-describedby="weekly-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="weekly_digest" class="font-medium text-zinc-950 dark:text-white">Weekly Digest</label>
                <p id="weekly-description" class="text-zinc-500 dark:text-zinc-400">Receive a summary of activity every week.</p>
              </div>
            </div>
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="marketing" type="checkbox" name="newsletter" aria-describedby="marketing-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="marketing" class="font-medium text-zinc-950 dark:text-white">Marketing Emails</label>
                <p id="marketing-description" class="text-zinc-500 dark:text-zinc-400">Special offers and promotional content.</p>
              </div>
            </div>
          </div>
        </fieldset>
      </div>

      <!-- Example 3: Privacy Settings -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
        <h3 class="text-base/6 font-semibold text-zinc-950 dark:text-white mb-2">Privacy Settings</h3>
        <p class="text-sm/6 text-zinc-500 dark:text-zinc-400 mb-6">Control your privacy and data sharing preferences.</p>

        <fieldset>
          <legend class="sr-only">Privacy Settings</legend>
          <div class="space-y-5">
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="profile_public" type="checkbox" name="privacy" checked aria-describedby="profile-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="profile_public" class="font-medium text-zinc-950 dark:text-white">Public Profile</label>
                <p id="profile-description" class="text-zinc-500 dark:text-zinc-400">Make your profile visible to other users.</p>
              </div>
            </div>
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="show_activity" type="checkbox" name="privacy" checked aria-describedby="activity-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="show_activity" class="font-medium text-zinc-950 dark:text-white">Show Activity</label>
                <p id="activity-description" class="text-zinc-500 dark:text-zinc-400">Display your recent activity on your profile.</p>
              </div>
            </div>
            <div class="flex gap-3">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input id="analytics" type="checkbox" name="privacy" aria-describedby="analytics-description" class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto" />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white dark:stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="analytics" class="font-medium text-zinc-950 dark:text-white">Analytics</label>
                <p id="analytics-description" class="text-zinc-500 dark:text-zinc-400">Help us improve by sharing anonymous usage data.</p>
              </div>
            </div>
          </div>
        </fieldset>
      </div>
    </div>
  `;
  const layoutData = {
    title: "Catalyst Checkboxes",
    currentPath: "/admin/checkboxes",
    user: data.user,
    content: pageContent
  };
  return renderAdminLayoutCatalyst(layoutData);
}

// src/templates/pages/admin-testimonials-list.template.ts
init_admin_layout_catalyst_template();
function renderTestimonialsList(data) {
  const { testimonials, totalCount, currentPage, totalPages, message, messageType } = data;
  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Testimonials</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage customer testimonials and reviews</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <a href="/admin/testimonials/new"
             class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
            </svg>
            Add Testimonial
          </a>
        </div>
      </div>

      ${message ? renderAlert({ type: messageType || "info", message, dismissible: true }) : ""}

      <!-- Filters -->
      <div class="relative rounded-xl overflow-hidden mb-6">
        <!-- Gradient Background -->
        <div class="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-purple-500/10 dark:from-cyan-400/20 dark:via-blue-400/20 dark:to-purple-400/20"></div>

        <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
          <div class="px-6 py-5">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-4 flex-1">
                <div>
                  <label for="published" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Status</label>
                  <div class="mt-2 grid grid-cols-1">
                    <select
                      name="published"
                      id="published"
                      hx-get="/admin/testimonials"
                      hx-trigger="change"
                      hx-target="#testimonials-list"
                      hx-include="[name='minRating'], [name='search']"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-cyan-500/30 dark:outline-cyan-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-cyan-500 dark:focus-visible:outline-cyan-400 sm:text-sm/6 min-w-48"
                    >
                      <option value="">All</option>
                      <option value="true">Published</option>
                      <option value="false">Draft</option>
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-cyan-600 dark:text-cyan-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div>
                  <label for="minRating" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Min Rating</label>
                  <div class="mt-2 grid grid-cols-1">
                    <select
                      name="minRating"
                      id="minRating"
                      hx-get="/admin/testimonials"
                      hx-trigger="change"
                      hx-target="#testimonials-list"
                      hx-include="[name='published'], [name='search']"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-cyan-500/30 dark:outline-cyan-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-cyan-500 dark:focus-visible:outline-cyan-400 sm:text-sm/6 min-w-48"
                    >
                      <option value="">All Ratings</option>
                      <option value="5">5 Stars</option>
                      <option value="4">4+ Stars</option>
                      <option value="3">3+ Stars</option>
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-cyan-600 dark:text-cyan-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div class="flex-1 max-w-md">
                  <label for="search" class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Search</label>
                  <div class="relative group">
                    <div class="absolute left-3.5 top-2.5 flex items-center justify-center w-5 h-5 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 dark:from-cyan-300 dark:to-blue-400 opacity-90 group-focus-within:opacity-100 transition-opacity">
                      <svg class="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                      </svg>
                    </div>
                    <input
                      type="text"
                      name="search"
                      id="search"
                      placeholder="Search testimonials..."
                      hx-get="/admin/testimonials"
                      hx-trigger="keyup changed delay:300ms"
                      hx-target="#testimonials-list"
                      hx-include="[name='published'], [name='minRating']"
                      class="w-full rounded-full bg-transparent px-11 py-2 text-sm text-zinc-950 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 border-2 border-cyan-200/50 dark:border-cyan-700/50 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400 focus:shadow-lg focus:shadow-cyan-500/20 dark:focus:shadow-cyan-400/20 transition-all duration-300"
                    />
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-x-3 ml-4">
                <span class="text-sm/6 font-medium text-zinc-700 dark:text-zinc-300 px-3 py-1.5 rounded-full bg-white/60 dark:bg-zinc-800/60 backdrop-blur-sm">${totalCount} ${totalCount === 1 ? "item" : "items"}</span>
                <button
                  onclick="location.reload()"
                  class="inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-cyan-200/50 dark:ring-cyan-700/50 hover:bg-gradient-to-r hover:from-cyan-50 hover:to-blue-50 dark:hover:from-cyan-900/30 dark:hover:to-blue-900/30 hover:ring-cyan-300 dark:hover:ring-cyan-600 transition-all duration-200"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                  </svg>
                  Refresh
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Testimonials List -->
      <div id="testimonials-list">
        ${testimonials.length > 0 ? renderTable({
    tableId: "testimonials-table",
    rowClickable: true,
    rowClickUrl: (row) => `/admin/testimonials/${row.id}`,
    columns: [
      { key: "author", label: "Author", sortable: true, sortType: "string" },
      { key: "testimonial", label: "Testimonial", sortable: false },
      { key: "status", label: "Status", sortable: true, sortType: "boolean" },
      { key: "sortOrder", label: "Order", sortable: true, sortType: "number" },
      { key: "created_at", label: "Created", sortable: true, sortType: "date" }
    ],
    rows: testimonials.map((testimonial) => {
      const rating = testimonial.rating ? "\u2B50".repeat(testimonial.rating) : "";
      const truncated = testimonial.testimonial_text.length > 100 ? testimonial.testimonial_text.substring(0, 100) + "..." : testimonial.testimonial_text;
      return {
        id: testimonial.id,
        author: `
                <div class="flex flex-col">
                  <div class="font-medium text-zinc-950 dark:text-white">${testimonial.author_name}</div>
                  ${testimonial.author_title || testimonial.author_company ? `
                    <div class="text-xs text-zinc-500 dark:text-zinc-400">
                      ${[testimonial.author_title, testimonial.author_company].filter(Boolean).join(" \xB7 ")}
                    </div>
                  ` : ""}
                  ${rating ? `<div class="text-xs mt-1">${rating}</div>` : ""}
                </div>
              `,
        testimonial: `<div class="text-sm text-zinc-700 dark:text-zinc-300 max-w-md">${truncated}</div>`,
        status: testimonial.isPublished ? '<span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">Published</span>' : '<span class="inline-flex items-center rounded-md bg-zinc-50 dark:bg-zinc-500/10 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/20 dark:ring-zinc-500/20">Draft</span>',
        sortOrder: testimonial.sortOrder.toString(),
        created_at: new Date(testimonial.created_at * 1e3).toLocaleDateString()
      };
    }),
    selectable: true
  }) : `
          <div class="text-center py-12 bg-white dark:bg-zinc-900 rounded-lg shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <h3 class="mt-2 text-sm font-semibold text-zinc-950 dark:text-white">No testimonials</h3>
            <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Get started by creating a new testimonial.</p>
            <div class="mt-6">
              <a href="/admin/testimonials/new" class="inline-flex items-center rounded-md bg-zinc-950 dark:bg-white px-3 py-2 text-sm font-semibold text-white dark:text-zinc-950 shadow-sm hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
                <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
                </svg>
                New Testimonial
              </a>
            </div>
          </div>
        `}
      </div>

      ${totalPages > 1 ? renderPagination({
    currentPage,
    totalPages,
    totalItems: totalCount,
    itemsPerPage: 20,
    startItem: (currentPage - 1) * 20 + 1,
    endItem: Math.min(currentPage * 20, totalCount),
    baseUrl: "/admin/testimonials"
  }) : ""}
    </div>
  `;
  const layoutData = {
    title: "Testimonials",
    currentPath: "/admin/testimonials",
    user: data.user,
    content: pageContent
  };
  return renderAdminLayoutCatalyst(layoutData);
}

// src/templates/pages/admin-code-examples-list.template.ts
init_admin_layout_catalyst_template();
function renderCodeExamplesList(data) {
  const { codeExamples, totalCount, currentPage, totalPages, message, messageType } = data;
  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Code Examples</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage code snippets and examples</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <a href="/admin/code-examples/new"
             class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
            </svg>
            Add Code Example
          </a>
        </div>
      </div>

      ${message ? renderAlert({ type: messageType || "info", message, dismissible: true }) : ""}

      <!-- Filters -->
      <div class="relative rounded-xl overflow-hidden mb-6">
        <!-- Gradient Background -->
        <div class="absolute inset-0 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-orange-500/10 dark:from-purple-400/20 dark:via-pink-400/20 dark:to-orange-400/20"></div>

        <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
          <div class="px-6 py-5">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-4 flex-1">
                <div>
                  <label for="published" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Status</label>
                  <div class="mt-2 grid grid-cols-1">
                    <select
                      name="published"
                      id="published"
                      hx-get="/admin/code-examples"
                      hx-trigger="change"
                      hx-target="#code-examples-list"
                      hx-include="[name='language'], [name='search']"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-purple-500/30 dark:outline-purple-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-purple-500 dark:focus-visible:outline-purple-400 sm:text-sm/6 min-w-48"
                    >
                      <option value="">All</option>
                      <option value="true">Published</option>
                      <option value="false">Draft</option>
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-purple-600 dark:text-purple-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div>
                  <label for="language" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Language</label>
                  <div class="mt-2 grid grid-cols-1">
                    <select
                      name="language"
                      id="language"
                      hx-get="/admin/code-examples"
                      hx-trigger="change"
                      hx-target="#code-examples-list"
                      hx-include="[name='published'], [name='search']"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-purple-500/30 dark:outline-purple-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-purple-500 dark:focus-visible:outline-purple-400 sm:text-sm/6 min-w-48"
                    >
                      <option value="">All Languages</option>
                      <option value="javascript">JavaScript</option>
                      <option value="typescript">TypeScript</option>
                      <option value="python">Python</option>
                      <option value="go">Go</option>
                      <option value="rust">Rust</option>
                      <option value="java">Java</option>
                      <option value="php">PHP</option>
                      <option value="ruby">Ruby</option>
                      <option value="sql">SQL</option>
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-purple-600 dark:text-purple-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div class="flex-1 max-w-md">
                  <label for="search" class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Search</label>
                  <div class="relative group">
                    <div class="absolute left-3.5 top-2.5 flex items-center justify-center w-5 h-5 rounded-full bg-gradient-to-br from-purple-400 to-pink-500 dark:from-purple-300 dark:to-pink-400 opacity-90 group-focus-within:opacity-100 transition-opacity">
                      <svg class="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                      </svg>
                    </div>
                    <input
                      type="text"
                      name="search"
                      id="search"
                      placeholder="Search code examples..."
                      hx-get="/admin/code-examples"
                      hx-trigger="keyup changed delay:300ms"
                      hx-target="#code-examples-list"
                      hx-include="[name='published'], [name='language']"
                      class="w-full rounded-full bg-transparent px-11 py-2 text-sm text-zinc-950 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 border-2 border-purple-200/50 dark:border-purple-700/50 focus:outline-none focus:border-purple-500 dark:focus:border-purple-400 focus:shadow-lg focus:shadow-purple-500/20 dark:focus:shadow-purple-400/20 transition-all duration-300"
                    />
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-x-3 ml-4">
                <span class="text-sm/6 font-medium text-zinc-700 dark:text-zinc-300 px-3 py-1.5 rounded-full bg-white/60 dark:bg-zinc-800/60 backdrop-blur-sm">${totalCount} ${totalCount === 1 ? "item" : "items"}</span>
                <button
                  onclick="location.reload()"
                  class="inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-purple-200/50 dark:ring-purple-700/50 hover:bg-gradient-to-r hover:from-purple-50 hover:to-pink-50 dark:hover:from-purple-900/30 dark:hover:to-pink-900/30 hover:ring-purple-300 dark:hover:ring-purple-600 transition-all duration-200"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                  </svg>
                  Refresh
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Code Examples List -->
      <div id="code-examples-list">
        ${codeExamples.length > 0 ? renderTable({
    tableId: "code-examples-table",
    rowClickable: true,
    rowClickUrl: (row) => `/admin/code-examples/${row.id}`,
    columns: [
      { key: "title", label: "Title", sortable: true, sortType: "string" },
      { key: "language", label: "Language", sortable: true, sortType: "string" },
      { key: "description", label: "Description", sortable: false },
      { key: "status", label: "Status", sortable: true, sortType: "boolean" },
      { key: "sortOrder", label: "Order", sortable: true, sortType: "number" },
      { key: "created_at", label: "Created", sortable: true, sortType: "date" }
    ],
    rows: codeExamples.map((example) => {
      const truncatedDesc = example.description ? example.description.length > 80 ? example.description.substring(0, 80) + "..." : example.description : "No description";
      const languageColors = {
        javascript: "bg-yellow-100 dark:bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 ring-yellow-600/20 dark:ring-yellow-500/20",
        typescript: "bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 ring-blue-600/20 dark:ring-blue-500/20",
        python: "bg-green-100 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-green-600/20 dark:ring-green-500/20",
        go: "bg-cyan-100 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 ring-cyan-600/20 dark:ring-cyan-500/20",
        rust: "bg-orange-100 dark:bg-orange-500/10 text-orange-700 dark:text-orange-400 ring-orange-600/20 dark:ring-orange-500/20",
        java: "bg-red-100 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-red-600/20 dark:ring-red-500/20",
        php: "bg-indigo-100 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 ring-indigo-600/20 dark:ring-indigo-500/20",
        ruby: "bg-pink-100 dark:bg-pink-500/10 text-pink-700 dark:text-pink-400 ring-pink-600/20 dark:ring-pink-500/20",
        sql: "bg-purple-100 dark:bg-purple-500/10 text-purple-700 dark:text-purple-400 ring-purple-600/20 dark:ring-purple-500/20"
      };
      const langColor = languageColors[example.language.toLowerCase()] || "bg-zinc-100 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-zinc-600/20 dark:ring-zinc-500/20";
      return {
        id: example.id,
        title: `<div class="font-medium text-zinc-950 dark:text-white">${example.title}</div>`,
        language: `<span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${langColor}">${example.language}</span>`,
        description: `<div class="text-sm text-zinc-700 dark:text-zinc-300 max-w-md">${truncatedDesc}</div>`,
        status: example.isPublished ? '<span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">Published</span>' : '<span class="inline-flex items-center rounded-md bg-zinc-50 dark:bg-zinc-500/10 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/20 dark:ring-zinc-500/20">Draft</span>',
        sortOrder: example.sortOrder.toString(),
        created_at: new Date(example.created_at * 1e3).toLocaleDateString()
      };
    }),
    selectable: true
  }) : `
          <div class="text-center py-12 bg-white dark:bg-zinc-900 rounded-lg shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
            <h3 class="mt-2 text-sm font-semibold text-zinc-950 dark:text-white">No code examples</h3>
            <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Get started by creating a new code example.</p>
            <div class="mt-6">
              <a href="/admin/code-examples/new" class="inline-flex items-center rounded-md bg-zinc-950 dark:bg-white px-3 py-2 text-sm font-semibold text-white dark:text-zinc-950 shadow-sm hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
                <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
                </svg>
                New Code Example
              </a>
            </div>
          </div>
        `}
      </div>

      ${totalPages > 1 ? renderPagination({
    currentPage,
    totalPages,
    totalItems: totalCount,
    itemsPerPage: 20,
    startItem: (currentPage - 1) * 20 + 1,
    endItem: Math.min(currentPage * 20, totalCount),
    baseUrl: "/admin/code-examples"
  }) : ""}
    </div>
  `;
  const layoutData = {
    title: "Code Examples",
    currentPath: "/admin/code-examples",
    user: data.user,
    content: pageContent
  };
  return renderAdminLayoutCatalyst(layoutData);
}

// src/templates/form.template.ts
function renderForm(data) {
  return `
    <form 
      ${data.id ? `id="${data.id}"` : ""}
      ${data.hxPost ? `hx-post="${data.hxPost}"` : data.hxPut ? `hx-put="${data.hxPut}"` : data.action ? `action="${data.action}"` : ""}
      ${data.hxTarget ? `hx-target="${data.hxTarget}"` : ""}
      method="${data.method || "POST"}"
      class="${data.className || "space-y-6"}"
      ${data.fields.some((f) => f.type === "file") ? 'enctype="multipart/form-data"' : ""}
    >
      ${data.title ? `
        <div class="mb-6">
          <h2 class="text-lg font-medium text-gray-1">${data.title}</h2>
          ${data.description ? `<p class="mt-1 text-sm text-gray-4">${data.description}</p>` : ""}
        </div>
      ` : ""}
      
      <div id="form-messages"></div>
      
      ${data.fields.map((field) => renderFormField(field)).join("")}
      
      <div class="flex justify-between items-center pt-6 border-t border-gray-7">
        <div class="flex space-x-4">
          ${data.submitButtons.map((button) => `
            <button 
              type="${button.type || "submit"}"
              ${button.name ? `name="${button.name}"` : ""}
              ${button.value ? `value="${button.value}"` : ""}
              ${button.onclick ? `onclick="${button.onclick}"` : ""}
              class="btn ${button.className || "btn-primary"}"
            >
              ${button.label}
            </button>
          `).join("")}
        </div>
      </div>
    </form>
  `;
}
function renderFormField(field) {
  const fieldId = `field-${field.name}`;
  const required = field.required ? "required" : "";
  const readonly = field.readonly ? "readonly" : "";
  const placeholder = field.placeholder ? `placeholder="${field.placeholder}"` : "";
  let fieldHTML = "";
  switch (field.type) {
    case "text":
    case "email":
    case "number":
    case "date":
      fieldHTML = `
        <input
          type="${field.type === "date" ? "datetime-local" : field.type}"
          id="${fieldId}"
          name="${field.name}"
          value="${field.value || ""}"
          class="form-input ${field.className || ""}"
          ${placeholder}
          ${required}
          ${readonly}
          ${field.validation?.min !== void 0 ? `min="${field.validation.min}"` : ""}
          ${field.validation?.max !== void 0 ? `max="${field.validation.max}"` : ""}
          ${field.validation?.pattern ? `pattern="${field.validation.pattern}"` : ""}
        >
      `;
      break;
    case "textarea":
      fieldHTML = `
        <textarea 
          id="${fieldId}"
          name="${field.name}" 
          class="form-textarea ${field.className || ""}" 
          rows="${field.rows || 4}"
          ${placeholder}
          ${required}
        >${field.value || ""}</textarea>
      `;
      break;
    case "rich_text":
      const uniqueId = `${field.name}-${Date.now()}`;
      fieldHTML = `
        <div class="markdown-field">
          <textarea id="${uniqueId}" name="${field.name}" class="form-textarea" rows="8">${field.value || ""}</textarea>
          <script>
            if (typeof EasyMDE !== 'undefined') {
              new EasyMDE({
                element: document.getElementById('${uniqueId}'),
                minHeight: '300px',
                spellChecker: false,
                status: ['autosave', 'lines', 'words', 'cursor'],
                autosave: {
                  enabled: true,
                  uniqueId: '${uniqueId}',
                  delay: 1000
                },
                renderingConfig: {
                  singleLineBreaks: false,
                  codeSyntaxHighlighting: true
                }
              });
            }
          </script>
        </div>
      `;
      break;
    case "select":
      fieldHTML = `
        <select 
          id="${fieldId}"
          name="${field.name}" 
          class="form-input ${field.className || ""}" 
          ${required}
        >
          ${field.options ? field.options.map((option) => `
            <option value="${option.value}" ${option.selected || field.value === option.value ? "selected" : ""}>
              ${option.label}
            </option>
          `).join("") : ""}
        </select>
      `;
      break;
    case "multi_select":
      fieldHTML = `
        <select 
          id="${fieldId}"
          name="${field.name}" 
          class="form-input ${field.className || ""}" 
          multiple 
          ${required}
        >
          ${field.options ? field.options.map((option) => `
            <option value="${option.value}" ${option.selected ? "selected" : ""}>
              ${option.label}
            </option>
          `).join("") : ""}
        </select>
      `;
      break;
    case "checkbox":
      fieldHTML = `
        <input
          type="checkbox"
          id="${fieldId}"
          name="${field.name}"
          value="1"
          class="size-4 rounded border border-white/15 bg-white/5 checked:border-transparent checked:bg-white disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-white/20 focus:ring-offset-2 ${field.className || ""}"
          ${field.value ? "checked" : ""}
          ${required}
        >
        <label for="${fieldId}" class="ml-2 text-sm text-white">${field.label}</label>
      `;
      break;
    default:
      fieldHTML = `
        <input 
          type="text" 
          id="${fieldId}"
          name="${field.name}" 
          value="${field.value || ""}"
          class="form-input ${field.className || ""}" 
          ${placeholder} 
          ${required}
        >
      `;
      break;
  }
  if (field.type === "checkbox") {
    return `
      <div class="form-group">
        <div class="flex items-center">
          ${fieldHTML}
        </div>
        ${field.helpText ? `<p class="text-sm text-zinc-500 dark:text-zinc-400 mt-1 ml-6">${field.helpText}</p>` : ""}
      </div>
    `;
  }
  return `
    <div class="form-group">
      <label for="${fieldId}" class="form-label">
        ${field.label}${field.required ? " *" : ""}
      </label>
      ${fieldHTML}
      ${field.helpText ? `<p class="text-sm text-zinc-500 dark:text-zinc-400 mt-1">${field.helpText}</p>` : ""}
    </div>
  `;
}

export { adminLayoutV2, getConfirmationDialogScript, init_admin_layout_catalyst_template, init_logo_template, renderAdminLayout, renderAdminLayoutCatalyst, renderAlert, renderCheckboxPage, renderCodeExamplesList, renderConfirmationDialog, renderDesignPage, renderForm, renderFormField, renderLogo, renderPagination, renderTable, renderTestimonialsList };
//# sourceMappingURL=chunk-VCH6HXVP.js.map
//# sourceMappingURL=chunk-VCH6HXVP.js.map