import { renderAlert } from '../alert.template'

export interface LoginPageData {
  error?: string
  message?: string
  version?: string
}

export function renderLoginPage(data: LoginPageData, demoLoginActive: boolean = false): string {
  return `
    <!DOCTYPE html>
    <html lang="en" class="h-full dark">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login - SonicJS AI</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <script src="https://unpkg.com/htmx.org@2.0.3"></script>
      <script src="https://cdn.tailwindcss.com"></script>
      <script>
        tailwind.config = {
          darkMode: 'class',
          theme: {
            extend: {
              colors: {
                error: '#ef4444'
              }
            }
          }
        }
      </script>
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        body {
          font-family: 'Inter', system-ui, -apple-system, sans-serif;
        }
      </style>
    </head>
    <body class="h-full bg-zinc-950">
      <div class="flex min-h-full flex-col justify-center py-12 sm:px-6 lg:px-8">
        <!-- Logo Section -->
        <div class="sm:mx-auto sm:w-full sm:max-w-md text-center">
          <div class="mx-auto w-64 mb-8">
            <svg class="w-full h-auto" viewBox="380 1300 2250 400" aria-hidden="true">
              <path fill="#F1F2F2" d="M476.851,1404.673h168.536c4.714,0,8.695-1.618,11.944-4.866c3.241-3.241,4.866-7.222,4.866-11.943    c0-2.357-0.443-4.569-1.327-6.636c-0.885-2.06-2.067-3.829-3.539-5.308c-1.479-1.472-3.249-2.654-5.308-3.538    c-2.067-0.885-4.279-1.327-6.635-1.327H476.851c-20.057,0-37.158,7.154-51.313,21.454c-14.155,14.308-21.233,31.483-21.233,51.534    c0,20.058,7.078,37.234,21.233,51.534c14.155,14.308,31.255,21.454,51.313,21.454h112.357c10.907,0,20.196,3.837,27.868,11.502    c7.666,7.672,11.502,16.885,11.502,27.646c0,10.769-3.836,19.982-11.502,27.647c-7.672,7.673-16.961,11.502-27.868,11.502H421.115    c-4.721,0-8.702,1.624-11.944,4.865c-3.248,3.249-4.866,7.23-4.866,11.944c0,3.248,0.733,6.123,2.212,8.626    c1.472,2.509,3.462,4.499,5.971,5.972c2.502,1.472,5.378,2.212,8.626,2.212h168.094c20.052,0,37.227-7.078,51.534-21.234    c14.3-14.155,21.454-31.331,21.454-51.534c0-20.196-7.154-37.379-21.454-51.534c-14.308-14.156-31.483-21.234-51.534-21.234    H476.851c-10.616,0-19.76-3.905-27.426-11.721c-7.672-7.811-11.501-17.101-11.501-27.87c0-10.761,3.829-19.975,11.501-27.647    C457.091,1408.508,466.235,1404.673,476.851,1404.673z"></path>
              <path fill="#F1F2F2" d="M974.78,1398.211c-5.016,6.574-10.034,13.146-15.048,19.721c-1.828,2.398-3.657,4.796-5.487,7.194    c1.994,1.719,3.958,3.51,5.873,5.424c18.724,18.731,28.089,41.216,28.089,67.459c0,26.251-9.366,48.658-28.089,67.237    c-18.731,18.579-41.215,27.868-67.459,27.868c-9.848,0-19.156-1.308-27.923-3.923l-4.185,3.354    c-8.587,6.885-17.154,13.796-25.725,20.702c17.52,8.967,36.86,13.487,58.054,13.487c35.533,0,65.91-12.608,91.124-37.821    c25.214-25.215,37.821-55.584,37.821-91.125c0-35.534-12.607-65.911-37.821-91.126    C981.004,1403.663,977.926,1400.854,974.78,1398.211z"></path>
              <path fill="#F1F2F2" d="M1364.644,1439.619c-4.72,0-8.702,1.624-11.943,4.865c-3.249,3.249-4.866,7.23-4.866,11.944v138.014    l-167.651-211.003c-0.297-0.586-0.74-1.03-1.327-1.326c-4.721-4.714-10.249-7.742-16.588-9.069    c-6.346-1.326-12.608-0.732-18.801,1.77c-6.192,2.509-11.059,6.49-14.598,11.944c-3.539,5.46-5.308,11.577-5.308,18.357v208.348    c0,4.721,1.618,8.703,4.866,11.944c3.241,3.241,7.222,4.865,11.943,4.865c2.945,0,5.751-0.738,8.405-2.211    c2.654-1.472,4.713-3.463,6.193-5.971c1.473-2.503,2.212-5.378,2.212-8.627v-205.251l166.325,209.675    c2.06,2.654,4.423,4.865,7.078,6.635c5.308,3.829,11.349,5.75,18.137,5.75c5.308,0,10.464-1.182,15.482-3.538    c3.539-1.769,6.56-4.127,9.069-7.078c2.502-2.945,4.491-6.338,5.971-10.175c1.473-3.829,2.212-7.664,2.212-11.501v-141.552    c0-4.714-1.624-8.695-4.865-11.944C1373.339,1441.243,1369.359,1439.619,1364.644,1439.619z"></path>
              <path fill="#F1F2F2" d="M1508.406,1432.983c-2.654-1.472-5.46-2.212-8.404-2.212c-4.721,0-8.703,1.7-11.944,5.087    c-3.249,3.395-4.865,7.3-4.865,11.723v163.228c0,4.721,1.616,8.702,4.865,11.943c3.241,3.249,7.223,4.866,11.944,4.866    c2.944,0,5.751-0.732,8.404-2.212c2.655-1.472,4.714-3.539,6.193-6.194c1.473-2.654,2.213-5.453,2.213-8.404V1447.58    c0-2.945-0.74-5.75-2.213-8.405C1513.12,1436.522,1511.06,1434.462,1508.406,1432.983z"></path>
              <path fill="#F1F2F2" d="M1499.78,1367.957c-4.575,0-8.481,1.625-11.722,4.866c-3.249,3.249-4.865,7.23-4.865,11.943    c0,2.951,0.732,5.75,2.212,8.405c1.472,2.654,3.463,4.721,5.971,6.193c2.503,1.479,5.378,2.212,8.627,2.212    c4.423,0,8.328-1.618,11.721-4.865c3.387-3.243,5.088-7.224,5.088-11.944c0-4.713-1.701-8.694-5.088-11.943    C1508.33,1369.582,1504.349,1367.957,1499.78,1367.957z"></path>
              <path fill="#F1F2F2" d="M1859.627,1369.727H1747.27c-35.388,0-65.69,12.607-90.904,37.821    c-25.213,25.215-37.82,55.591-37.82,91.125c0,35.54,12.607,65.911,37.82,91.125c25.215,25.215,55.516,37.821,90.904,37.821h56.178    c4.714,0,8.695-1.618,11.944-4.866c3.241-3.241,4.865-7.222,4.865-11.943c0-4.714-1.624-8.695-4.865-11.943    c-3.249-3.243-7.23-4.866-11.944-4.866h-56.178c-26.251,0-48.659-9.359-67.237-28.09c-18.579-18.723-27.868-41.207-27.868-67.459    c0-26.243,9.29-48.659,27.868-67.237c18.579-18.579,40.987-27.868,67.237-27.868h112.357c4.714,0,8.696-1.693,11.944-5.087    c3.241-3.387,4.865-7.368,4.865-11.943c0-4.569-1.624-8.475-4.865-11.723C1868.322,1371.351,1864.341,1369.727,1859.627,1369.727z    "></path>
              <path fill="#06b6d4" d="M2219.256,1371.054h-112.357c-4.423,0-8.336,1.624-11.723,4.865c-3.393,3.249-5.087,7.23-5.087,11.944    c0,4.721,1.694,8.702,5.087,11.943c3.387,3.249,7.3,4.866,11.723,4.866h95.547v95.105c0,26.251-9.365,48.659-28.088,67.237    c-18.731,18.579-41.215,27.868-67.459,27.868c-26.251,0-48.659-9.289-67.237-27.868c-18.579-18.579-27.868-40.987-27.868-67.237    c0-4.713-1.701-8.771-5.088-12.165c-3.393-3.387-7.374-5.087-11.943-5.087c-4.575,0-8.481,1.7-11.722,5.087    c-3.249,3.393-4.865,7.451-4.865,12.165c0,35.388,12.607,65.69,37.82,90.904c25.215,25.213,55.584,37.82,91.126,37.82    c35.532,0,65.91-12.607,91.125-37.82c25.214-25.215,37.82-55.516,37.82-90.904v-111.915c0-4.714-1.624-8.695-4.865-11.944    C2227.951,1372.678,2223.971,1371.054,2219.256,1371.054z"></path>
              <path fill="#06b6d4" d="M2574.24,1502.875c-14.306-14.156-31.483-21.234-51.533-21.234H2410.35    c-10.617,0-19.762-3.829-27.426-11.501c-7.672-7.664-11.501-16.954-11.501-27.868c0-10.907,3.829-20.196,11.501-27.868    c7.664-7.664,16.809-11.501,27.426-11.501h112.357c4.714,0,8.695-1.617,11.944-4.866c3.241-3.241,4.865-7.222,4.865-11.943    c0-4.714-1.624-8.695-4.865-11.944c-3.249-3.241-7.23-4.865-11.944-4.865H2410.35c-20.058,0-37.158,7.154-51.313,21.454    c-14.156,14.308-21.232,31.483-21.232,51.534c0,20.058,7.077,37.234,21.232,51.534c14.156,14.308,31.255,21.454,51.313,21.454    h112.357c7.078,0,13.637,1.77,19.684,5.308c6.042,3.539,10.838,8.336,14.377,14.377c3.538,6.047,5.307,12.607,5.307,19.685    c0,10.616-3.835,19.76-11.501,27.425c-7.672,7.673-16.961,11.502-27.868,11.502h-168.094c-4.721,0-8.703,1.7-11.944,5.087    c-3.249,3.393-4.865,7.374-4.865,11.943c0,4.576,1.616,8.481,4.865,11.723c3.241,3.249,7.223,4.866,11.944,4.866h168.094    c20.051,0,37.227-7.078,51.533-21.234c14.302-14.155,21.454-31.331,21.454-51.534    C2595.695,1534.213,2588.542,1517.03,2574.24,1502.875z"></path>
              <path fill="#06b6d4" d="M854.024,1585.195l20.001-16.028c16.616-13.507,33.04-27.265,50.086-40.251    c1.13-0.861,2.9-1.686,2.003-3.516c-0.843-1.716-2.481-2.302-4.484-2.123c-8.514,0.765-17.016-0.538-25.537-0.353    c-1.124,0.024-2.768,0.221-3.163-1.25c-0.371-1.369,1.088-2.063,1.919-2.894c6.26-6.242,12.574-12.43,18.816-18.691    c9.303-9.327,18.565-18.714,27.851-28.066c1.848-1.859,3.701-3.713,5.549-5.572c2.655-2.661,5.309-5.315,7.958-7.982    c0.574-0.579,1.259-1.141,1.246-1.94c-0.004-0.257-0.078-0.538-0.254-0.853c-0.556-0.981-1.441-1.1-2.469-0.957    c-0.658,0.096-1.315,0.185-1.973,0.275c-3.844,0.538-7.689,1.076-11.533,1.608c-3.641,0.505-7.281,1.02-10.922,1.529    c-4.162,0.582-8.324,1.158-12.486,1.748c-1.142,0.161-2.409,1.662-3.354,0.508c-0.419-0.508-0.431-1.028-0.251-1.531    c0.269-0.741,0.957-1.441,1.387-2.021c3.414-4.58,6.882-9.124,10.356-13.662c1.74-2.272,3.48-4.544,5.214-6.822    c4.682-6.141,9.369-12.281,14.051-18.422c0.09-0.119,0.181-0.237,0.271-0.355c6.848-8.98,13.7-17.958,20.553-26.936    c0.488-0.64,0.977-1.28,1.465-1.92c2.159-2.828,4.315-5.658,6.476-8.486c4.197-5.501,8.454-10.954,12.67-16.442    c0.263-0.347,0.538-0.718,0.717-1.106c0.269-0.586,0.299-1.196-0.335-1.776c-0.825-0.753-1.8-0.15-2.595,0.419    c-0.67,0.472-1.333,0.957-1.955,1.489c-2.206,1.889-4.401,3.797-6.595,5.698c-3.958,3.438-7.922,6.876-11.976,10.194    c-2.443,2.003-4.865,4.028-7.301,6.038c-18.689-10.581-39.53-15.906-62.549-15.906c-35.54,0-65.911,12.607-91.125,37.82    c-25.214,25.215-37.821,55.592-37.821,91.126c0,35.54,12.607,65.91,37.821,91.125c4.146,4.146,8.445,7.916,12.87,11.381    c-9.015,11.14-18.036,22.277-27.034,33.429c-1.208,1.489-3.755,3.151-2.745,4.891c0.078,0.144,0.173,0.281,0.305,0.425    c1.321,1.429,3.492-1.303,4.933-2.457c6.673-5.333,13.333-10.685,19.982-16.042c3.707-2.984,7.417-5.965,11.124-8.952    c1.474-1.188,2.951-2.373,4.425-3.561c6.41-5.164,12.816-10.333,19.238-15.481L854.024,1585.195z M797.552,1498.009    c0-26.243,9.29-48.728,27.868-67.459c18.579-18.723,40.987-28.089,67.238-28.089c12.273,0,23.712,2.075,34.34,6.171    c-3.37,2.905-6.734,5.816-10.069,8.762c-6.075,5.351-12.365,10.469-18.667,15.564c-4.179,3.378-8.371,6.744-12.514,10.164    c-7.54,6.23-15.037,12.52-22.529,18.804c-7.091,5.955-14.182,11.904-21.19,17.949c-1.136,0.974-3.055,1.907-2.135,3.94    c0.831,1.836,2.774,1.417,4.341,1.578l12.145-0.599l14.151-0.698c1.031-0.102,2.192-0.257,2.89,0.632    c0.034,0.044,0.073,0.078,0.106,0.127c1.017,1.561-0.67,2.105-1.387,2.942c-6.308,7.318-12.616,14.637-18.978,21.907    c-8.161,9.339-16.353,18.649-24.544,27.958c-2.146,2.433-4.275,4.879-6.422,7.312c-1.034,1.172-2.129,2.272-1.238,3.922    c0.933,1.728,2.685,1.752,4.323,1.602c4.134-0.367,8.263-0.489,12.396-0.492c0.242,0,0.485-0.005,0.728-0.004    c2.711,0.009,5.422,0.068,8.134,0.145c2.582,0.074,5.166,0.165,7.752,0.249c0.275,1.62-0.879,2.356-1.62,3.259    c-1.333,1.626-2.667,3.247-4,4.867c-4.315,5.252-8.62,10.514-12.928,15.772c-3.562-2.725-7.007-5.733-10.324-9.051    C806.842,1546.667,797.552,1524.26,797.552,1498.009z"></path>
            </svg>
          </div>
          <h2 class="mt-6 text-xl font-medium text-white">Welcome Back</h2>
          <p class="mt-2 text-sm text-zinc-400">Sign in to your account to continue</p>
        </div>

        <!-- Form Container -->
        <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
          <div class="bg-zinc-900 shadow-sm ring-1 ring-white/10 rounded-xl px-6 py-8 sm:px-10">
            <!-- Alerts -->
            ${data.error ? `<div class="mb-6">${renderAlert({ type: 'error', message: data.error })}</div>` : ''}
            ${data.message ? `<div class="mb-6">${renderAlert({ type: 'success', message: data.message })}</div>` : ''}

            <!-- Form Response (errors from Better Auth) -->
            <div id="form-response" class="mb-6"></div>

            <!-- Form: submits to Better Auth /auth/sign-in/email -->
            <form
              id="login-form"
              action="/auth/sign-in/email"
              method="POST"
              class="space-y-6"
            >
              <!-- Email -->
              <div>
                <label for="email" class="block text-sm font-medium text-white mb-2">
                  Email Address
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autocomplete="email"
                  required
                  class="w-full rounded-lg bg-zinc-800 px-3 py-2 text-sm text-white shadow-sm ring-1 ring-inset ring-white/10 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-white transition-shadow"
                  placeholder="Enter your email"
                >
              </div>

              <!-- Password -->
              <div>
                <label for="password" class="block text-sm font-medium text-white mb-2">
                  Password
                </label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  autocomplete="current-password"
                  required
                  class="w-full rounded-lg bg-zinc-800 px-3 py-2 text-sm text-white shadow-sm ring-1 ring-inset ring-white/10 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-white transition-shadow"
                  placeholder="Enter your password"
                >
              </div>

              <!-- Submit Button -->
              <button
                type="submit"
                class="w-full rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-zinc-950 hover:bg-zinc-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-zinc-900 transition-colors"
              >
                Sign In
              </button>
            </form>
            <script>
              (function() {
                var form = document.getElementById('login-form');
                if (!form) return;
                form.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var target = document.getElementById('form-response');
                  var email = form.querySelector('[name="email"]').value;
                  var password = form.querySelector('[name="password"]').value;
                  fetch('/auth/sign-in/email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ email: email, password: password })
                  }).then(function(r) {
                    if (r.ok) { window.location.href = '/admin/dashboard'; return; }
                    return r.json().then(function(d) { return Promise.reject(d); });
                  }).catch(function(err) {
                    if (target) target.innerHTML = '<div class="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">' + (err.message || 'Invalid email or password') + '</div>';
                  });
                });
              })();
            </script>

            <!-- Links -->
            <div class="mt-6 text-center">
              <p class="text-sm text-zinc-400">
                Don't have an account?
                <a href="/auth/register" class="font-semibold text-white hover:text-zinc-300 transition-colors">Create one here</a>
              </p>
            </div>
          </div>

          <!-- Version -->
          <div class="mt-6 text-center">
            <span class="inline-flex items-center rounded-md px-2.5 py-1 text-xs font-medium bg-cyan-500/10 text-cyan-400 ring-1 ring-inset ring-cyan-500/20">
              v${data.version || '0.1.0'}
            </span>
          </div>
        </div>
      </div>

      ${demoLoginActive ? `
      <script>
        // Demo Login Prefill Script
        (function() {
          'use strict';

          function prefillLoginForm() {
            const emailInput = document.getElementById('email');
            const passwordInput = document.getElementById('password');

            if (emailInput && passwordInput) {
              emailInput.value = 'admin@sonicjs.com';
              passwordInput.value = 'sonicjs!';

              // Add visual indication that form is prefilled (only if not already present)
              const form = emailInput.closest('form');
              if (form && !form.querySelector('.demo-mode-notice')) {
                const notice = document.createElement('div');
                notice.className = 'demo-mode-notice mb-6 rounded-lg bg-blue-500/10 p-4 ring-1 ring-blue-500/20';
                notice.innerHTML = '<div class="flex items-start gap-x-3"><svg class="h-5 w-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><div><h3 class="text-sm font-semibold text-blue-300">Demo Mode</h3><p class="mt-1 text-sm text-blue-400">Login form prefilled with demo credentials</p></div></div>';
                form.insertBefore(notice, form.firstChild);
              }
            }
          }

          // Prefill on page load
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', prefillLoginForm);
          } else {
            prefillLoginForm();
          }

          // Also handle HTMX page changes (for SPA-like navigation)
          document.addEventListener('htmx:afterSwap', function(event) {
            if (event.detail.target.id === 'main-content' ||
                document.getElementById('email')) {
              setTimeout(prefillLoginForm, 100);
            }
          });
        })();
      </script>
      ` : ''}
    </body>
    </html>
  `
}