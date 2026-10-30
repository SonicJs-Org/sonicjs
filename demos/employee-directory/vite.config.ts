import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'path'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const backendUrl = env['VITE_DEV_BACKEND']

  return {
    plugins: [tailwindcss(), react()],
    resolve: {
      alias: {
        '@sonicjs-cms/sdk': resolve(__dirname, '../../packages/sdk/src/index.ts'),
      },
    },
    server: {
      port: 5199,
      ...(backendUrl ? {
        proxy: {
          '/api': { target: backendUrl, changeOrigin: true },
          '/v1': { target: backendUrl, changeOrigin: true },
        },
      } : {}),
    },
  }
})
