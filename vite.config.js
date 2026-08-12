import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/threat-hunt-dashboard/',
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/proxy/threatfox': {
        target: 'https://threatfox-api.abuse.ch',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/proxy\/threatfox/, '/api/v1'),
      },
      '/proxy/urlhaus': {
        target: 'https://urlhaus-api.abuse.ch',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/proxy\/urlhaus/, '/v1'),
      },
      '/proxy/feodotracker': {
        target: 'https://feodotracker.abuse.ch',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/proxy\/feodotracker/, ''),
      },
      '/proxy/malwarebazaar': {
        target: 'https://mb-api.abuse.ch',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/proxy\/malwarebazaar/, '/api/v1'),
      },
    },
  },
})
