import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The API target differs between `npm run dev` on a host machine
// (talking to the API on localhost) and `vite preview` inside the
// frontend container (talking to the argus-api container by service
// name, per docker-compose.yml). VITE_API_PROXY_TARGET is set as a
// plain container env var for the latter case — this is read by Node
// when the Vite CLI starts, not inlined into client bundle code, so it
// doesn't need the import.meta.env / VITE_ build-time prefix rules.
const apiTarget = process.env.VITE_API_PROXY_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  // `vite preview` (used in the container) doesn't inherit `server.proxy`
  // by default — it has its own `preview.proxy` option, so it has to be
  // configured separately or the built app's /api calls 404 in production.
  preview: {
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
})
