import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  base: './', // required for Electron loadFile: scripts/css load from relative paths
  plugins: [react()],
  server: {
    port: 5174,
    strictPort: true,
  },
})
