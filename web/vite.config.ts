import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://127.0.0.1:9099',
      '/.well-known': 'http://127.0.0.1:9099',
      '/oauth': 'http://127.0.0.1:9099',
      '/userinfo': 'http://127.0.0.1:9099',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
