import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    outDir: 'dist',
    target: 'es2022',
    minify: 'esbuild',
    cssMinify: true,
    sourcemap: false,
  },
  server: {
    port: 3000,
  },
});
