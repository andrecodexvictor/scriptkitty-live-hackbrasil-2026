import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    outDir: 'dist',
    target: 'es2022',
    minify: 'esbuild',
    cssMinify: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('@openuidev') || id.includes('zod')) {
              return 'vendor-openui';
            }
            if (id.includes('motion')) {
              return 'vendor-motion';
            }
            return 'vendor';
          }
          return undefined;
        },
      },
    },
  },
});
