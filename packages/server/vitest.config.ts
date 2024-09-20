import { resolve } from 'path';
import { defineConfig } from 'vitest/config';
import pkg from './package.json'

export default defineConfig({
  test: {
    globals: true,
    name: pkg.name,
    alias: {
      '@': resolve(import.meta.dirname, './src'),
    },
  },
});
