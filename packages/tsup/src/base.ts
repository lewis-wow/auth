import type { Options } from 'tsup';

export const baseTsupConfig: Options = {
  entry: ['src/**/*.{ts,tsx}', '!src/**/*.test.{ts,tsx}'],
  sourcemap: true,
  format: ['esm', 'cjs'],
};
