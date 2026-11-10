/**
 * Vitest replaces jest for the service specs.
 *
 * Jest cannot survive the move to NestJS 12: `@nestjs/common@12` is ESM-only
 * ("type": "module", a single `./index.js` entry, and no `require` condition
 * anywhere in its exports map), so a CommonJS jest dies on the first Nest import
 * — before any individual package's compatibility matters.
 *
 * This lands on Nest 11 deliberately, so the runner change is verified against the
 * existing baseline before any dependency bump rides along with it. Same order the
 * factory (#4732 -> #4733) and competition-factory-server (#938 -> #939) migrations
 * used.
 */
import { defineConfig, configDefaults } from 'vitest/config';
import swc from 'unplugin-swc';

import { fileURLToPath } from 'node:url';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  test: {
    // The specs were written against jest's injected globals — describe/it/expect and
    // the hooks are used bare in all seven files. Keeping them global confines this
    // migration to the jest.* -> vi.* surface instead of rewriting every file.
    globals: true,
    environment: 'node',
    // Anchored at the source root, so a sibling
    // worktree or a build output can never be collected as a second copy of the suite.
    include: ['src/**/*.spec.ts'],
    exclude: [...configDefaults.exclude, '**/build/**', '**/.claude/**'],
    setupFiles: ['dotenv/config'],
    // Several specs read and mutate process.env (HIVEID_* secrets, service tokens)
    // at describe scope, which is process-wide state: running the files in parallel
    // workers would make them race. This is what jest's default single worker gave
    // them, and the suite runs in about a second.
    fileParallelism: false,
  },
  resolve: {
    // jest resolved root-relative `src/...` specifiers through
    // modulePaths: ['<rootDir>'] + moduleDirectories: ['node_modules', 'src'].
    // Vite needs it spelled out, and as a PREFIX rule rather than an exact match
    // so it cannot swallow a package that happens to be named `src`.
    alias: [{ find: /^src\//, replacement: `${rootDir}src/` }],
  },
  plugins: [
    // Nest resolves constructor injection from `design:paramtypes`, and esbuild —
    // Vite's default TS transform — cannot emit decorator metadata. swc can, so the
    // specs transform through swc instead, mirroring tsconfig.json's
    // experimentalDecorators + emitDecoratorMetadata.
    swc.vite({
      module: { type: 'es6' },
      jsc: {
        target: 'es2021',
        parser: { syntax: 'typescript', decorators: true },
        transform: { legacyDecorator: true, decoratorMetadata: true },
      },
    }),
  ],
});
