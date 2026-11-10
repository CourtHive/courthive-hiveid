import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import sonarjs from 'eslint-plugin-sonarjs';
import globals from 'globals';

export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'build/**', 'coverage/**', 'migrations/**', 'scripts/husky/**'],
  },
  js.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        project: 'tsconfig.json',
      },
      globals: {
        ...globals.node,
        ...globals.vitest,
        ...globals.es2021,
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
      sonarjs: sonarjs,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      'sonarjs/cognitive-complexity': ['warn', 30],
      '@typescript-eslint/interface-name-prefix': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { ignoreRestSiblings: true, argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // TypeScript validates identifiers natively (and understands type-only
      // references like `AsyncIterable<T>` in annotations). eslint's no-undef
      // doesn't, and produces false positives on TS built-ins. Per the
      // @typescript-eslint maintainers' own guidance, disable it for TS.
      'no-undef': 'off',
      'no-console': 'off',
      'no-empty': 'warn',
      'no-prototype-builtins': 'off',
    },
  },
  {
    files: ['**/*.cjs', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'script',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'off',
    },
  },
];
