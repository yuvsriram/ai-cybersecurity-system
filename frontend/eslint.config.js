import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import {
  defineConfig,
  globalIgnores,
} from 'eslint/config'

export default defineConfig([
  globalIgnores([
    'dist',
  ]),

  {
    files: [
      '**/*.{ts,tsx}',
    ],

    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],

    languageOptions: {
      globals:
        globals.browser,
    },

    rules: {
      /*
       * Our pages intentionally load
       * remote API state when mounted or
       * when filters/auth context change.
       *
       * React 19's newer lint preset
       * treats synchronous loading-state
       * updates inside those effects as
       * an error. That rule is more
       * opinionated than corrective for
       * this application architecture.
       */
      'react-hooks/set-state-in-effect':
        'off',
    },
  },

  {
    files: [
      'src/auth/ApiKeyContext.tsx',
    ],

    rules: {
      /*
       * This module intentionally exports
       * both the provider and its consumer
       * hook/context helpers.
       */
      'react-refresh/only-export-components':
        'off',
    },
  },

  {
    files: [
      'src/pages/AuditLogPage.tsx',
      'src/pages/CasesPage.tsx',
      'src/pages/InvestigationsPage.tsx',
    ],

    rules: {
      /*
       * These pages expose explicit
       * load/refresh functions that are
       * also called by UI controls.
       *
       * Their effects are intentionally
       * keyed to the actual state inputs
       * rather than to a newly-created
       * function identity each render.
       */
      'react-hooks/exhaustive-deps':
        'off',
    },
  },
])