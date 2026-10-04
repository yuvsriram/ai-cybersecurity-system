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
      











      'react-hooks/set-state-in-effect':
        'off',
    },
  },

  {
    files: [
      'src/auth/ApiKeyContext.tsx',
    ],

    rules: {
      




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
      









      'react-hooks/exhaustive-deps':
        'off',
    },
  },
])