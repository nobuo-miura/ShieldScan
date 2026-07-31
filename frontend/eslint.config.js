import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'

export default [
  { ignores: ['dist/'] },
  js.configs.recommended,
  // eslint-plugin-react-hooks は eslintrc 形式と flat 形式の両方を同梱している。
  // configs.flat 側でないと plugins が配列のままで ESLint 10 が受け付けない。
  reactHooks.configs.flat['recommended-latest'],
  reactRefresh.configs.vite,
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      globals: globals.browser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    rules: {
      // 大文字始まりの識別子はコンポーネントや定数なので未使用検出から除外する
      'no-unused-vars': ['error', { varsIgnorePattern: '^[A-Z_]' }],
    },
  },
]
