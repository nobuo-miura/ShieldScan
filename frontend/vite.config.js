import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080'
    }
  },
  build: {
    rolldownOptions: {
      output: {
        // recharts が単体でバンドルの大半を占めるため別チャンクに切り出す。
        // アプリ側のコードを更新しても、この重いチャンクはブラウザキャッシュが効く。
        codeSplitting: {
          groups: [
            { name: 'recharts', test: /node_modules[\\/]recharts/ },
            { name: 'react', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
          ],
        },
      },
    },
  },
})
