import { defineConfig } from 'vitest/config'

// https://vitejs.dev/config/
export default defineConfig({
    define: {
        global: 'globalThis'
    },
    root: 'src',
    esbuild: {
        include: ['**/*.ts']
    },
    test: {
        globals: true,
        environment: 'jsdom',
        include: ['*.test.ts']
    }
})
