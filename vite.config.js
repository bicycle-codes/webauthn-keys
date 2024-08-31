import { defineConfig } from 'vite'
import preact from '@preact/preset-vite'
import postcssNesting from 'postcss-nesting'

// https://vitejs.dev/config/
export default defineConfig({
    define: {
        global: 'globalThis'
    },
    root: 'example',
    plugins: [
        preact({
            devtoolsInProd: false,
            prefreshEnabled: true,
            babel: {
                sourceMaps: 'both'
            }
        }),

        // jsToBottomNoModule()
    ],
    // https://github.com/vitejs/vite/issues/8644#issuecomment-1159308803
    esbuild: {
        logOverride: { 'this-is-undefined-in-esm': 'silent' }
    },
    publicDir: '_public',
    css: {
        postcss: {
            plugins: [
                postcssNesting
            ],
        },
    },
    server: {
        port: 8888,
        host: true,
        open: true,
    },
    build: {
        minify: false,
        outDir: '../public',
        emptyOutDir: true,
        sourcemap: 'inline'
    }
})

// function jsToBottomNoModule () {
//     return {
//         name: 'no-attribute',
//         transformIndexHtml (html) {
//             html = html.replace("type='module' crossorigin", '')
//             const scriptTag = html.match(/<script[^>]*>(.*?)<\/script[^>]*>/)[0]
//             html = html.replace(scriptTag, '')
//             html = html.replace('<!-- # INSERT SCRIPT HERE -->', scriptTag)
//             return html
//         }
//     }
// }
