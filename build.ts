import { globby } from 'globby'
import esbuild from 'esbuild'
import path from 'path'
import { fileURLToPath } from 'url'
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const glob = await globby(['src/*.ts', '!src/*.test.ts'])

// JS
await esbuild.build({
    entryPoints: glob,
    keepNames: true,
    minify: false,
    target: 'es2022',
    sourcemap: true,
    outdir: path.join(__dirname, 'dist'),
    platform: 'browser',
    format: 'esm',
    metafile: true,
    tsconfig: 'tsconfig.build.json',
})

// minified
await esbuild.build({
    entryPoints: glob,
    keepNames: true,
    minify: true,
    target: 'es2022',
    sourcemap: true,
    outdir: path.join(__dirname, 'dist'),
    outExtension: { '.js': '.min.js' },
    platform: 'browser',
    format: 'esm',
    metafile: true,
    tsconfig: 'tsconfig.build.json',
})
