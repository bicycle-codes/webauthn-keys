import { globby } from 'globby'
import esbuild from 'esbuild'
import path from 'path'
import { fileURLToPath } from 'url'
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// JS
await esbuild.build({
    entryPoints: await globby(['src/*.ts', '!src/*.test.ts']),
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
    entryPoints: [path.join('src', 'index.ts')],
    keepNames: true,
    minify: true,
    target: 'es2022',
    bundle: true,
    sourcemap: true,
    outfile: path.join(__dirname, 'dist', 'index.min.js'),
    outExtension: { '.js': '.min.js' },
    platform: 'browser',
    format: 'esm',
    metafile: true,
    tsconfig: 'tsconfig.build.json',
})
