import fastGlob from 'fast-glob'
import esbuild from 'esbuild'

await esbuild.build({
    entryPoints: await fastGlob('src/^*.test.ts'),
    keepNames: true,
    minify: false,
    sourcemap: 'inline',
    outdir: 'dist',
    platform: 'browser',
    format: 'esm',
    metafile: true,
    tsconfig: 'tsconfig.build.json',
})

await esbuild.build({
    entryPoints: await fastGlob('src/^*.test.ts'),
    keepNames: true,
    minify: true,
    sourcemap: 'inline',
    outdir: 'dist',
    outExtension: { '.js': '.min.js' },
    platform: 'browser',
    format: 'esm',
    metafile: true,
    tsconfig: 'tsconfig.build.json',
})
