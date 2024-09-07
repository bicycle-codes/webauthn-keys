import fastGlob from 'fast-glob'
import esbuild from 'esbuild'

await esbuild.build({
    entryPoints: await fastGlob('src/^*.test.ts'),
    keepNames: true,
    minify: false,
    target: 'es2022',
    sourcemap: true,
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
    target: 'es2022',
    sourcemap: true,
    outdir: 'dist',
    outExtension: { '.js': '.min.js' },
    platform: 'browser',
    format: 'esm',
    metafile: true,
    tsconfig: 'tsconfig.build.json',
})
