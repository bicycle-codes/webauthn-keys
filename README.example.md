# package name here
![tests](https://github.com/substrate-system/icons/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@substrate-system/icons?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://packagephobia.com/badge?p=@namespace/packagename)](https://packagephobia.com/result?p=@substrate-system/packagename)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg?style=flat-square)](package.json)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

`<package description goes here>`

[See a live demo](https://namespace.github.io/package-name/)

<!-- toc -->

## install

Installation instructions

```sh
npm i -S @namespace/package
```

## API

This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import '@namespace/package/module'
```

### Common JS
```js
require('@namespace/package/module')
```

## CSS

### Import CSS

```js
import '@namespace/package-name/css'
```

Or minified:
```js
import '@namespace/package-name/css/min'
```

### Customize CSS via some variables

```css
component-name {
    --example: pink;
}
```

## use

`usage instructions here`

### JS
```js
import '@namespace/package/module'
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@namespace/package/dist/module.min.js ./public
```

#### HTML
```html
<script type="module" src="./module.min.js"></script>
```
