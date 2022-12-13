// This enables ESLint to use dependencies of this config
// (see https://github.com/eslint/eslint/issues/3458)
require('eslint-config-toc/setup-plugins')

module.exports = {
  extends: ['toc/typescript'],
}
