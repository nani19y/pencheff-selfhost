// SPDX-License-Identifier: MIT
// Pinned ESLint flat config used by eslint_security.sh.
//
// Loads only eslint-plugin-security (MIT) — no parsing or style
// rules from the target repo. The file is .cjs because the runner
// invokes legacy ESLint with --no-eslintrc, which still expects
// CommonJS config syntax.

module.exports = {
  root: true,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
    ecmaFeatures: { jsx: true },
  },
  plugins: ["security"],
  extends: ["plugin:security/recommended-legacy"],
  ignorePatterns: ["node_modules/**", "dist/**", "build/**"],
  rules: {
    // Defaults from the recommended preset cover:
    //   detect-object-injection, detect-eval-with-expression,
    //   detect-buffer-noassert, detect-child-process, detect-disable-mustache-escape,
    //   detect-no-csrf-before-method-override, detect-non-literal-fs-filename,
    //   detect-non-literal-regexp, detect-non-literal-require,
    //   detect-possible-timing-attacks, detect-pseudoRandomBytes, detect-unsafe-regex,
    //   detect-bidi-characters, detect-new-buffer, detect-pseudoRandomBytes
  },
};
