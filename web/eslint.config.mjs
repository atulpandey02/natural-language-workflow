import next from "eslint-config-next";

// eslint-config-next@16 ships a flat config array (core-web-vitals + typescript).
const eslintConfig = [
  ...next,
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "playwright-report/**",
      "test-results/**",
      "next-env.d.ts",
      "e2e/seed.mjs",
    ],
  },
];

export default eslintConfig;
