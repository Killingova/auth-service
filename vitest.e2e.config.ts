import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["src/tests/setup-env.ts"],
    include: ["src/tests/http/**/*.test.ts"],
    exclude: ["dist/**", "node_modules/**"],
    testTimeout: 20_000,
    hookTimeout: 20_000,
    reporters: ["default"],
  },
});
