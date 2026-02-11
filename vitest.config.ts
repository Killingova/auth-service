import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["src/tests/setup-env.ts"],
    include: ["src/tests/unit/**/*.test.ts"],
    exclude: ["dist/**", "node_modules/**"],
    passWithNoTests: true,
    reporters: ["default"],
  },
});
