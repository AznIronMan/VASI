import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  test: {
    coverage: {
      reporter: ["text", "html"],
    },
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
