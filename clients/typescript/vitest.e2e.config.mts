import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    fileParallelism: false,
    include: ["tests/e2e/*.test.ts"],
    reporters: ["verbose"],
    maxWorkers: 1,
    testTimeout: 30_000,
  },
});
