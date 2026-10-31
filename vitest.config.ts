import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "node",
          include: ["test/**/*.test.ts"],
          environment: "node",
        },
      },
      {
        test: {
          name: "browser",
          include: ["test/**/*.test.ts"],
          // The CLI suite spawns node child processes; that is node-only.
          exclude: ["test/cli.test.ts"],
          browser: {
            enabled: true,
            provider: playwright(),
            instances: [{ browser: "chromium" }],
            headless: true,
          },
        },
      },
    ],
  },
});

