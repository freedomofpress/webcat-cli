import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: ["node_modules", "dist"],
    server: {
      deps: {
        inline: true,
      },
    },
  },
});
