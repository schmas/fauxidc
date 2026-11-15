import { defineConfig, devices } from "@playwright/test";

// The SPA exit test (spec 14, M2): auth0-spa-js and oidc-client-ts log in,
// refresh and log out against fauxidc. Chromium only; Chrome and Firefox
// desktop runs are manual (docs/testing/m2-exit-test.md).
export default defineConfig({
  testDir: "./tests",
  // Checks a server that already listens on port 9000 (reuseExistingServer).
  globalSetup: "./global-setup.ts",
  timeout: 60_000,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      // server-check.mjs fails with a clear message when another server holds port 9000.
      command:
        "node server-check.mjs && cargo run --manifest-path ../../Cargo.toml -- --config ../../examples/auth0.toml --config ../../examples/okta.toml --config custom-user.toml",
      url: "http://localhost:9000/_mock/health",
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: "pipe",
    },
    {
      command: "node serve.mjs",
      url: "http://localhost:5173/",
      timeout: 30_000,
      reuseExistingServer: !process.env.CI,
    },
  ],
});
