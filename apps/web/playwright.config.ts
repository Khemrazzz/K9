import { defineConfig, devices } from "@playwright/test";

const ci = !!process.env.CI;

// End-to-end tests against the real stack: Keycloak and the API from docker compose,
// and this app's production build. See the README for prerequisites.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  forbidOnly: ci,
  // In CI the JSON report feeds the security regression gate (scripts/ci/verify-test-results.mjs).
  reporter: ci ? [["list"], ["json", { outputFile: "playwright-report/e2e-results.json" }]] : [["list"]],
  use: {
    baseURL: "http://localhost:3000",
    // Traces record cookies and headers, so they stay local; CI keeps screenshots only.
    trace: ci ? "off" : "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run start",
    url: "http://localhost:3000",
    reuseExistingServer: !ci,
    timeout: 120_000,
  },
});
