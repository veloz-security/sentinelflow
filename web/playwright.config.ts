import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testIgnore:
    process.env.SENTINELFLOW_VISUAL_BASELINE === '1'
      ? 'csp-production.spec.ts'
      : ['csp-production.spec.ts', 'visual-stability.spec.ts'],
  timeout: 60_000,
  fullyParallel: true,
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  workers: 2,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'narrow-chromium',
      use: {
        browserName: 'chromium',
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 1,
        hasTouch: true,
      },
    },
    {
      name: 'desktop-firefox',
      testIgnore: [/visual-stability\.spec\.ts/, /csp-production\.spec\.ts/],
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'desktop-webkit',
      testIgnore: [/visual-stability\.spec\.ts/, /csp-production\.spec\.ts/],
      use: { ...devices['Desktop Safari'] },
    },
  ],
  webServer: [
    {
      command: 'node tests/mock-management-server.mjs',
      url: 'http://127.0.0.1:4180/__ready',
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command:
        'SENTINELFLOW_MANAGEMENT_API_URL=http://127.0.0.1:4180 npm run preview -- --host 127.0.0.1 --port 4173',
      url: 'http://127.0.0.1:4173',
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
