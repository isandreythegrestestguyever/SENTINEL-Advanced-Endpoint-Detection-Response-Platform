import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const port = Number(process.env.SENTINEL_E2E_PORT) || 18080;
const baseURL = `http://127.0.0.1:${port}`;
const browser = process.env.PLAYWRIGHT_CHANNEL
  ? { channel: process.env.PLAYWRIGHT_CHANNEL }
  : {};

export default defineConfig({
  testDir: './web/e2e',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL,
    browserName: 'chromium',
    headless: true,
    viewport: { width: 1440, height: 1000 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    ...browser,
  },
  webServer: {
    command: 'go run ./cmd/sentinel',
    cwd: process.cwd(),
    url: `${baseURL}/api/health`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      ...process.env,
      SENTINEL_ADDR: `127.0.0.1:${port}`,
      SENTINEL_DB: join(tmpdir(), `sentinel-playwright-${process.pid}.json`),
      SENTINEL_ADMIN_TOKEN: 'sentinel-e2e-admin-token',
      SENTINEL_ANALYST_TOKEN: 'sentinel-e2e-analyst-token',
      GOMODCACHE: '/tmp/sentinel-gomodcache',
      GOCACHE: '/tmp/sentinel-go-cache',
    },
  },
});
