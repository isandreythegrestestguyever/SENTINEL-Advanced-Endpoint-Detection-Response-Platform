import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';

async function downloadedJSON(download) {
  const stream = await download.createReadStream();
  let content = '';
  for await (const chunk of stream) content += chunk;
  return JSON.parse(content);
}

test('analyst runs S01, inspects Sigma evidence, and exports the fixture report', async ({ page }) => {
  await page.goto('/#range');
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(11, 15, 16)');

  await page.getByRole('button', { name: 'Set analyst token' }).click();
  await page.locator('#analyst-token').fill('incorrect-e2e-token');
  await page.getByRole('button', { name: 'VERIFY & SAVE' }).click();
  await expect(page.locator('#token-error')).toHaveText('Token not accepted. Check the value and try again.');

  await page.locator('#analyst-token').fill('sentinel-e2e-analyst-token');
  await page.getByRole('button', { name: 'VERIFY & SAVE' }).click();
  await expect(page.locator('#operator-mode')).toHaveText('TOKEN SAVED');
  await expect(page.getByRole('heading', { name: 'Sentinel Range' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'START REPLAY' })).toBeVisible();

  await page.getByRole('button', { name: 'START REPLAY' }).click();
  await expect(page.getByText('SCENARIO PASSED')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText('DETECTED SEN-SIGMA-PUBLIC-001')).toBeVisible();
  await expect(page.getByText('100%', { exact: true })).toHaveCount(2);
  await mkdir('test-results', { recursive: true });
  await page.screenshot({ path: 'test-results/sentinel-range.png', fullPage: true, animations: 'disabled' });

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'EXPORT JSON', exact: true }).click(),
  ]);
  const report = await downloadedJSON(download);
  expect(report.success).toBe(true);
  expect(report.scenario_id).toBe('S01');
  expect(report.detected).toContain('SEN-SIGMA-PUBLIC-001');
  expect(report.alerts).toHaveLength(3);

  await page.locator('[data-view="detections"]').click();
  const sigmaAlert = page.locator('tr').filter({ hasText: 'SEN-SIGMA-PUBLIC-001' });
  await expect(sigmaAlert).toBeVisible();
  await sigmaAlert.getByRole('button', { name: 'INSPECT' }).click();
  await expect(page.locator('.detail-row').filter({ hasText: 'Evidence' }))
    .toContainText('Sigma 7b0cbd19-cc70-4a9b-b6d1-87c51756a422 matched image containing');
  await expect(page.locator('.detail-row').filter({ hasText: 'Data provenance' }))
    .toContainText('SIMULATED');

  await page.locator('[data-view="incidents"]').click();
  const simulatedCase = page.locator('tr').filter({ hasText: 'SIM ·' });
  await expect(simulatedCase).toBeVisible();
  await expect(simulatedCase).toContainText('3 alert(s)');
});

test('all seven scenarios pass through backend ingestion with their ground truth', async ({ page }) => {
  await page.goto('/#range');
  await page.getByRole('button', { name: 'Set analyst token' }).click();
  await page.locator('#analyst-token').fill('sentinel-e2e-analyst-token');
  await page.getByRole('button', { name: 'VERIFY & SAVE' }).click();
  await expect(page.locator('#operator-mode')).toHaveText('TOKEN SAVED');

  const scenarios = await page.locator('[data-scenario]').evaluateAll((buttons) =>
    buttons.map((button) => ({
      id: button.dataset.scenario,
      name: button.querySelector('strong')?.textContent?.trim(),
    })),
  );
  expect(scenarios).toHaveLength(7);

  for (const scenario of scenarios) {
    await page.locator(`[data-scenario="${scenario.id}"]`).click();
    await expect(page.getByRole('heading', { name: scenario.name })).toBeVisible();
    const requirements = await page.locator('.empty-inline').filter({ hasText: 'Results appear after the final event' }).innerText();
    const expected = [...requirements.matchAll(/SEN-[A-Z0-9-]+/g)].map(([ruleId]) => ruleId);

    await page.getByRole('button', { name: 'START REPLAY' }).click();
    await expect(page.getByText('SCENARIO PASSED')).toBeVisible({ timeout: 20_000 });
    for (const ruleId of expected) {
      await expect(page.getByText(`DETECTED ${ruleId}`, { exact: true })).toBeVisible();
    }

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: 'EXPORT JSON', exact: true }).click(),
    ]);
    const report = await downloadedJSON(download);
    expect(report.success, `${scenario.id} should satisfy its ground truth`).toBe(true);
    expect(report.scenario_id).toBe(scenario.id);
    expect(report.expected_alerts).toEqual(expected);
    expect(report.detected).toEqual(expected);
    expect(report.missed).toEqual([]);
    expect(report.unexpected).toEqual([]);
  }
});
