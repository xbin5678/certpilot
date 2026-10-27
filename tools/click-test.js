const { chromium } = require(process.env.PW_PKG);

(async () => {
  const b = await chromium.launch({ executablePath: process.env.CHROME_PATH });
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = [];
  p.on('pageerror', e => errs.push(String(e)));

  await p.goto(process.env.BASE || 'http://127.0.0.1:9443', { waitUntil: 'networkidle' });
  await p.fill('#login-password', process.env.PASS);
  await p.click('#login-btn');
  await p.waitForTimeout(1500);
  await p.click("button[data-view='certs']");
  await p.waitForTimeout(800);

  const row = p.locator('tbody tr').first();
  const cb = row.locator('input[type=checkbox]');
  const sw = row.locator('label.sw');

  const before = await cb.isChecked();
  await sw.click();
  await p.waitForTimeout(1200);
  const toast = (await p.locator('.toast').first().textContent().catch(() => '') || '').trim();

  await p.reload({ waitUntil: 'networkidle' });
  await p.waitForTimeout(1200);
  await p.click("button[data-view='certs']");
  await p.waitForTimeout(800);
  const afterReload = await p.locator('tbody tr').first().locator('input[type=checkbox]').isChecked();
  await p.screenshot({ path: 'docs/screenshots/vps-05-toggle-off.png' });

  await p.locator('tbody tr').first().locator('label.sw').click();
  await p.waitForTimeout(1000);
  const restored = await p.locator('tbody tr').first().locator('input[type=checkbox]').isChecked();

  console.log(JSON.stringify({ before, afterReload, restored, toast, errs }));
  await b.close();
})().catch(e => { console.error('FAILED', e.message); process.exit(1); });
