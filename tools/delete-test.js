const { chromium } = require(process.env.PW_PKG);

(async () => {
  const b = await chromium.launch({ executablePath: process.env.CHROME_PATH });
  const p = await b.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const errs = [];
  p.on('pageerror', e => errs.push(String(e)));

  await p.goto(process.env.BASE || 'http://127.0.0.1:9443', { waitUntil: 'networkidle' });
  await p.fill('#login-password', process.env.PASS);
  await p.click('#login-btn');
  await p.waitForTimeout(1500);
  await p.click("button[data-view='certs']");
  await p.waitForTimeout(900);

  const rowsBefore = await p.locator('tbody tr').count();

  const row = p.locator('tbody tr', { hasText: '待删除测试' });
  await row.locator('button:has-text("删除")').click();
  await p.waitForTimeout(700);
  await p.screenshot({ path: 'docs/screenshots/vps-07-delete-confirm.png' });

  const dialogTitle = (await p.locator('.modal-head h3').textContent().catch(() => '') || '').trim();
  await p.click('#confirm-ok');
  await p.waitForTimeout(1500);

  const rowsAfter = await p.locator('tbody tr').count();
  const stillThere = await p.locator('tbody tr', { hasText: '待删除测试' }).count();
  const toasts = await p.locator('.toast').allTextContents();
  await p.screenshot({ path: 'docs/screenshots/vps-08-after-delete.png' });

  console.log(JSON.stringify({ rowsBefore, rowsAfter, stillThere, dialogTitle, toasts, errs }));
  await b.close();
})().catch(e => { console.error('FAILED', e.message); process.exit(1); });
