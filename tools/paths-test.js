const { chromium } = require(process.env.PW_PKG);

(async () => {
  const b = await chromium.launch({ executablePath: process.env.CHROME_PATH });
  const ctx = await b.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    permissions: ['clipboard-read', 'clipboard-write'],
  });
  const p = await ctx.newPage();
  const errs = [];
  p.on('pageerror', e => errs.push(String(e)));
  p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });

  await p.goto(process.env.BASE || 'http://127.0.0.1:9443', { waitUntil: 'networkidle' });
  await p.fill('#login-password', process.env.PASS);
  await p.click('#login-btn');
  await p.waitForTimeout(1500);

  await p.click("button[data-view='paths']");
  await p.waitForTimeout(1200);
  await p.screenshot({ path: 'docs/screenshots/vps-06-paths.png' });

  // 点第一个"复制"按钮
  await p.locator('button:has-text("复制")').first().click();
  await p.waitForTimeout(600);
  const toast1 = (await p.locator('.toast').first().textContent().catch(() => '') || '').trim();

  // 点"立即重新部署"
  await p.locator('button:has-text("立即重新部署")').first().click();
  await p.waitForTimeout(1500);
  const toasts = await p.locator('.toast').allTextContents();

  console.log(JSON.stringify({
    copyToast: toast1,
    toasts,
    errs,
    pathCount: await p.locator('.pathbox').count(),
  }));
  await b.close();
})().catch(e => { console.error('FAILED', e.message); process.exit(1); });
