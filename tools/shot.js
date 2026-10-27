const path = require('path');
const fs = require('fs');
const { chromium } = require(process.env.PW_PKG);

const BASE = 'http://127.0.0.1:18443';
const OUT = path.join(__dirname, '..', 'docs', 'screenshots');
fs.mkdirSync(OUT, { recursive: true });

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', e => errors.push(String(e)));

  await page.goto(BASE, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  await page.screenshot({ path: path.join(OUT, '01-login.png') });

  await page.fill('#login-password', 'test12345');
  await page.click('#login-btn');
  await page.waitForTimeout(1600);
  await page.screenshot({ path: path.join(OUT, '02-overview.png') });

  await page.click("button[data-view='certs']");
  await page.waitForTimeout(900);
  await page.screenshot({ path: path.join(OUT, '03-certs.png') });

  await page.click("button[data-view='compat']");
  await page.waitForTimeout(1400);
  await page.screenshot({ path: path.join(OUT, '04-compat.png') });

  await page.click("button[data-view='settings']");
  await page.waitForTimeout(900);
  await page.screenshot({ path: path.join(OUT, '05-settings.png') });

  await page.click("button[data-view='certs']");
  await page.waitForTimeout(600);
  await page.click('text=+ 新建证书');
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT, '06-new-cert.png') });

  console.log('CONSOLE_ERRORS:', errors.length ? JSON.stringify(errors) : 'none');
  await browser.close();
})().catch(e => { console.error('FAILED', e); process.exit(1); });
