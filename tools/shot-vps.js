const path = require('path');
const fs = require('fs');
const { chromium } = require(process.env.PW_PKG);

const BASE = process.env.BASE || 'http://127.0.0.1:9443';
const PASS = process.env.PASS;
const OUT = path.join(__dirname, '..', 'docs', 'screenshots');
fs.mkdirSync(OUT, { recursive: true });

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', e => errors.push(String(e)));

  await page.goto(BASE, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(500);

  await page.fill('#login-password', PASS);
  await page.click('#login-btn');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUT, 'vps-01-overview.png') });

  await page.click("button[data-view='certs']");
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(OUT, 'vps-04-certs.png') });

  await page.click("button[data-view='compat']");
  await page.waitForTimeout(1800);
  await page.screenshot({ path: path.join(OUT, 'vps-02-compat.png') });

  await page.click("button[data-view='settings']");
  await page.waitForTimeout(900);
  await page.screenshot({ path: path.join(OUT, 'vps-03-settings.png') });

  console.log('TITLE:', await page.title());
  console.log('CONSOLE_ERRORS:', errors.length ? JSON.stringify(errors) : 'none');
  await browser.close();
})().catch(e => { console.error('FAILED', e.message); process.exit(1); });
