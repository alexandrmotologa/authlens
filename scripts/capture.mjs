import puppeteer from 'puppeteer-core';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

const BROWSER_PATH = fs.existsSync('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')
  ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
  : 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

const OUT_DIR = 'B:\\workgit\\authlens\\docs\\images';
const FRAMES_DIR = 'B:\\workgit\\authlens\\docs\\images\\frames';

if (!fs.existsSync(FRAMES_DIR)) {
  fs.mkdirSync(FRAMES_DIR, { recursive: true });
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function run() {
  console.log('1. Generating traffic on port 9099...');
  try {
    await fetch('http://127.0.0.1:9099/.well-known/openid-configuration');
    await fetch('http://127.0.0.1:9099/.well-known/jwks.json');
    await fetch('http://127.0.0.1:9099/api/status');
    await fetch('http://127.0.0.1:9099/api/personas');
    
    // Simulate PKCE
    await fetch('http://127.0.0.1:9099/api/pkce/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        persona_id: 'admin',
        verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        method: 'S256'
      })
    });

    // Unauthenticated mock call (401)
    await fetch('http://127.0.0.1:9099/api/mock/protected');

    // Authenticated mock call (200)
    const tokRes = await fetch('http://127.0.0.1:9099/api/personas/admin/token?alg=RS256');
    if (tokRes.ok) {
      const tokData = await tokRes.json();
      await fetch('http://127.0.0.1:9099/api/mock/protected', {
        headers: { 'Authorization': `Bearer ${tokData.access_token}` }
      });
    }
  } catch (err) {
    console.error('Error seeding traffic:', err);
  }

  console.log('2. Launching headless browser...');
  const browser = await puppeteer.launch({
    executablePath: BROWSER_PATH,
    headless: 'new',
    defaultViewport: {
      width: 1440,
      height: 900,
      deviceScaleFactor: 2
    },
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--hide-scrollbars']
  });

  const page = await browser.newPage();
  await page.goto('http://127.0.0.1:9099', { waitUntil: 'networkidle0' });
  await sleep(1500);

  console.log('3. Capturing individual panel screenshots...');

  // Helper to click nav item
  async function selectTab(label) {
    const buttons = await page.$$('button');
    for (const btn of buttons) {
      const text = await page.evaluate(el => el.textContent, btn);
      if (text && text.includes(label)) {
        await btn.click();
        await sleep(1200);
        return;
      }
    }
    console.warn('Tab not found:', label);
  }

  // 1. Overview
  await selectTab('Overview & Endpoints');
  await page.screenshot({ path: path.join(OUT_DIR, 'authlens-1.png') });
  console.log('Captured authlens-1.png (Overview)');

  // 2. Personas
  await selectTab('Personas & Tokens');
  await page.screenshot({ path: path.join(OUT_DIR, 'authlens-2.png') });
  console.log('Captured authlens-2.png (Personas)');

  // 3. PKCE
  await selectTab('PKCE Tracer');
  await page.screenshot({ path: path.join(OUT_DIR, 'authlens-3.png') });
  console.log('Captured authlens-3.png (PKCE)');

  // 4. JWT Studio
  await selectTab('Offline JWT Studio');
  await page.screenshot({ path: path.join(OUT_DIR, 'authlens-4.png') });
  console.log('Captured authlens-4.png (JWT Studio)');

  // 5. Security Fuzzer
  await selectTab('Security Fuzzer');
  await page.screenshot({ path: path.join(OUT_DIR, 'authlens-5.png') });
  console.log('Captured authlens-5.png (Security Fuzzer)');

  // 6. Keystore & JWKS
  await selectTab('Keystore & JWKS');
  await page.screenshot({ path: path.join(OUT_DIR, 'authlens-6.png') });
  console.log('Captured authlens-6.png (Keystore)');

  // 7. Traffic Logs
  await selectTab('Traffic Logs');
  await page.screenshot({ path: path.join(OUT_DIR, 'authlens-7.png') });
  console.log('Captured authlens-7.png (Traffic Logs)');

  console.log('4. Capturing animation frames for demo GIF...');
  let frameIdx = 0;
  const tabs = [
    'Overview & Endpoints',
    'Personas & Tokens',
    'PKCE Tracer',
    'Offline JWT Studio',
    'Security Fuzzer',
    'Keystore & JWKS',
    'Traffic Logs'
  ];

  for (const t of tabs) {
    await selectTab(t);
    for (let f = 0; f < 6; f++) {
      const framePath = path.join(FRAMES_DIR, `frame_${String(frameIdx).padStart(3, '0')}.png`);
      await page.screenshot({ path: framePath });
      frameIdx++;
      await sleep(150);
    }
  }

  await browser.close();
  console.log(`Captured ${frameIdx} frames.`);

  console.log('5. Compiling GIF with ffmpeg...');
  const gifPath = path.join(OUT_DIR, 'authlens_demo.gif');
  const palettePath = path.join(FRAMES_DIR, 'palette.png');

  // Palette generation for high quality colors
  execSync(
    `ffmpeg -y -framerate 4 -i "${FRAMES_DIR}\\frame_%03d.png" -vf "scale=960:-1:flags=lanczos,palettegen=stats_mode=diff" "${palettePath}"`,
    { stdio: 'inherit' }
  );

  // GIF rendering with paletteuse
  execSync(
    `ffmpeg -y -framerate 4 -i "${FRAMES_DIR}\\frame_%03d.png" -i "${palettePath}" -lavfi "scale=960:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=3" "${gifPath}"`,
    { stdio: 'inherit' }
  );

  console.log('Cleaning up frames...');
  fs.rmSync(FRAMES_DIR, { recursive: true, force: true });

  console.log('Demo GIF and all 7 screenshots successfully generated!');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
