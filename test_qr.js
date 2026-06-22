const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();

  page.on('console', msg => {
    console.log(`[PAGE CONSOLE] ${msg.type()}: ${msg.text()}`);
  });
  page.on('pageerror', error => {
    console.log(`[PAGE ERROR]: ${error.message}`);
  });
  page.on('requestfailed', request => {
    console.log(`[REQUEST FAILED]: ${request.url()} ${request.failure().errorText}`);
  });

  console.log('Navigating to login page...');
  await page.goto('http://localhost:3000/login', { waitUntil: 'networkidle2' });

  console.log('Opening QR modal...');
  // Find the button that opens the modal
  const button = await page.$('button[data-bs-target="#qrModal"]');
  if (button) {
    await button.click();
    console.log('Clicked button. Waiting 3 seconds...');
    await new Promise(r => setTimeout(r, 3000));
  } else {
    console.log('Button not found!');
  }

  const containerHtml = await page.$eval('#qrCodeContainer', el => el.innerHTML);
  console.log('QR Container HTML:', containerHtml);

  await browser.close();
})();
