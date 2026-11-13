import { test, expect } from "@playwright/test";
import { openAccountControls } from "./nav";
const release = { version: '0.5.0', url: 'https://main.deskrally.com/download/client/releases/0.5.0/DeskRallyClient.exe', sha256: 'a'.repeat(64), size: 431016 };
for (const width of [1280, 390]) test(`public downloads work without sign-in at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 900 });
  let protectedCalls = 0;
  await page.route('**/cp/**', route => { protectedCalls++; return route.fulfill({ status: 401 }); });
  await page.route('**/download/client/manifest.json', route => route.fulfill({ json: release }));
  await page.goto('/downloads');
  await expect(page.getByRole('link', { name: 'Download Windows desktop app' })).toHaveAttribute('href', '/download/client/releases/0.5.0/DeskRallyClient.exe');
  // The support-agent link comes from VITE_SUPPORT_DOWNLOAD_URL, a BUILD-time value production sets and
  // the test dev server does not (setting it there changes the /join page other specs assert). So:
  // when it is configured the href must be exact, and when it is not the page must say so.
  const support = page.getByRole('link', { name: 'Download Windows support client' });
  if (await support.count()) await expect(support).toHaveAttribute('href', /^\/download\/DeskRallySupport\.exe$|^https:\/\//);
  else await expect(page.getByText('The support download is not available on this site yet.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Get unattended access agent' })).toHaveAttribute('href', '/console?area=enrollment');
  expect(protectedCalls).toBe(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath(`downloads-${width}.png`), fullPage: true });
});
for (const failure of ['malformed', 'missing']) test(`${failure} desktop metadata offers retry without an unsafe link`, async ({ page }) => {
  let valid = false;
  await page.route('**/download/client/manifest.json', route => !valid && failure === 'missing' ? route.fulfill({ status: 404 }) : route.fulfill({ json: valid ? release : { ...release, url: 'https://evil.example/app.exe' } }));
  await page.goto('/downloads');
  await expect(page.getByRole('status')).toContainText('temporarily unavailable');
  await expect(page.getByRole('link', { name: 'Download Windows desktop app' })).toHaveCount(0);
  valid = true;
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByRole('link', { name: 'Download Windows desktop app' })).toBeVisible();
});
test('permanent agent requires login and opens Deploy after authentication', async ({ page }) => {
  let signedIn = false;
  await page.route('**/cp/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/cp/auth/login') { signedIn = true; return route.fulfill({ status: 200, json: {} }); }
    if (!signedIn) return route.fulfill({ status: 401, json: { error: 'unauthorized' } });
    if (path === '/cp/auth/session') return route.fulfill({ status: 204 });
    return route.fulfill({ json: { groups: [], enrollment_tokens: [], machines: [], sessions: [], available: false } });
  });
  await page.goto('/console?area=enrollment');
  await expect(page.getByTestId('app-login-gate')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Downloads', exact: true })).toHaveAttribute('href', '/downloads');
  await expect(page.getByTestId('enrollment-tokens')).toHaveCount(0);
  await page.getByTestId('cp-login-tenant').fill('test');
  await page.getByTestId('cp-login-email').fill('user@example.test');
  await page.getByTestId('cp-login-password').fill('test-password');
  await page.getByTestId('cp-login-submit').click();
  await expect(page.getByTestId('enrollment-tokens')).toBeVisible();
  await expect(page).toHaveURL(/\/console$/);
  await expect(page.getByText('Select a group…')).toHaveCount(0);
});
test('support landing page and console expose Downloads without adding a toolbar row', async ({ page }) => {
  let signedIn = false;
  await page.route('**/cp/**', route => {
    if (!signedIn) return route.fulfill({ status: 401, json: { error: 'unauthorized' } });
    if (new URL(route.request().url()).pathname === '/cp/auth/session') return route.fulfill({ status: 204 });
    return route.fulfill({ json: { machines: [], groups: [], sessions: [], presence_known: true } });
  });
  await page.goto('/');
  await expect(page.getByRole('link', { name: 'Downloads', exact: true })).toHaveAttribute('href', '/downloads');
  signedIn = true;
  await page.goto('/console');
  await openAccountControls(page); // wave 10b: the Account menu at the bar's right end (the DeskRally menu on a phone)
  await expect(page.getByRole('link', { name: 'Downloads', exact: true })).toHaveAttribute('target', '_blank');
  expect((await page.locator('.app__topbar').boundingBox())!.height).toBe(46);
});
