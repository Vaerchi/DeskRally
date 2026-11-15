import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin === 'http://127.0.0.1:5173') return route.continue();
    return route.abort();
  });
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
});

test('native WebCrypto delivers requested valid bytes and rejects mismatched bytes', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const modulePath = '/src/lib/file_transfer.ts';
    const ft: typeof import('../src/lib/file_transfer') = await import(modulePath);
    const pool = new ft.DownloadMemoryBudget(1024, 4);
    const delivered: { name: string; bytes: Uint8Array; verified: boolean }[] = [];
    const errors: { reason: string }[] = [];
    const client = new ft.FileTransferClient(() => {}, file => delivered.push(file), () => {},
      { memoryBudget: pool, onDownloadError: error => errors.push(error) });
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const sha = await ft.sha256Hex(bytes);
    try {
      for (const valid of [true, false]) {
        const id = client.request('C:\\synthetic.bin');
        client.handleMessage(ft.encodeMessage({ t: 'Offer', c: { id, name: 'synthetic.bin', size: 4, sha256: valid ? sha : '00'.repeat(32) } }));
        client.handleMessage(ft.encodeMessage({ t: 'Chunk', c: { id, seq: 0, data: bytes } }));
        client.handleMessage(ft.encodeMessage({ t: 'Done', c: { id } }));
      }
      const deadline = performance.now() + 2000;
      while (pool.stats().leases && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
      return { delivered: delivered.map(file => ({ name: file.name, bytes: [...file.bytes], verified: file.verified })), errors, budget: pool.stats() };
    } finally { client.dispose(); }
  });
  expect(result.delivered).toEqual([{ name: 'synthetic.bin', bytes: [1, 2, 3, 4], verified: true }]);
  expect(result.errors.map(e => e.reason)).toEqual(['sha256 mismatch']);
  expect(result.budget.leases).toBe(0);
});

test('native browser timer expires a silent receiving transfer and frees capacity', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const modulePath = '/src/lib/file_transfer.ts';
    const ft: typeof import('../src/lib/file_transfer') = await import(modulePath);
    const pool = new ft.DownloadMemoryBudget(16, 1);
    const errors: { reason: string }[] = [];
    const client = new ft.FileTransferClient(() => {}, () => {}, () => {},
      { memoryBudget: pool, limits: { inactivityMs: 100 }, onDownloadError: e => errors.push(e) });
    try {
      client.handleMessage(ft.encodeMessage({ t: 'Offer', c: {
        id: client.request('synthetic.bin'), name: 'synthetic.bin', size: 4, sha256: '00'.repeat(32),
      } }));
      const admitted = pool.stats().leases;
      const deadline = performance.now() + 2000;
      while (!errors.length && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
      return { admitted, errors, budget: pool.stats() };
    } finally { client.dispose(); }
  });
  expect(result.admitted).toBe(1);
  expect(result.errors.map(e => e.reason)).toEqual(['transfer expired']);
  expect(result.budget).toMatchObject({ used: 0, leases: 0 });
});
