import {test,expect} from '@playwright/test';
test.beforeEach(async({page})=>{
 await page.goto('http://127.0.0.1:5173/e2e/fixtures/connection_diagnostics.html');
 await expect(page.getByText('Connection details',{exact:true})).toBeVisible();
});
test('polls only when open, with one read pending, and reports unavailable fields',async({page})=>{
 expect(await page.evaluate(()=>(window as any).diag.calls())).toBe(0);
 await page.getByText('Connection details',{exact:true}).click();
 await expect.poll(()=>page.evaluate(()=>(window as any).diag.calls())).toBe(1);
 await page.waitForTimeout(2200);
 expect(await page.evaluate(()=>(window as any).diag.calls())).toBe(1);
 await page.evaluate(()=>(window as any).diag.resolve(123));
 await expect(page.getByRole('region')).toContainText('Packets received: 123');
 await expect(page.getByRole('region')).toContainText('Frames decoded: unavailable');
 await page.getByText('Connection details',{exact:true}).click();
 await page.waitForTimeout(2200);
 expect(await page.evaluate(()=>(window as any).diag.calls())).toBe(1);
});
test('discards a previous connection response and handles query errors',async({page})=>{
 await page.getByText('Connection details',{exact:true}).click();
 await expect.poll(()=>page.evaluate(()=>(window as any).diag.calls())).toBe(1);
 await page.evaluate(()=>(window as any).diag.next());
 await page.getByText('Connection details',{exact:true}).click();
 await expect.poll(()=>page.evaluate(()=>(window as any).diag.calls())).toBe(2);
 await page.evaluate(()=>(window as any).diag.resolve(999));
 await expect(page.getByRole('region')).not.toContainText('999');
 await page.evaluate(()=>(window as any).diag.reject());
 await expect(page.getByRole('region')).toContainText('Statistics unavailable; retrying');
});
test('real app exposes diagnostics even when session authorization fails before video',async({page})=>{
 await page.route('**/cp/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/cp/auth/session')return route.fulfill({status:204});
  if(path==='/cp/machines')return route.fulfill({json:{machines:[{id:'machine',tenant_id:'tenant',device_id:'00112233-4455-6677-8899-aabbccddeeff',group_id:'group',name:'Diagnostic test',online:true}],presence_known:true}});
  if(path==='/cp/sessions'&&route.request().method()==='POST')return route.fulfill({status:403,json:{error:'not authorized'}});
  return route.fulfill({json:{sessions:[],groups:[],roles:[],users:[]}});
 });
 await page.goto('http://127.0.0.1:5173/console');
 await page.getByRole('button',{name:'DeskRally',exact:true}).click();
 await page.getByRole('combobox',{name:'Connect in',exact:true}).selectOption('browser');
 await page.keyboard.press('Escape');
 await page.locator('.access__connect').click();
 await page.getByRole('button',{name:'Session',exact:true}).click();
 await page.getByText('Connection details',{exact:true}).click();
 const details=page.getByRole('region',{name:'Connection diagnostic details'});
 await expect(details).toContainText('State: Failed');
 await expect(details).toContainText('Video track: absent');
 await expect(details).toContainText('Inbound video stats: unavailable');
});
