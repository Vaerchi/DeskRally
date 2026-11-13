import {test,expect,type Page} from '@playwright/test';
import { setConnectIn } from "./nav";
const id='00112233-4455-6677-8899-aabbccddeeff';
async function setup(page:Page){
 const state={posts:0,attendedPosts:0,auth:204};
 await page.route('**/cp/**',async route=>{
  const p=new URL(route.request().url()).pathname;
  if(p==='/cp/auth/session')return route.fulfill({status:state.auth});
  if(p==='/cp/machines' && state.auth===401)return route.fulfill({status:401,json:{error:'sign in'}});
  if(p==='/cp/machines')return route.fulfill({json:{machines:[{id:'machine',tenant_id:'tenant',device_id:id,group_id:'group',name:'Test machine',online:true}],presence_known:true}});
  if(p==='/cp/sessions'&&route.request().method()==='POST'){state.posts++;return route.fulfill({status:403,json:{error:'not authorized'}});}
  if(p.endsWith('/connect')){state.attendedPosts++;return route.fulfill({status:403,json:{error:'not authorized'}});}
  return route.fulfill({json:{sessions:[],groups:[],users:[],roles:[]}});
 });return state;
}
for (const tenant of ['main','loam','vc']) test(`${tenant} app launch preserves tenant; browser fallback authorizes normally`,async({page})=>{
 const origin=`https://${tenant}.deskrally.com`;
 await page.route(`${origin}/**`,async route=>{
  const response=await route.fetch({url:route.request().url().replace(origin,'http://127.0.0.1:5173')});
  await route.fulfill({response});
 });
 const s=await setup(page);await page.goto(`${origin}/console`);
 await setConnectIn(page, "desktop");
 await page.locator('.access__connect').click();await expect(page.getByTestId('desktop-launch-notice')).toBeVisible();expect(s.posts).toBe(0);
 await expect(page.getByRole('link',{name:'Open app again'})).toHaveAttribute('href',`deskrally-client://${tenant==='main'?'':`tenant/${tenant}/`}connect/${id}`);
 if(tenant==='main')await expect(page.getByTestId('desktop-launch-notice')).not.toContainText('requires DeskRally');
 else await expect(page.getByTestId('desktop-launch-notice')).toContainText('requires DeskRally 0.6.0 or newer');
 await page.getByRole('button',{name:'Connect in browser instead'}).click();await expect.poll(()=>s.posts).toBe(1);
 await expect(page.getByTestId('desktop-launch-notice')).toHaveCount(0);
});

test('unsupported website never launches into Main',async({page})=>{
 const s=await setup(page);await page.goto('http://127.0.0.1:5173/console');
 await setConnectIn(page, "desktop");
 await page.locator('.access__connect').click();
 await expect(page.getByTestId('desktop-launch-notice')).toHaveCount(0);
 await expect(page.getByText('This connection cannot open in the desktop app. Choose Browser to connect from this website.')).toBeVisible();
 expect(s.posts).toBe(0);
 await setConnectIn(page, "browser");
 await page.locator('.access__connect').click();await expect.poll(()=>s.posts).toBe(1);
});
test('machine and attended deep links wait for authentication',async({page})=>{
 const s=await setup(page);s.auth=401;await page.goto(`http://127.0.0.1:5173/console?device=${id}`);
 await expect(page.getByTestId('app-login-gate')).toBeVisible();expect(s.posts).toBe(0);
 s.auth=204;await page.reload();await expect.poll(()=>s.posts).toBe(1);
 await page.goto(`http://127.0.0.1:5173/console?attended=${id}`);await expect.poll(()=>s.attendedPosts).toBe(1);
});

test.describe('inside the desktop app', () => {
 test.use({userAgent:'Mozilla/5.0 Windows DeskRallyDesktop/0.3.0'});
 test('a failed connection retries here instead of asking to launch another app',async({page})=>{
  const s=await setup(page);
  await page.goto('http://127.0.0.1:5173/console');
  await page.locator('.access__connect').click();
  await expect.poll(()=>s.posts).toBe(1);
  await expect(page.getByText('not authorized',{exact:false}).first()).toBeVisible();
  await page.locator('.access__connect').click();
  await expect.poll(()=>s.posts).toBe(2);
  await expect(page.getByTestId('desktop-launch-notice')).toHaveCount(0);
  await expect(page.getByText('This connection cannot open in the desktop app.',{exact:false})).toHaveCount(0);
 });
 test('an in-progress connection keeps its window and uses app-specific launch instructions',async({page})=>{
  const origin='https://main.deskrally.com';
  await page.route(`${origin}/**`,async route=>{
   const response=await route.fetch({url:route.request().url().replace(origin,'http://127.0.0.1:5173')});
   await route.fulfill({response});
  });
  await setup(page);
  let started=0;
  let release!:()=>void;
  const gate=new Promise<void>(resolve=>{release=resolve;});
  await page.route('**/cp/sessions',async route=>{
   if(route.request().method()!=='POST')return route.fallback();
   started++;await gate;
   await route.fulfill({status:403,json:{error:'not authorized'}});
  });
  try {
   await page.goto(`${origin}/console`);
   await page.locator('.access__connect').click();
   await expect.poll(()=>started).toBe(1);
   await page.locator('.access__connect').click();
   const notice=page.getByTestId('desktop-launch-notice');
   await expect(notice).toContainText('Opening another DeskRally window.');
   await expect(notice).not.toContainText('browser');
   await expect(page.getByRole('button',{name:'Connect in this window instead'})).toBeVisible();
   expect(started).toBe(1);
  } finally {release();}
 });
});
