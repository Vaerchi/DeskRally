import { test, expect, type Page } from '@playwright/test';
const url='http://127.0.0.1:5173/e2e/monitor_windows.html';
// Monitor windows are offered in the View panel (menu redesign wave 7b; they were under "More").
async function viewPanel(page:Page,open:boolean){const t=page.getByTestId('viewer-view-menu');if(((await t.getAttribute('aria-expanded'))==='true')!==open)await t.click();}
async function open(page:Page,id:number){await viewPanel(page,true);const ready=page.waitForEvent('popup');await page.getByTestId(`monitor-window-${id}`).click();const p=await ready;await viewPanel(page,false);await expect(p.getByTestId('viewer-monitor')).toHaveValue(String(id));await expect.poll(()=>p.locator('video').evaluate(v=>({w:v.videoWidth,playing:!v.paused}))).toEqual({w:1280,playing:true});return p;}
// Receive ownership across windows is pinned with automatic clipboard sharing OFF (the F08 behaviour).
test.beforeEach(async({context})=>{await context.addInitScript(()=>{try{localStorage.setItem('deskrally.clipboard.auto','0');}catch{/* none */}});});
test('monitor windows keep independent crops, input and clipboard on one connection',async({page})=>{
 await page.goto(url);const left=await open(page,0);const right=await open(page,1);
 await expect(left.getByTestId('clipboard-send')).toBeVisible();await expect(right.getByTestId('clipboard-send')).toBeVisible();
 for(const [p,x] of [[left,16384],[right,49151]] as const){
  await p.bringToFront();const b=await p.getByTestId('viewer-surface').boundingBox();expect(b).not.toBeNull();
  await p.mouse.move(b!.x+b!.width/2,b!.y+b!.height/2);
  await expect.poll(()=>page.evaluate(()=>(window as any).inputs.filter((e:any)=>e.t==='MouseMove').at(-1)?.c.x)).toBeCloseTo(x,-1);
  await page.evaluate(()=>(window as any).inputs=[]);await p.keyboard.press('a');
  await expect.poll(()=>page.evaluate(()=>(window as any).inputs.filter((e:any)=>e.t==='Key').length)).toBe(2);
 }
 await left.getByTestId('viewer-monitor').selectOption('1');await expect(right.getByTestId('viewer-monitor')).toHaveValue('1');
 await left.getByTestId('viewer-monitor').selectOption('0');await expect(right.getByTestId('viewer-monitor')).toHaveValue('1');
 expect(await page.evaluate(()=>(window as any).selections)).toEqual([]);
 await left.getByRole('button',{name:'Close window',exact:true}).click();await expect.poll(()=>left.isClosed()).toBe(true);
 expect(right.isClosed()).toBe(false);expect(await page.evaluate(()=>(window as any).disconnects)).toBe(0);
 await page.evaluate(()=>(window as any).end());await expect.poll(()=>right.isClosed()).toBe(true);
});
test('removing a display closes its window and a blocked popup reports an error',async({page})=>{
 await page.goto(url);const right=await open(page,1);await page.evaluate(()=>(window as any).removeMonitor());await expect.poll(()=>right.isClosed()).toBe(true);
 await page.reload();await page.evaluate(()=>{window.open=()=>null;});await viewPanel(page,true);await expect(page.getByTestId('monitor-window-0')).toBeVisible();await page.getByTestId('monitor-window-0').click();await expect(page.getByRole('alert')).toContainText('Allow pop-ups');
 await page.evaluate(()=>(window as any).disableCanvas());await expect(page.getByTestId('monitor-window-0')).toHaveCount(0);
});
test('clipboard receive belongs to one monitor window and closing another does not revoke it',async({page})=>{
 await page.goto(url);const left=await open(page,0);const right=await open(page,1);
 for(const p of [left,right])await p.evaluate(()=>{(window as any).writes=[];Object.defineProperty(navigator,'clipboard',{configurable:true,value:{readText:async()=>'',writeText:async(t:string)=>(window as any).writes.push(t)}});});
 await left.getByTestId('clipboard-receive').check();await page.evaluate(()=>(window as any).clipInput('first'));
 await expect.poll(()=>left.evaluate(()=>(window as any).writes)).toEqual(['first']);
 await right.getByTestId('clipboard-receive').check();await expect(left.getByTestId('clipboard-receive')).not.toBeChecked();
 await left.close();await page.evaluate(()=>(window as any).clipInput('second'));
 await expect.poll(()=>right.evaluate(()=>(window as any).writes)).toEqual(['second']);
 await right.close();const again=await open(page,1);await expect(again.getByTestId('clipboard-receive')).not.toBeChecked();
});
