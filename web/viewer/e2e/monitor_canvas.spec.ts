import { test,expect } from "@playwright/test";
const url="http://127.0.0.1:5173/e2e/monitor_canvas.html";
async function ready(page:any){await expect.poll(()=>page.locator("video").first().evaluate((v:HTMLVideoElement)=>v.videoWidth)).toBe(400);}
async function center(locator:any){const b=await locator.boundingBox();return{x:b.x+b.width/2,y:b.y+b.height/2};}
test("monitor selection crops video and touch/mouse input maps to fixed desktop",async({page},info)=>{
  await page.goto(url);await ready(page);
  const picker=page.getByTestId("viewer-monitor");await expect(picker).toBeEnabled();
  await picker.selectOption("1");
  const crop=page.getByTestId("viewer-crop-wrapper");await expect(crop).toBeVisible();
  const b=await crop.boundingBox();expect(b!.width/b!.height).toBeCloseTo(2/3,2);
  const c=await center(crop);
  // Logs are retained by the mock transport; clear the array in place.
  await page.evaluate(()=>{(window as any).__logs[0].length=0;});
  if(info.project.name==="mobile") await page.touchscreen.tap(c.x,c.y);
  else await page.mouse.move(c.x,c.y);
  await expect.poll(()=>page.evaluate(()=>(window as any).__logs[0].filter((x:any)=>x.t==="MouseMove").length)).toBeGreaterThan(0);
  const point=await page.evaluate(()=>(window as any).__logs[0].filter((x:any)=>x.t==="MouseMove").at(-1).c);
  // Native mouse events quantize CSS coordinates to integer pixels; bound the error to one pixel.
  expect(Math.abs(point.x-16384)).toBeLessThanOrEqual(Math.ceil(32768/b!.width));
  expect(Math.abs(point.y-32768)).toBeLessThanOrEqual(Math.ceil(65535/b!.height));
  await expect.poll(()=>page.evaluate(()=>(window as any).__selections[0])).toEqual([]);
  await page.screenshot({path:test.info().outputPath("left-monitor.png")});
  // A tap in the black letterbox must not send a move or button press.
  const surface=await page.getByTestId("viewer-surface").boundingBox();
  const letterbox={x:surface!.x+1,y:surface!.y+1};
  await page.evaluate(()=>{(window as any).__logs[0].length=0;});
  if(info.project.name==="mobile") await page.touchscreen.tap(letterbox.x,letterbox.y);
  else await page.mouse.click(letterbox.x,letterbox.y);
  expect(await page.evaluate(()=>(window as any).__logs[0])).toEqual([]);
  await picker.selectOption("0");await expect(crop).toBeVisible();
  const primary=await crop.boundingBox();expect(primary!.width/primary!.height).toBeCloseTo(1,2);
  await picker.selectOption("4294967295");await expect(crop).toHaveCount(0);await ready(page);
});
test("two viewers choose independently without changing stream or server selection",async({page})=>{
  await page.goto(url+"?two");await ready(page);
  await page.getByTestId("session-0").getByTestId("viewer-monitor").selectOption("1");
  await expect(page.getByTestId("session-1").getByTestId("viewer-monitor")).toHaveValue("0");
  expect(await page.evaluate(()=>(window as any).__selections)).toEqual([[],[]]);
});
test("old pinned agents keep their selector disabled",async({page})=>{
  await page.goto(url+"?legacy");await expect(page.getByTestId("viewer-monitor")).toBeDisabled();
});
test("popout can choose a local viewport and return with the selection intact",async({page,context})=>{
  await page.goto(url);await ready(page);
  await page.getByTestId("viewer-view-menu").click(); // Pop out is in the View panel (menu redesign wave 7b)
  const [pop]=await Promise.all([context.waitForEvent("page"),page.getByTestId("viewer-popout").click()]);
  await ready(pop);await expect(pop.getByTestId("popout-monitor")).toBeEnabled();
  await pop.getByTestId("popout-monitor").selectOption("1");
  await expect(pop.getByTestId("viewer-crop-wrapper")).toBeVisible();
  // "Return to tab" closes this window: the click can land and the page close before Playwright's click
  // returns, which it reports as "Target page ... has been closed". Wait for the close instead.
  await Promise.all([
    pop.waitForEvent("close"),
    pop.getByRole("button",{name:"Return to tab",exact:true}).click().catch((e:unknown)=>{
      if(!/has been closed/.test(String(e)))throw e;
    }),
  ]);
  await expect(page.getByTestId("viewer-monitor")).toHaveValue("1");await ready(page);
});

test("crop follows surface resize and zoom uses the same geometry",async({page,context})=>{
  await page.goto(url);await ready(page);
  await page.getByTestId("viewer-monitor").selectOption("1");
  await page.setViewportSize({width:780,height:620});
  const crop=page.getByTestId("viewer-crop-wrapper");
  await expect.poll(async()=>{
    const surface=await page.getByTestId("viewer-surface").boundingBox();
    const box=await crop.boundingBox();
    const fit=Math.min(surface!.width/200,surface!.height/300);
    return Math.abs(box!.width-200*fit)+Math.abs(box!.height-300*fit);
  }).toBeLessThan(1);
  await page.getByTestId("viewer-view-menu").click(); // Pop out is in the View panel (menu redesign wave 7b)
  const [pop]=await Promise.all([context.waitForEvent("page"),page.getByTestId("viewer-popout").click()]);
  await ready(pop);const pcrop=pop.getByTestId("viewer-crop-wrapper");
  const initial=await pcrop.boundingBox();
  await pop.getByRole("button",{name:"Zoom in",exact:true}).click();
  await expect.poll(async()=>(await pcrop.boundingBox())!.width).toBeGreaterThan(initial!.width*1.4);
  await pop.getByRole("button",{name:"Fit",exact:true}).click();
  await expect.poll(async()=>Math.abs((await pcrop.boundingBox())!.width-initial!.width)).toBeLessThan(1);
  await pop.close();
});

test("stationary mouse click after selection positions before pressing",async({page})=>{
  await page.goto(url);await ready(page);
  await page.getByTestId("viewer-monitor").selectOption("1");
  const crop=page.getByTestId("viewer-crop-wrapper");const c=await center(crop);
  await page.evaluate(()=>{(window as any).__logs[0].length=0;});
  // Dispatch a down with no preceding mousemove: keyboard selection may leave the mouse still.
  await page.getByTestId("viewer-surface").dispatchEvent("mousedown",{clientX:c.x,clientY:c.y,button:0,bubbles:true});
  const events=await page.evaluate(()=>(window as any).__logs[0]);
  expect(events.map((e:any)=>e.t)).toEqual(["MouseMove","MouseButton"]);
  expect(events[0].c.x).toBeGreaterThan(15000);expect(events[0].c.x).toBeLessThan(18000);
  expect(events[1].c.down).toBe(true);
  await page.getByTestId("viewer-monitor").selectOption("0");
  expect(await page.evaluate(()=>(window as any).__logs[0].at(-1))).toEqual({t:"MouseButton",c:{button:"Left",down:false}});
});
