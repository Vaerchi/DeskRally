import { PINNED } from "./chrome_pinned";
import { test, expect, type BrowserContext } from "@playwright/test";
// The Playwright config serves the dev server on 5173 (strictPort); 5178 was a stale port and every
// test here failed at its first goto without running.
const url="http://127.0.0.1:5173/e2e/attended_shared.html";
const record=(id:string,state="consented",reason="Printer support")=>({id,tenant_id:"tenant",group_id:"group",technician_id:"alice",state,reason,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+600000).toISOString()});
async function routes(context:BrowserContext,records:any[]){
 await context.route("**/fixture/**",async route=>{
  const req=route.request(), path=new URL(req.url()).pathname;
  const respond=(body:any,status=200)=>route.fulfill({status,json:body});
  if(path.endsWith("/machine-groups"))return respond({machine_groups:[{id:"group",name:"Support"}]});
  if(path.endsWith("/attended-sessions")){
   if(req.method()==="POST"){
    const s={...record("new-session","pending",req.postDataJSON().reason),technician_id:"alice"};records.unshift(s);
    return respond({session:s,code:"ABCD-EFGH",join_code:"ABCDEFGH",join_url:"/join#ABCDEFGH"},201);
   }
   const offset=Number(new URL(req.url()).searchParams.get("offset")??0);
   return respond({sessions:records.slice(offset,offset+50),has_more:records.length>offset+50});
  }
  const m=path.match(/attended-sessions\/([^/]+)(?:\/(connect|end|promote))?$/);
  if(m){
   const s=records.find(s=>s.id===m[1]);if(!s)return respond({error:"missing"},404);
   if(m[2]==="connect")return respond({session:{...s,state:"active"},signaling:{test:"envelope"}});
   if(m[2]==="end")s.state="ended";
   return respond({session:s});
  }
  return respond({error:"unavailable"},404);
 });
}
test("a closed creator tab can be recovered from fresh browsers and another technician",async({browser})=>{
 const rows:any[]=[];
 const use=test.info().project.use;
 const options={viewport:use.viewport,isMobile:use.isMobile,hasTouch:use.hasTouch,userAgent:use.userAgent,deviceScaleFactor:use.deviceScaleFactor};
 const first=await browser.newContext({ ...PINNED, ...options });await routes(first,rows);const page=await first.newPage();
 await page.goto(url);await expect(page.getByTestId("attended-start")).toBeEnabled();
 await page.getByTestId("attended-reason").fill("Lost-tab printer help");await page.getByTestId("attended-start").click();
 await expect(page.getByTestId("attended-code")).toBeVisible();await first.close();
 for(const account of ["alice","bob"]){
  const fresh=await browser.newContext({ ...PINNED, ...options });await routes(fresh,rows);const recovered=await fresh.newPage();
  await recovered.goto(url+"?account="+account);
  await recovered.getByRole("button",{name:/Lost-tab printer help/}).click();
  await expect(recovered.getByTestId("attended-state")).toHaveText("pending");
  await expect(recovered.getByTestId("attended-code")).toHaveCount(0);
  await expect(recovered.getByTestId("attended-connect")).toBeDisabled();
  rows[0].state="consented";
  await expect(recovered.getByTestId("attended-connect")).toBeEnabled({timeout:10000});
  await recovered.getByTestId("attended-connect").click();
  await expect.poll(()=>recovered.evaluate(()=>(window as any).__connected?.session.id)).toBe("new-session");
  rows[0].state="pending";await fresh.close();
 }
});
test("selecting another session never shows the new invitation's code",async({page,context})=>{
 const rows=[record("old-session")];await routes(context,rows);await page.goto(url);
 await expect(page.getByTestId("attended-start")).toBeEnabled();await page.getByTestId("attended-start").click();
 await expect(page.getByTestId("attended-code")).toBeVisible();
 await page.getByRole("button",{name:/Printer support/}).click();
 await expect(page.getByTestId("attended-code")).toHaveCount(0);
 await expect(page.getByTestId("attended-state")).toHaveText("consented");
 await page.getByTestId("attended-end").click();await expect(page.getByTestId("attended-state")).toHaveText("ended");
 await expect(page.getByTestId("attended-connect")).toBeDisabled();
});


test("pagination and refresh find sessions beyond the first page",async({page,context})=>{
 const rows=Array.from({length:51},(_,i)=>record(`session-${i}`,"pending",`Help ${i}`));
 await routes(context,rows);await page.goto(url);
 await expect(page.getByRole("button",{name:/Help 49 /})).toBeVisible();
 await expect(page.getByRole("button",{name:/Help 50 /})).toHaveCount(0);
 await page.getByRole("button",{name:"Load more",exact:true}).click();
 await page.getByRole("button",{name:/Help 50 /}).click();
 await expect(page.getByTestId("attended-state")).toHaveText("pending");
 rows.unshift(record("new","consented","New colleague session"));
 await page.getByRole("button",{name:"Refresh",exact:true}).click();
 await expect(page.getByRole("button",{name:/New colleague session/})).toBeVisible();
});

test("a delayed previous-account response cannot restore private state",async({page,context})=>{
 const rows=[record("old","consented","Old account private session")];await routes(context,rows);
 let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);
 let requested!:()=>void;const started=new Promise<void>(resolve=>requested=resolve);
 await context.route("**/fixture/alice/attended-sessions?**",async route=>{
  requested();await gate;await route.fulfill({json:{sessions:rows,has_more:false}});
 });
 await context.route("**/fixture/bob/attended-sessions?**",async route=>route.fulfill({json:{sessions:[],has_more:false}}));
 await page.goto(url);await started;
 await page.evaluate(()=>(window as any).__account("bob"));
 await expect(page.getByText("No support sessions found.")).toBeVisible();
 const completed=page.waitForResponse(response=>response.url().includes("/fixture/alice/attended-sessions?"));
 release();await (await completed).finished();
 await page.evaluate(()=>new Promise<void>(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve()))));
 await expect(page.getByRole("button",{name:/Old account private session/})).toHaveCount(0);
 await expect(page.getByTestId("attended-state")).toHaveCount(0);
});

test("listing failure offers a working retry",async({page,context})=>{
 await routes(context,[record("shared")]);let fail=true;
 await context.route("**/fixture/alice/attended-sessions?**",async route=>{
  if(fail){fail=false;return route.fulfill({status:503,json:{error:"unavailable"}})}
  return route.fallback();
 });
 await page.goto(url);await expect(page.getByText("Could not load support sessions. Try Refresh.")).toBeVisible();
 await page.getByRole("button",{name:"Refresh",exact:true}).click();
 await page.getByRole("button",{name:/Printer support/}).click();
 await expect(page.getByTestId("attended-state")).toHaveText("consented");
 await page.screenshot({path:test.info().outputPath("shared-support.png"),fullPage:true});
});


for(const code of ["7K3M9R2T","0123456789ABC"]){
 test(`join page accepts and launches ${code.length}-character codes`,async({page})=>{
  await page.goto(url+"?join#"+code);
  await expect(page.getByTestId("join-code")).toHaveAttribute("data-code",code);
  await expect(page.getByRole("link",{name:"Open the DeskRally support client",exact:true})).toHaveAttribute("href",new RegExp("code="+code));
  await page.getByLabel("Session code",{exact:true}).fill("7k3m-9r2t");
  await page.getByRole("button",{name:"Continue",exact:true}).click();
  await expect(page.getByTestId("join-code")).toHaveText("7K3M-9R2T");
  await expect(page).toHaveURL(/\/join#7K3M9R2T$/);
 });
}
