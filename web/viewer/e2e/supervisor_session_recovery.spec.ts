import {test,expect,type Page} from "@playwright/test";
import { clickInViewerPanel, openAccountControls } from "./nav";
import { openManualConnect } from "./manual_connect";
async function fixture(page:Page, withPolicy=false) {
 await page.clock.install();
 const state={starts:0,policy:200,mints:[] as string[],mintStatus:200,ends:[] as string[],closeSignaling:false};
 await page.route(/.*/,route=>new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
 await page.route("**/cp/**",async route=> {
  const path=new URL(route.request().url()).pathname;
  if(path === "/cp/auth/session") return route.fulfill({status:204});
  if(path === "/cp/machines") return route.fulfill({json:{machines:[],presence_known:true}});
  if(path === "/cp/sessions") {
    // GET /cp/sessions is the live-session badge listing — return empty, do NOT count as a start.
    if(route.request().method() !== "POST") return route.fulfill({json:{sessions:[]}});
    state.starts++;return route.fulfill({json:{session:{id:`session-${state.starts}`},...(withPolicy ? {session_policy:{access:"view_only",signed:"signed-policy"}} : {}),signaling:{url:"ws://127.0.0.1:5188/ws",ticket:{}}}});
  }
  if(path === "/cp/grant/mint") {
    state.mints.push(JSON.parse(route.request().postData() ?? "{}").session_id);
    return state.mintStatus === 200 ? route.fulfill({body:JSON.stringify({claims:{grant:{capabilities:[]}},sig:"s"+state.mints.length})}) : route.fulfill({status:state.mintStatus,json:{error:"denied"}});
  }
  if(path.endsWith("/policy")) return route.fulfill({status:state.policy,json:state.policy === 200 ? {session_policy:{access:"control",signed:"test",lease_ttl_ms:30000,expires_at_ms:9999999999999}} : {error:"administrator ended session"}});
  if(path.endsWith("/end")) state.ends.push(path.split("/")[3]);
 return route.fulfill({json:{session:{id:"ended"}}});
 });
 // closeSignaling: later signaling connections drop at once, so a retry mints a record that never connects.
 await page.routeWebSocket("ws://127.0.0.1:5188/ws",ws=>{if(state.closeSignaling) ws.close();});
 await page.addInitScript(()=> {
  const w=window as any;w.peers=[];
  class Peer {
   connectionState="new";onconnectionstatechange:any;ontrack:any;onicecandidate:any;frames=1;
   dc:any={readyState:"open",sent:[] as ArrayBuffer[],send(bytes:ArrayBuffer){this.sent.push(bytes);},close(){this.readyState="closed";this.onclose?.();}};
   constructor(){w.peers.push(this);}
   createDataChannel(){return this.dc;} addTransceiver(){} close(){this.connectionState="closed";this.onconnectionstatechange?.();}
   getStats(){return Promise.resolve(new Map([["video",{type:"inbound-rtp",kind:"video",framesDecoded:this.frames}]]));}
   connected(){this.connectionState="connected";this.onconnectionstatechange?.();}
   fail(){this.connectionState="failed";this.onconnectionstatechange?.();}
   control(message:unknown){const bytes=new TextEncoder().encode(JSON.stringify(message));const frame=new Uint8Array(5+bytes.length);new DataView(frame.buffer).setUint32(1,bytes.length);frame.set(bytes,5);this.dc.onmessage?.({data:frame.buffer});}
  }
  w.RTCPeerConnection=Peer;
 });
 await page.goto(test.info().project.use.baseURL!);
 await openManualConnect(page);
 await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
 await page.getByTestId("manual-connect").click();
 await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(1);
 await page.evaluate(()=>(window as any).peers[0].connected());
 return state;
}
test("silent frozen video shows recovery and obtains a fresh session after authorization check",async({page})=> {
 const state=await fixture(page);
 await page.clock.runFor(24000);
 await expect(page.getByTestId("viewer-recovery")).toContainText("Reconnecting");
 await page.clock.runFor(2000);
 await expect.poll(()=>state.starts).toBe(2);
 await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(2);
 await page.evaluate(()=>(window as any).peers[1].connected());
 await expect(page.getByTestId("viewer-recovery")).toHaveCount(0);
 // A queued callback from the abandoned connection cannot ruin the recovered one.
 await page.evaluate(()=>(window as any).peers[0].fail());
 await expect(page.getByTestId("viewer-recovery")).toHaveCount(0);
});
test("guest-ended session is never automatically replaced",async({page})=> {
 const state=await fixture(page);
 await page.evaluate(()=>(window as any).peers[0].control({t:"SessionEndedByGuest"}));
 await page.evaluate(()=>(window as any).peers[0].fail());
 await page.clock.runFor(120000);expect(state.starts).toBe(1);
 await expect(page.getByTestId("viewer-recovery")).toContainText("guest ended");
});
test("guest end processed AFTER the transport failure still cancels the scheduled recovery",async({page})=> {
 const state=await fixture(page);
 await page.evaluate(()=>(window as any).peers[0].fail());
 await expect(page.getByTestId("viewer-recovery")).toContainText("Reconnecting");
 await page.evaluate(()=>(window as any).peers[0].control({t:"SessionEndedByGuest"}));
 await page.clock.runFor(120000);expect(state.starts).toBe(1);
 await expect(page.getByTestId("viewer-recovery")).toContainText("guest ended");
});
test("guest end while the recovery authorization check is in flight discards its late approval",async({page})=> {
 const state=await fixture(page);
 let release!:()=>void;
 const gate=new Promise<void>(r=>release=r);
 let renewing=false;
 await page.route("**/cp/sessions/*/policy",async route=> {
  renewing=true;await gate;
  await route.fulfill({json:{session_policy:{access:"control",signed:"test",lease_ttl_ms:30000,expires_at_ms:9999999999999}}});
 });
 await page.evaluate(()=>(window as any).peers[0].fail());await page.clock.runFor(2000);
 await expect.poll(()=>renewing).toBe(true);
 await page.evaluate(()=>(window as any).peers[0].control({t:"SessionEndedByGuest"}));
 release();await page.clock.runFor(120000);expect(state.starts).toBe(1);
 expect(await page.evaluate(()=>(window as any).peers.length)).toBe(1);
 await expect(page.getByTestId("viewer-recovery")).toContainText("guest ended");
});
test("revoked original session is explained and never automatically replaced",async({page})=> {
 const state=await fixture(page);state.policy=409;
 await page.evaluate(()=>(window as any).peers[0].fail());
 await page.clock.runFor(2000);
 await expect(page.getByTestId("viewer-recovery")).toContainText("administrator ended session");
 await page.clock.runFor(120000);expect(state.starts).toBe(1);
 await expect(page.getByTestId("viewer-reconnect")).toBeVisible();
});
test("Disconnect cancels pending automatic recovery",async({page})=> {
 const state=await fixture(page);
 await page.evaluate(()=>(window as any).peers[0].fail());
 await page.getByRole("button",{name:"Disconnect",exact:true}).click();
 await page.clock.runFor(120000);expect(state.starts).toBe(1);
 await expect(page.getByTestId("viewer-recovery")).toHaveCount(0);
});
test("agent lease-ended message exposes the stale picture even while WebRTC stays connected",async({page})=> {
 await fixture(page);
 const renewed=page.waitForResponse("**/cp/sessions/*/policy");
 await page.evaluate(()=>(window as any).peers[0].control({t:"SessionLeaseRequired",c:{renew_within_ms:30000}}));
 await renewed;
 await expect.poll(()=>page.evaluate(()=>(window as any).peers[0].dc.sent.some((bytes:ArrayBuffer)=>JSON.parse(new TextDecoder().decode(new Uint8Array(bytes).slice(5))).t === "InstallSessionPolicy"))).toBe(true);
 expect(await page.evaluate(()=>(window as any).peers.length)).toBe(1);
 // No SessionPolicyInstalled acknowledgement: policyPending is still true.
 await page.evaluate(()=>(window as any).peers[0].control({t:"Error",c:{message:"session ended: the control-plane session lease expired and was not renewed"}}));
 await expect(page.getByTestId("viewer-recovery")).toContainText("Reconnecting");
});

// 10-28: a sleeping laptop's monitors re-enumerated as they woke and the agent ended the session six
// seconds in. Recovery then re-checked the ORIGINAL session, got 409 and refused ("session has ended"),
// so the technician had to press Reconnect. A display-layout end now starts a FRESH session itself
// (full authorization, never a revival), at most three times in ten minutes.
const LAYOUT_END="session ended: the display layout on this machine changed (a monitor was connected, disconnected or woke up, or the resolution changed); reconnect to continue";
test("a display-layout end starts a fresh session automatically even though the original has ended",async({page})=> {
 const state=await fixture(page);state.policy=409;
 await page.evaluate(m=>(window as any).peers[0].control({t:"Error",c:{message:m}}),LAYOUT_END);
 await expect(page.getByText("reconnecting automatically", {exact:false})).toBeVisible();
 await page.clock.runFor(1600);
 await expect.poll(()=>state.starts).toBe(2);
 // The FRESH session is authorized; only the original was ended.
 state.policy=200;
 await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(2);
 await page.evaluate(()=>(window as any).peers[1].connected());
 // Inside the 20 s stall window: this fixture's frame counter never advances, so a longer wait would
 // measure the stall detector's (correct) reconnects, not this one.
 await page.clock.runFor(10000);
 expect(state.starts).toBe(2);
 await expect(page.getByText("administrator ended session")).toHaveCount(0);
 await expect(page.getByTestId("viewer-reconnect")).toHaveCount(0);
});
test("only the display-layout end reconnects by itself: a lease end with a 409 still waits for the technician",async({page})=> {
 const state=await fixture(page);state.policy=409;
 await page.evaluate(()=>(window as any).peers[0].control({t:"Error",c:{message:"session ended: the control-plane session lease expired and was not renewed"}}));
 await page.clock.runFor(120000);
 expect(state.starts).toBe(1);
 await expect(page.getByTestId("viewer-reconnect")).toBeVisible();
});
test("display-layout reconnects stop after three in ten minutes",async({page})=> {
 const state=await fixture(page);state.policy=409;
 for(let i=0;i<3;i++) {
  await page.evaluate(([n,m])=>(window as any).peers[n].control({t:"Error",c:{message:m}}),[i,LAYOUT_END] as const);
  await page.clock.runFor(1600);
  await expect.poll(()=>state.starts).toBe(i+2);
  await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(i+2);
  await page.evaluate(n=>(window as any).peers[n].connected(),i+1);
 }
 await page.evaluate(m=>(window as any).peers[3].control({t:"Error",c:{message:m}}),LAYOUT_END);
 await page.clock.runFor(120000);
 expect(state.starts).toBe(4);
 await expect(page.getByTestId("viewer-reconnect")).toBeVisible();
});

test("popped-out viewer shows the same recovery state and reconnect action",async({page,context})=> {
 await fixture(page);
 const popupPromise=context.waitForEvent("page");
 await clickInViewerPanel(page, "view", page.getByTestId("viewer-popout"));
 const popup=await popupPromise;await popup.waitForLoadState("domcontentloaded");
 await page.evaluate(()=>(window as any).peers[0].fail());
 await expect(popup.getByTestId("viewer-recovery")).toContainText("Reconnecting");
 await expect(popup.getByTestId("viewer-reconnect")).toBeVisible();
 await popup.close();
 await expect(page.getByTestId("viewer-recovery")).toBeVisible();
});
test("sign-out cancels backoff and leaves no automatic fresh session",async({page})=> {
 const state=await fixture(page);
 await page.evaluate(()=>(window as any).peers[0].fail());
 await openAccountControls(page);
 await page.getByTestId("app-signout").click();
 await page.clock.runFor(120000);
 await expect(page.getByTestId("app-login-gate")).toBeVisible();
 expect(state.starts).toBe(1);
});
test("unchanging desktop pixels do not time out while decoded frames progress",async({page})=> {
 const state=await fixture(page);
 for(let i=0;i<12;i++) {
  await page.evaluate(()=>(window as any).peers[0].frames++);
  await page.clock.runFor(3000);
 }
 expect(state.starts).toBe(1);await expect(page.getByTestId("viewer-recovery")).toHaveCount(0);
});

test("Disconnect while recovery authorization is pending ignores its late approval",async({page})=> {
 const state=await fixture(page);
 let release!:()=>void;
 const gate=new Promise<void>(r=>release=r);
 let renewing=false;
 await page.route("**/cp/sessions/*/policy",async route=> {
  renewing=true;await gate;
  await route.fulfill({json:{session_policy:{access:"control",signed:"test",lease_ttl_ms:30000,expires_at_ms:9999999999999}}});
 });
 await page.evaluate(()=>(window as any).peers[0].fail());await page.clock.runFor(2000);
 await expect.poll(()=>renewing).toBe(true);
 await page.getByRole("button",{name:"Disconnect",exact:true}).click();
 release();await page.clock.runFor(120000);expect(state.starts).toBe(1);
});
test("denied replacement session stops recovery without direct-connect fallback",async({page})=> {
 await fixture(page);let attempts=0;
 await page.route("**/cp/sessions",async route=> {attempts++;await route.fulfill({status:403,json:{error:"access revoked"}});});
 await page.evaluate(()=>(window as any).peers[0].fail());await page.clock.runFor(2000);
 await expect(page.getByTestId("viewer-recovery")).toContainText("Reconnect refused");
 await page.clock.runFor(120000);expect(attempts).toBe(1);
 expect(await page.evaluate(()=>(window as any).peers.length)).toBe(1);
});

test("natural ICE recovery cancels an authorization check already in flight",async({page})=> {
 const state=await fixture(page);let release!:()=>void;const gate=new Promise<void>(r=>release=r);let renewing=false;
 await page.route("**/cp/sessions/*/policy",async route=> {
  renewing=true;await gate;await route.fulfill({json:{session_policy:{access:"control",signed:"test",lease_ttl_ms:30000,expires_at_ms:9999999999999}}});
 });
 await page.evaluate(()=> {const p=(window as any).peers[0];p.connectionState="disconnected";p.onconnectionstatechange();});
 await page.clock.runFor(2000);await expect.poll(()=>renewing).toBe(true);
 await page.evaluate(()=>(window as any).peers[0].connected());
 release();await page.clock.runFor(5000);
 expect(state.starts).toBe(1);await expect(page.getByTestId("viewer-recovery")).toHaveCount(0);
});

test("brokered access policy is installed after the data channel exists",async({page})=> {
 await fixture(page,true);
 const messages=await page.evaluate(()=>(window as any).peers[0].dc.sent.map((bytes:ArrayBuffer)=>JSON.parse(new TextDecoder().decode(new Uint8Array(bytes).slice(5)))));
 expect(messages).toContainEqual({t:"InstallSessionPolicy",c:{signed_policy:"signed-policy"}});
 await page.evaluate(()=>(window as any).peers[0].fail());await page.clock.runFor(2000);
 await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(2);
 const retried=await page.evaluate(()=>(window as any).peers[1].dc.sent.map((bytes:ArrayBuffer)=>JSON.parse(new TextDecoder().decode(new Uint8Array(bytes).slice(5)))));
 expect(retried).toContainEqual({t:"InstallSessionPolicy",c:{signed_policy:"signed-policy"}});
});

// Production, 2026-10-21: the guest pressed End on a LEASED session; the lease renewal got 409 "session
// has ended" and the viewer released the record, then started a FRESH session ~10 s later. The tests
// above never ran the lease renewer, so its refusal path (onRefused) was never combined with a guest End.
for (const order of ["guest-message-first", "renewal-409-first", "no-guest-message"] as const) {
 test(`leased session: guest End is never automatically replaced (${order})`,async({page})=> {
  const state=await fixture(page);
  const renewed=page.waitForResponse("**/cp/sessions/*/policy");
  await page.evaluate(()=>(window as any).peers[0].control({t:"SessionLeaseRequired",c:{renew_within_ms:30000}}));
  await renewed;
  state.policy=409;
  if(order === "guest-message-first") await page.evaluate(()=>(window as any).peers[0].control({t:"SessionEndedByGuest"}));
  await page.evaluate(()=> {const p=(window as any).peers[0];p.connectionState="disconnected";p.onconnectionstatechange();});
  await page.clock.runFor(15000); // the next renewal lands and is refused
  if(order === "renewal-409-first") await page.evaluate(()=>(window as any).peers[0].control({t:"SessionEndedByGuest"}));
  await page.evaluate(()=>(window as any).peers[0].fail());
  await page.clock.runFor(180000);
  expect(state.starts).toBe(1);
  expect(await page.evaluate(()=>(window as any).peers.length)).toBe(1);
 });
}

const installedGrants=(page:Page,peer:number)=>page.evaluate((i)=>{
 const out:string[]=[];
 for(const b of (window as any).peers[i].dc.sent){const u=new Uint8Array(b);const t=new TextDecoder().decode(u.slice(5));try{const m=JSON.parse(t);if(m.t==="InstallGrant")out.push(m.c.signed_grant);}catch{}}
 return out;
},peer);
test("a recovered session re-mints its backstage grant for the NEW session id, with no user action",async({page})=> {
 const state=await fixture(page);
 await page.evaluate(()=>(window as any).peers[0].control({t:"GrantInstalled"}));
 await page.clock.runFor(24000);
 await page.clock.runFor(2000);
 await expect.poll(()=>state.starts).toBe(2);
 await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(2);
 await expect.poll(()=>state.mints).toEqual(["session-2"]);
 await expect.poll(()=>installedGrants(page,1).then(g=>g.length)).toBe(1);
});
test("a recovered session that never had a grant mints nothing",async({page})=> {
 const state=await fixture(page);
 await page.clock.runFor(24000);
 await page.clock.runFor(2000);
 await expect.poll(()=>state.starts).toBe(2);
 await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(2);
 await page.waitForTimeout(200);
 expect(state.mints).toEqual([]);
 expect(await installedGrants(page,1)).toEqual([]);
});
test("a 403 on the resume mint is not retried and installs nothing",async({page})=> {
 const state=await fixture(page);
 state.mintStatus=403;
 await page.evaluate(()=>(window as any).peers[0].control({t:"GrantInstalled"}));
 await page.clock.runFor(24000);
 await page.clock.runFor(2000);
 await expect.poll(()=>state.mints.length).toBe(1);
 await page.clock.runFor(60000);
 expect(state.mints.length).toBe(1);
 expect(await installedGrants(page,1)).toEqual([]);
});

// Production 2026-11-09, session 4c1f4541: the last retry of a failing recovery minted a record that never connected,
// recovery then gave up, and nothing ended the record until a teardown two hours later, whose /end got a 401 (the
// sign-in had lapsed). A live row leaked. When recovery stops for good, every record it created is ended at once.
test("when automatic recovery gives up, no session record it created is left open",async({page})=> {
 const state=await fixture(page);
 state.closeSignaling=true;
 await page.evaluate(()=>(window as any).peers[0].fail());
 for(let i=0;i<12;i++) await page.clock.runFor(20000);
 await expect(page.getByTestId("viewer-recovery")).toContainText("Automatic reconnect stopped");
 expect(state.starts).toBeGreaterThan(1); // the retries really did mint new records
 const started=Array.from({length:state.starts},(_,i)=>`session-${i+1}`);
 await expect.poll(()=>started.filter(id=>!state.ends.includes(id))).toEqual([]);
});
