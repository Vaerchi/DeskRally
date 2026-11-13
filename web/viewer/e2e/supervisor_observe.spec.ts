import {test,expect,type Page} from "@playwright/test";
import { clickAccessAction, openAccessActions } from "./machine_actions";

const DEVICE="00112233-4455-6677-8899-aabbccddeeff";
const WS="ws://127.0.0.1:5188/ws";
async function fixture(page:Page, options:{legacy?:boolean; conflict?:boolean; path?:string}={}) {
 await page.clock.install();
 const starts:Array<Record<string,unknown>>=[];
 let socket:{send:(message:string)=>void}|null=null;
 let closed=false;
 let brokered=false;
 const sentTypes:string[]=[];
 await page.route(/.*/,route=>new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
 await page.route("**/cp/**",async route=> {
  const path=new URL(route.request().url()).pathname;
  if(path === "/cp/auth/session") return route.fulfill({status:204});
  if(path === "/cp/machines") return route.fulfill({json:{machines:[{id:"machine",device_id:DEVICE,name:"Machine",group_id:"group",os:"windows",online:true,multi_session_capable:true}],presence_known:true}});
  if(path === "/cp/sessions") {
   if(route.request().method() !== "POST") return route.fulfill({json:{sessions:[]}});
   const body=route.request().postDataJSON();starts.push(body);
   if(options.conflict) return route.fulfill({status:409,json:{error:"agent too old"}});
   return route.fulfill({json:{session:{id:`session-${starts.length}`},...(body.access ? {session_policy:{access:"view_only",signed:"signed-policy"}} : {}),signaling:{url:WS,ticket:{}}}});
  }
  return route.fulfill({json:{session:{id:"ended"}}});
 });
 await page.routeWebSocket(WS,ws=> {
  socket=ws;
  ws.onClose(()=>{closed=true;});
  ws.onMessage(message=> {
   const msg=JSON.parse(String(message));
   sentTypes.push(msg.type);
   if(msg.type === "register_agent") ws.send(JSON.stringify({type:"registered",server_pubkey:"ed25519:mock"}));
   if(msg.type === "connect_request") {
    brokered=true;
    ws.send(JSON.stringify({type:"brokered",session:"own-signaling-session",peer_device:DEVICE,peer_pubkey:"ed25519:agent-mock",...(options.legacy ? {} : {access:"view_only",access_version:1})}));
   }
  });
 });
 await page.addInitScript(()=> {
  const w=window as any;w.peers=[];
  class Peer {
   connectionState="new";onconnectionstatechange:any;ontrack:any;onicecandidate:any;frames=1;
   dc:any={readyState:"open",sent:[] as ArrayBuffer[],send(bytes:ArrayBuffer){this.sent.push(bytes);},close(){this.readyState="closed";this.onclose?.();}};
   constructor(){w.peers.push(this);}
   createDataChannel(){return this.dc;} addTransceiver(){}
   createOffer(){return Promise.resolve({type:"offer",sdp:"v=0 mock-offer"});} setLocalDescription(){return Promise.resolve();} close(){this.connectionState="closed";this.onconnectionstatechange?.();}
   getStats(){return Promise.resolve(new Map([["video",{type:"inbound-rtp",kind:"video",framesDecoded:this.frames}]]));}
   connected(){this.connectionState="connected";this.onconnectionstatechange?.();}
   fail(){this.connectionState="failed";this.onconnectionstatechange?.();}
   control(message:unknown){const bytes=new TextEncoder().encode(JSON.stringify(message));const frame=new Uint8Array(5+bytes.length);new DataView(frame.buffer).setUint32(1,bytes.length);frame.set(bytes,5);this.dc.onmessage?.({data:frame.buffer});}
  }
  w.RTCPeerConnection=Peer;
 });
 await page.goto(new URL(options.path ?? "/", test.info().project.use.baseURL ?? "http://127.0.0.1:5173").toString());
 if(!options.path){await openAccessActions(page,DEVICE);await expect(page.getByTestId(`observe-${DEVICE}`)).toBeVisible();}
 return {starts,sentTypes,brokered:()=>brokered,closed:()=>closed,send:(message:unknown)=>socket!.send(JSON.stringify(message))};
}
async function observe(page:Page) {
 await clickAccessAction(page,DEVICE,`observe-${DEVICE}`);
}
async function connected(page:Page) {
 await expect.poll(()=>page.evaluate(()=>(window as any).peers.length)).toBe(1);
 await page.evaluate(()=>(window as any).peers[0].connected());
}

test("Observe adds access while Connect preserves its request shape",async({page})=> {
 const state=await fixture(page);
 await observe(page);
 await expect.poll(()=>state.starts.length).toBe(1);
 expect(state.starts[0]).toEqual({machine_id:DEVICE,access:"view_only"});
 await connected(page);
 await page.getByRole("button",{name:"Disconnect",exact:true}).click();
 await page.getByTestId(`connect-${DEVICE}`).click();
 await expect.poll(()=>state.starts.length).toBe(2);
 expect(state.starts[1]).toEqual({machine_id:DEVICE});
});

// The actuating controls live inside the Tools and Input menus, so each menu is OPENED before
// asserting; a closed menu would make "absent" pass trivially. The controlling-session twin below is
// the negative control: the same steps must find every control present.
// viewer-power is the box around the power controls: an observer must not see it even empty.
// viewer-record is in the Tools panel since menu redesign wave 7b (it was under "More").
const ACTUATING = ["viewer-lock","viewer-command-toggle","viewer-power","viewer-record","viewer-block-input"];
async function actuatingCounts(page:Page) {
 const counts:Record<string,number>={};
 await page.getByTestId("viewer-tools-menu").click();
 for(const id of ["viewer-lock","viewer-command-toggle","viewer-power","viewer-record"]) counts[id]=await page.getByTestId(id).count();
 await page.keyboard.press("Escape");
 await page.getByTestId("viewer-input-menu").click();
 counts["viewer-block-input"]=await page.getByTestId("viewer-block-input").count();
 await page.keyboard.press("Escape");
 return counts;
}

test("authorized Observe shows its badge and hides actuating controls",async({page})=> {
 const state=await fixture(page);
 await observe(page);
 await expect.poll(state.brokered).toBe(true);
 await connected(page);
 await expect(page.getByTestId("observing-badge")).toHaveText("Observing · view only");
 // Positive control for the legacy test's "no sdp": an accepted observe DOES negotiate.
 await expect.poll(()=>state.sentTypes.includes("sdp")).toBe(true);
 const counts=await actuatingCounts(page);
 for(const id of ACTUATING) expect(counts[id], id).toBe(0);
});

test("a controlling session through the same steps shows every actuating control",async({page})=> {
 const state=await fixture(page);
 await page.getByTestId(`connect-${DEVICE}`).click();
 await expect.poll(state.brokered).toBe(true);
 await connected(page);
 await expect(page.getByTestId("observing-badge")).toHaveCount(0);
 const counts=await actuatingCounts(page);
 for(const id of ACTUATING) expect(counts[id], id).toBeGreaterThan(0);
});

test("legacy brokered response disconnects without showing a session",async({page})=> {
 const state=await fixture(page,{legacy:true});
 await observe(page);
 await expect(page.getByTestId("app-error").locator("span")).toHaveText("This server cannot observe yet; nothing was shown");
 await expect.poll(state.closed).toBe(true);
 await expect(page.getByTestId("viewer-machine-label")).toHaveCount(0);
 await expect(page.getByTestId("observing-badge")).toHaveCount(0);
 // Refused BEFORE negotiation: the console never sent an SDP offer to a server that would broker control.
 expect(state.sentTypes).not.toContain("sdp");
});

test("Observe displays the server conflict reason",async({page})=> {
 const state=await fixture(page,{conflict:true});
 await observe(page);
 await expect(page.getByTestId("app-error")).toContainText("agent too old");
 expect(state.brokered()).toBe(false);
});

test("participants count observers among peers",async({page})=> {
 const state=await fixture(page);
 await observe(page);
 await expect.poll(state.brokered).toBe(true);
 await connected(page);
 state.send({type:"session_participants",device_id:DEVICE,participants:[
  {session_id:"own-signaling-session",access:"view_only"},
  {session_id:"peer-observer",access:"view_only"},
  {session_id:"peer-controller",access:"control"},
 ]});
 await expect(page.getByTestId("session-participants")).toContainText("2 co-techs · 1 observing");
});

// docs/01 §7 "invite a participant": the invite is a console link. A watch link must open VIEW-ONLY
// (the request carries access:"view_only"); the control link is the negative control and must not.
test("a watch invite link opens the machine view-only",async({page})=> {
 const state=await fixture(page,{path:`/console?device=${DEVICE}&observe=1`});
 await expect.poll(()=>state.starts.length).toBe(1);
 expect(state.starts[0]).toEqual({machine_id:DEVICE,access:"view_only"});
 await connected(page);
 await expect(page.getByTestId("observing-badge")).toBeVisible();
});

test("a control invite link opens an ordinary session",async({page})=> {
 const state=await fixture(page,{path:`/console?device=${DEVICE}`});
 await expect.poll(()=>state.starts.length).toBe(1);
 expect(state.starts[0]).toEqual({machine_id:DEVICE});
});

test("the session menu copies a watch invite for this machine",async({page})=> {
 await page.addInitScript(()=> {
  (window as any).copied=[];
  Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText:(t:string)=>{(window as any).copied.push(t);return Promise.resolve();},readText:()=>Promise.resolve("")}});
 });
 const state=await fixture(page);
 await page.getByTestId(`connect-${DEVICE}`).click();
 await expect.poll(()=>state.starts.length).toBe(1);
 await connected(page);
 await page.getByRole("button", { name: "Session", exact: true }).click();
 await page.getByTestId("session-invite-watch").click();
 await expect(page.getByTestId("session-invite-copied")).toBeVisible();
 const copied:string[]=await page.evaluate(()=>(window as any).copied);
 const url=new URL(copied[copied.length-1]);
 expect(url.pathname).toBe("/console");
 expect(url.searchParams.get("device")).toBe(DEVICE);
 expect(url.searchParams.get("observe")).toBe("1");
});
