import { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { SessionViewer } from "../src/components/SessionViewer";
import { ChannelId, type Transport } from "../src/lib";
import { ClipboardClient, encodeMessage } from "../src/lib/clipboard";
import { ClipboardControl } from "../src/components/ClipboardControl";
import "../src/index.css";
const w = window as any;
w.inputs=[]; w.selections=[]; w.disconnects=0;
const transport: Transport = {kind:"webrtc",state:"connected",send(channel,payload){if(channel===ChannelId.Input)w.inputs.push(JSON.parse(new TextDecoder().decode(payload)));},sendFrame(){},async connect(){},close(){w.disconnects++;}};
const monitors=[{id:0,label:"Left",width:640,height:360,primary:true},{id:1,label:"Right",width:640,height:360}];
const canvasLayout={width:1280,height:360,monitors:[{id:0,x:0,y:0,width:640,height:360},{id:1,x:640,y:0,width:640,height:360}]};
let clipTime=0;
const clip=new ClipboardClient(()=>{}, {readText:async()=>"test clipboard",writeText:async()=>{}}, {now:()=>clipTime+=500});
w.clipInput=(text:string)=>clip.handleMessage(encodeMessage({t:"Text",c:text}));
function Harness(){
 const [stream,setStream]=useState<MediaStream|null>(null);const [live,setLive]=useState(true);const [layout,setLayout]=useState<typeof canvasLayout|undefined>(canvasLayout);
 useEffect(()=>{const c=document.createElement("canvas");c.width=1280;c.height=360;const ctx=c.getContext("2d")!;
 const draw=()=>{ctx.fillStyle="red";ctx.fillRect(0,0,640,360);ctx.fillStyle="blue";ctx.fillRect(640,0,640,360);};draw();const timer=setInterval(draw,50);const s=c.captureStream(20);setStream(s);
 w.removeMonitor=()=>setLayout({...canvasLayout,monitors:[canvasLayout.monitors[0]]});w.disableCanvas=()=>setLayout(undefined);w.end=()=>setLive(false);
 return()=>{clearInterval(timer);s.getTracks().forEach(t=>t.stop());};},[]);
 return <div className="app"><div className="app__body"><main className="app__main"><section className="app__session">{live&&<SessionViewer transport={transport} stream={stream} connectionState="connected" machineName="Test" monitors={monitors} monitorCanvas={layout} popoutControls={<ClipboardControl client={clip}/>} onSelectMonitor={id=>w.selections.push(id)} onDisconnect={()=>{w.disconnects++;setLive(false);}}/>}</section></main></div></div>;
}
createRoot(document.getElementById("root")!).render(<Harness/>);
