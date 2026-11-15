import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Viewer } from "../src/components/Viewer";
import type { Transport } from "../src/lib";
import "../src/index.css";
const canvas = {width:400,height:300,monitors:[
  {id:0,x:200,y:100,width:200,height:200}, {id:1,x:0,y:0,width:200,height:300}]};
const monitors = [{id:0,label:"Primary",width:200,height:200,primary:true},
  {id:1,label:"Left",width:200,height:300,primary:false}];
const logs: unknown[][] = [[],[]];
const selections: number[][]=[[],[]];
Object.assign(window,{__logs:logs,__selections:selections});
const transports = [0,1].map(i=>({kind:"webrtc",state:"connected",
  send(_channel,payload){ logs[i].push(JSON.parse(new TextDecoder().decode(payload))); },
  sendFrame(){},connect:async()=>{},close(){}} as Transport));
function App(){
  const [stream,setStream]=useState<MediaStream|null>(null);
  useEffect(()=>{
    const c=document.createElement("canvas");c.width=400;c.height=300;
    const ctx=c.getContext("2d")!;
    const draw=()=>{ctx.fillStyle="black";ctx.fillRect(0,0,400,300);
      ctx.fillStyle="blue";ctx.fillRect(0,0,200,300);
      ctx.fillStyle="red";ctx.fillRect(200,100,200,200);};
    draw();const media=c.captureStream(20);setStream(media);
    const interval=setInterval(draw,50);return()=>{clearInterval(interval);media.getTracks().forEach(t=>t.stop());};
  },[]);
  const two=new URLSearchParams(location.search).has("two");
  const legacy=new URLSearchParams(location.search).has("legacy");
  return <>{(two?[0,1]:[0]).map(i=><div className="session" data-testid={`session-${i}`} key={i}>
    <Viewer machineName={`Test ${i}`} stream={stream} transport={transports[i]} connectionState="connected"
      monitors={monitors} monitorCanvas={legacy?undefined:canvas} pinnedMonitorId={legacy?0:4294967295}
      onSelectMonitor={id=>selections[i].push(id)} /></div>)}</>;
}
createRoot(document.getElementById("root")!).render(<App/>);
