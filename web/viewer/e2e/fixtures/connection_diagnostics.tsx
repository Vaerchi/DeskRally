import React from 'react';
import {createRoot} from 'react-dom/client';
import {ConnectionDiagnostics} from '../../src/components/ConnectionDiagnostics';
let calls=0, generation=0;
const pending: Array<{resolve:(value:RTCStatsReport)=>void,reject:()=>void}>=[];
const getStats=()=>{calls++;return new Promise<RTCStatsReport>((resolve,reject)=>pending.push({resolve,reject}));};
const root=createRoot(document.getElementById('root')!);
function render(){root.render(<ConnectionDiagnostics key={generation} sessionKey={String(generation)} getStats={getStats} stream={null} connectionState="connected"/>);}
(window as any).diag={
 calls:()=>calls,
 resolve:(packets:number)=>pending.shift()!.resolve(new Map([['video',{type:'inbound-rtp',kind:'video',packetsReceived:packets}]]) as unknown as RTCStatsReport),
 reject:()=>pending.shift()!.reject(),
 next:()=>{generation++;render();},
};
render();
