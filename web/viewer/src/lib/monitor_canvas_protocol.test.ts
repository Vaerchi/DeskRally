import { describe, it, expect } from "vitest";
import { encodeControl, decodeControl, ControlClient } from "./control";
const canvas = {width:3200,height:2104,monitors:[
  {id:0,x:1280,y:1024,width:1920,height:1080},
  {id:1,x:0,y:0,width:1280,height:1024},
]};
const decode = (c: unknown) => decodeControl(new TextEncoder().encode(JSON.stringify({t:"MonitorCanvas",c})));
describe("fixed monitor canvas wire capability",()=>{
  it("round-trips exact geometry",()=>{
    const msg = {t:"MonitorCanvas" as const,c:canvas};
    expect(decodeControl(encodeControl(msg))).toEqual(msg);
  });
  it("dispatches canvas before list without issuing a selection",()=>{
    const received:unknown[]=[];const sent:unknown[]=[];
    const client=new ControlClient(bytes=>sent.push(bytes),{
      onMonitorCanvas:c=>received.push(c),onMonitors:m=>received.push(m)});
    client.handleMessage(encodeControl({t:"MonitorCanvas",c:canvas}));
    client.handleMessage(encodeControl({t:"MonitorList",c:{monitors:[]}}));
    expect(received).toEqual([canvas,[]]);expect(sent).toEqual([]);
  });
  it.each([
    {...canvas,width:0}, {...canvas,height:Infinity}, {...canvas,width:16384},
    {...canvas,monitors:[]}, {...canvas,monitors:[canvas.monitors[0],canvas.monitors[0]]},
    {...canvas,monitors:[{...canvas.monitors[0],x:-1}]},
    {...canvas,monitors:[{...canvas.monitors[0],x:1281}]},
    {...canvas,monitors:[{...canvas.monitors[0],id:4294967295}]},
    {...canvas,monitors:[{...canvas.monitors[0],height:0}]},
    {...canvas,monitors:[{...canvas.monitors[0],y:0.5}]},
  ])("rejects invalid canvas geometry %j",c=>expect(()=>decode(c)).toThrow());
});
