import React from "react";
import { createRoot } from "react-dom/client";
import { JoinPage } from "../src/components/JoinPage";
import { AttendedPanel } from "../src/components/AttendedPanel";
import { ConsoleApiClient } from "../src/lib/console_api";
import "../src/index.css";
const root=createRoot(document.getElementById("root")!);
function render(account:string){
 const api=new ConsoleApiClient({baseUrl:`/fixture/${account}`});
 root.render(<AttendedPanel api={api} onConnect={value=>{(window as any).__connected=value;}}/>);
}
(window as any).__account=render;
if(new URLSearchParams(location.search).has("join")) root.render(<JoinPage code={location.hash.slice(1)} />);
else render(new URLSearchParams(location.search).get("account")??"alice");
