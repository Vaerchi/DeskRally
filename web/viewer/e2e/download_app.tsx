// Real App, file-transfer client, and DOM save flow. Only network transport is synthetic.
// This fixture never constructs RTC or signaling sockets and receives only test byte arrays.
import { createRoot } from "react-dom/client";
import App from "../src/App";
import { SignalingClient, WebRTCTransport } from "../src/lib/transport";
import { ChannelId } from "../src/lib/protocol";
import { decodeMessage, encodeMessage, sha256Hex } from "../src/lib/file_transfer";
import "../src/index.css";

type FixtureTransport = {
  events: { onStateChange?: (state: string) => void; onMessage?: (channel: ChannelId, payload: Uint8Array) => void };
};
const transports: FixtureTransport[] = [];
const requests: string[] = [];
SignalingClient.prototype.open = async function () {};
SignalingClient.prototype.send = function () {};
WebRTCTransport.prototype.connect = async function () {
  const fixture = this as unknown as FixtureTransport;
  transports.push(fixture);
  this.state = "connected";
  fixture.events.onStateChange?.("connected");
};
WebRTCTransport.prototype.send = function (channel, payload) {
  if (channel === ChannelId.FileTransfer) {
    const message = decodeMessage(payload);
    if (message.t === "Request") requests.push(message.c.id);
  }
};
WebRTCTransport.prototype.close = function () { this.state = "disconnected"; };

Object.assign(window, {
  __downloadConnections: () => transports.length,
  __downloadRequest: () => requests.at(-1),
  __rejectDownload: (name: string) => {
    transports.at(-1)!.events.onMessage!(ChannelId.FileTransfer, encodeMessage({
      t: "Offer", c: { id: crypto.randomUUID(), name, size: -1, sha256: "0".repeat(64) },
    }));
  },
  __sendDownload: async (name: string, id = crypto.randomUUID(), index = transports.length - 1) => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const sha256 = await sha256Hex(bytes);
    const deliver = transports[index].events.onMessage!;
    deliver(ChannelId.FileTransfer, encodeMessage({ t: "Offer", c: { id, name, size: bytes.length, sha256 } }));
    deliver(ChannelId.FileTransfer, encodeMessage({ t: "Chunk", c: { id, seq: 0, data: bytes } }));
    deliver(ChannelId.FileTransfer, encodeMessage({ t: "Done", c: { id } }));
    return id;
  },
});
createRoot(document.getElementById("root")!).render(<App />);
