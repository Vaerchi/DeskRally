import app from "./App.tsx?raw";
import { expect, it } from "vitest";
import { ControlClient, decodeControl, encodeControl } from "./lib/control";
import { RunReceiptSession } from "./lib/run_receipt_relay";
import { runToolboxScript } from "./lib/toolbox_run";
import type { ToolboxItem } from "./lib/console_api";

it.each([[], ["run_receipt_v1"]].map((features) => ({ features })))(
  "dispatches the App toolbox grant with negotiated features $features",
  async ({ features }) => {
    expect(app).toContain("controlRef.current?.requestBackstageFeatures()");
    expect(app).toContain("runReceipts.setFeatures(features)");
    expect(app).toContain("onRunReceipt: (receipt) => runReceipts.receive(receipt)");
    expect(app).toContain("runReceiptsRef.current?.dispatch(control, command, shell, asUser, requestId)");

    const receiptSession = new RunReceiptSession(async () => 200);
    const frames: ReturnType<typeof decodeControl>[] = [];
    const control = new ControlClient((frame) => frames.push(decodeControl(frame)), {
      onBackstageFeatures: (list) => receiptSession.setFeatures(list),
    });
    control.requestBackstageFeatures();
    control.handleMessage(encodeControl({ t: "BackstageFeatures", c: { features } }));
    await runToolboxScript({ id: "item", version: 2 } as ToolboxItem, {
      api: { requestToolboxRun: async () => ({ request_id: "run", shell: "cmd", run_as: "system", command: "whoami" }) },
      currentSessionId: () => "session", isCurrent: () => true,
      sendRunCommand: (command, shell, asUser, id) => receiptSession.dispatch(control, command, shell, asUser, id),
    });
    expect(frames).toEqual([
      { t: "RequestBackstageFeatures" },
      { t: "RunCommand", c: { command: "whoami", shell: "Cmd", as_user: false, ...(features.length ? { request_id: "run" } : {}) } },
    ]);
  },
);
