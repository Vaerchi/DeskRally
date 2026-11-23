// Synthetic API only: no guest, service, enrollment, capture or input is started.
import { createRoot } from "react-dom/client";
import { AttendedPanel } from "../src/components/AttendedPanel";
import { JoinPage } from "../src/components/JoinPage";
import { ManagedInstallDownload } from "../src/components/ManagedInstallDownload";
import type { ConsoleApi, AttendedSessionRecord, MachineGroup } from "../src/lib/console_api";
import "../src/index.css";

const mode = new URLSearchParams(location.search).get("mode");
const requests: string[] = [];
let state: AttendedSessionRecord["state"] = "pending";
const session = (): AttendedSessionRecord => ({
  id: "test-session", tenant_id: "test-tenant", group_id: "test-group", technician_id: "test-tech",
  state, created_at: "2026-09-14T00:00:00Z", expires_at: "2026-09-15T00:00:00Z",
});
const groups: MachineGroup[] = mode === "empty" ? [] : [{ id: "test-group", name: "Home computers" }];
if (mode === "multiple") groups.push({ id: "work-group", name: "Work computers" });
const api = {
  managedInstallerAvailable: async () => mode === "installer",
  downloadManagedInstaller: async (group: string) => {
    requests.push(group);
    return new Blob(["synthetic installer bundle; never executed"], { type: "application/zip" });
  },
  listMachineGroups: async () => {
    if (mode === "error") throw new Error("synthetic failure");
    return groups;
  },
  createAttendedSession: async (group: string) => {
    requests.push(group);
    return { session: session(), code: "0123-4567-89AB-C", join_code: "0123456789ABC", join_url: "/join#0123456789ABC" };
  },
  getAttendedSession: async () => session(),
  connectAttendedSession: async () => { throw new Error("No real connection in this fixture"); },
} as unknown as ConsoleApi;
Object.assign(window, { supportRequests: requests, supportConsent: () => { state = "consented"; } });
createRoot(document.getElementById("root")!).render(mode === "installer"
  ? <ManagedInstallDownload api={api} groupId="test-group" /> : mode === "join"
  ? <JoinPage code="0123456789ABC" platform="windows" download={{ url: "/download/DeskRallySupport.exe", sha256: "a".repeat(64) }} />
  : <AttendedPanel api={api} onConnect={() => { throw new Error("No transport in fixture"); }} />);
