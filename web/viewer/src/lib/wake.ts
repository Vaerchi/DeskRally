import type { MachineRecord } from "./console_api";
import { holdsCapabilityForGroup, type MeCapability } from "./fleet_directives";

const noLanFacts = "This machine hasn't reported a wired network yet";
const noRelay = "No online machine you manage is on its network";
const requested = "Wake requested. It only works if Wake-on-LAN is turned on for this machine.";

export const WAKE_GUIDE_PATH = "/docs/wake-on-lan";

export function wakeMenuState(
  machine: Pick<MachineRecord, "online" | "group_id" | "wake">,
  myCaps: readonly MeCapability[],
  presenceKnown: boolean,
): { visible: boolean; enabled: boolean; reason?: string } {
  if (presenceKnown && machine.online === false && holdsCapabilityForGroup(myCaps, "wake_machine", machine.group_id)) {
    switch (machine.wake) {
      case "ready": return { visible: true, enabled: true };
      case "no_lan_facts": return { visible: true, enabled: false, reason: noLanFacts };
      case "no_relay": return { visible: true, enabled: false, reason: noRelay };
    }
  }
  return { visible: false, enabled: false };
}

export function wakeResultMessage(outcome: string | number | undefined): string {
  switch (outcome) {
    case "requested": return requested;
    case "uncertain": return requested + " The request may not have reached the relay.";
    case "machine_online": return "This machine is already online.";
    case "no_lan_facts": return noLanFacts;
    case "no_relay": return noRelay;
    case "unavailable": return "No relay could be reached right now. Try again shortly.";
    case "changed": return "Something changed while sending the request. Try again.";
    case "presence_unknown": return "Machine status is unknown right now. Try again shortly.";
    case "audit_unavailable": return "Wake is unavailable: auditing is not configured.";
    case 429: return "Wake was requested very recently. Wait a moment and try again.";
    case 404: return "Wake-on-LAN is not enabled on this server.";
    default: return "Could not request wake. Try again shortly.";
  }
}
