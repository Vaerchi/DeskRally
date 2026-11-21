# Wake-on-LAN

In Machines, open the offline machine’s action menu and choose **Wake**. Enable Wake-on-LAN in the target machine’s firmware and network adapter settings. Check the machine’s presence in the console to see when it comes online.

## Verified power states

DeskRally has yet to publish a verified power-state list. Wake behavior depends on the machine’s firmware, adapter, driver, and power state. Sleep, shutdown, Windows Fast Startup, and Modern Standby can behave differently.

## Network requirements

The target and an eligible online machine you manage need wired adapters on the same IPv4 network and default gateway. Each adapter needs a subnet prefix from /16 through /30 and a default gateway whose hardware address Windows has resolved.

- **This machine hasn't reported a wired network yet** means DeskRally has no wired network report for the target.
- **No online machine you manage is on its network** means DeskRally has no eligible online relay on the target’s network.

Wi-Fi adapters are outside the supported network setup. A Hyper-V external switch can also prevent eligibility if the virtual adapter owns the IPv4 address and gateway and the physical adapter has neither. Hyper-V internal and default switches do not affect eligibility.

Each machine reports up to four wired adapter and IPv4 network entries. A machine with more than four eligible entries may omit the network it shares with a relay.
