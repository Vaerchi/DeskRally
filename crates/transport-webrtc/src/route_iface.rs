//! The machine's network adapters as groups of local addresses, one group per adapter.
//!
//! ICE uses this to keep HOST candidates on the adapter that carries the signaling connection (see
//! `build_api` in lib.rs). Grouping matters: an adapter has several addresses (IPv4, global IPv6,
//! link-local IPv6), and limiting host candidates to the one address the signaling socket used would
//! drop the same adapter's other address family.
//!
//! webrtc-util's own interface list cannot be used for this on Windows: its Windows `ifaces()` sets
//! every interface name to "" (webrtc-util 0.9 `ifaces/ffi/windows`), so a filter by interface
//! name matches every adapter (measured on a two-NIC VM, 2026-11-12). Windows therefore reads the
//! adapters directly with `GetAdaptersAddresses`. Other platforms group webrtc-util's list by its
//! (real) interface names.

use std::net::IpAddr;

/// One `Vec` of unicast addresses per network adapter. Empty when the list cannot be read, which
/// callers treat as "unknown" (no restriction).
pub fn adapter_address_groups() -> Vec<Vec<IpAddr>> {
    platform::groups()
}

#[cfg(windows)]
mod platform {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

    pub fn groups() -> Vec<Vec<IpAddr>> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        // 16 KB fits most machines in one call; on ERROR_BUFFER_OVERFLOW the API reports the size
        // it needs. Bounded retries: the list can grow between calls.
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            // u64 elements keep the buffer 8-byte aligned for IP_ADAPTER_ADDRESSES_LH.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            // SAFETY: `head` points at `size` writable, aligned bytes that outlive the call.
            let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(head), &mut size) };
            if rc == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if rc != NO_ERROR.0 {
                tracing::debug!(rc, "ice: GetAdaptersAddresses failed; host candidates unrestricted");
                return Vec::new();
            }
            let mut out = Vec::new();
            let mut adapter = head as *const IP_ADAPTER_ADDRESSES_LH;
            // SAFETY: on NO_ERROR the buffer holds a NULL-terminated list of adapters, each with a
            // NULL-terminated unicast list whose sockaddrs are valid for their stated family; all of
            // it lives in `buf`, which outlives this loop.
            unsafe {
                while !adapter.is_null() {
                    let mut addrs = Vec::new();
                    let mut ua = (*adapter).FirstUnicastAddress as *const windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH;
                    while !ua.is_null() {
                        let sa = (*ua).Address.lpSockaddr;
                        if !sa.is_null() {
                            let family = (*sa).sa_family;
                            if family == AF_INET {
                                let sin = &*(sa as *const SOCKADDR_IN);
                                addrs.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr))));
                            } else if family == AF_INET6 {
                                let sin6 = &*(sa as *const SOCKADDR_IN6);
                                addrs.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte)));
                            }
                        }
                        ua = (*ua).Next;
                    }
                    if !addrs.is_empty() {
                        out.push(addrs);
                    }
                    adapter = (*adapter).Next;
                }
            }
            return out;
        }
        Vec::new()
    }
}

#[cfg(not(windows))]
mod platform {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    pub fn groups() -> Vec<Vec<IpAddr>> {
        let mut by_name: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
        for i in webrtc::util::ifaces::ifaces().unwrap_or_default() {
            // An unnamed interface cannot be grouped safely; leave it out (it can then never be the
            // route's group, so an unnamed route address means "no restriction").
            if let (false, Some(addr)) = (i.name.is_empty(), i.addr) {
                by_name.entry(i.name).or_default().push(addr.ip());
            }
        }
        by_name.into_values().collect()
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn this_machine_has_at_least_one_adapter_with_an_address() {
        let groups = super::adapter_address_groups();
        assert!(!groups.is_empty(), "GetAdaptersAddresses returned no adapters");
        assert!(groups.iter().any(|g| g.iter().any(|ip| ip.is_loopback())), "{groups:?}");
    }
}
