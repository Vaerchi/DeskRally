//! IPv4 facts from Windows IP Helper and the deterministic LAN report selection.

use std::collections::HashSet;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::ptr;
use std::time::Duration;

use rmt_protocol::signaling::LanEntry;
use tokio::sync::Notify;
use windows::Win32::Foundation::{BOOLEAN, ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, FreeMibTable, GetAdaptersAddresses, GetIfEntry2, GetIfTable2,
    GetIpNetTable2, NotifyIpInterfaceChange, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
    MIB_IF_ROW2, MIB_IPINTERFACE_ROW, MIB_IPNET_ROW2, MIB_NOTIFICATION_TYPE,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN, SOCKET_ADDRESS};

pub(crate) type Mac = [u8; 6];

struct Adapter {
    up: bool,
    ethernet: bool,
    connector: bool,
    hardware: bool,
    mac: Option<Mac>,
    gateway: Option<Ipv4Addr>,
    gateway_mac: Option<Mac>,
    index: u32,
    metric: u32,
    addresses: Vec<(Ipv4Addr, u8)>,
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) address: Ipv4Addr,
    pub(crate) network: Ipv4Addr,
    pub(crate) prefix: u8,
    pub(crate) gateway_mac: Option<Mac>,
    pub(crate) index: u32,
    mac: Mac,
    metric: u32,
}

impl Entry {
    fn wire(&self) -> LanEntry {
        LanEntry {
            mac: mac_text(self.mac),
            ipv4_network: format!("{}/{}", self.network, self.prefix),
            gateway_mac: self.gateway_mac.map(mac_text),
        }
    }
}

fn mac_text([a, b, c, d, e, f]: Mac) -> String {
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

fn mac(bytes: &[u8], len: u32) -> Option<Mac> {
    let value: Mac = bytes.get(..usize::try_from(len).ok()?)?.try_into().ok()?;
    (value != [0; 6] && value[0] & 1 == 0).then_some(value)
}

fn select(adapters: Vec<Adapter>) -> Vec<Entry> {
    let mut entries = Vec::new();
    for adapter in adapters {
        if !(adapter.up && adapter.ethernet && adapter.connector && adapter.hardware)
            || adapter.gateway.is_none()
        {
            continue;
        }
        let Some(mac) = adapter.mac else { continue };
        for (address, prefix) in adapter.addresses {
            if !(16..=30).contains(&prefix) {
                continue;
            }
            let network = Ipv4Addr::from(u32::from(address) & !(u32::MAX >> prefix));
            entries.push(Entry {
                address,
                network,
                prefix,
                mac,
                gateway_mac: adapter.gateway_mac,
                index: adapter.index,
                metric: adapter.metric,
            });
        }
    }
    entries.sort_by_key(|e| {
        (
            e.gateway_mac.is_none(),
            e.metric,
            e.index,
            e.address,
            e.prefix,
        )
    });
    let mut seen = HashSet::new();
    entries.retain(|e| seen.insert((e.index, e.network, e.prefix)));
    entries
}

fn report_entries(adapters: Vec<Adapter>) -> Vec<LanEntry> {
    let mut seen = HashSet::new();
    select(adapters)
        .iter()
        .filter(|e| seen.insert((e.mac, e.network, e.prefix)))
        .take(4)
        .map(Entry::wire)
        .collect()
}

pub(crate) fn snapshot() -> Option<Vec<LanEntry>> {
    Some(report_entries(adapters()?))
}

pub(crate) fn snapshot_matches(entries: &[LanEntry], order: &rmt_protocol::wake::WakeOrder) -> bool {
    let network = format!("{}/{}", Ipv4Addr::from(order.network), order.prefix);
    let gateway = mac_text(order.gateway_mac);
    entries.iter().any(|entry| {
        entry.ipv4_network == network && entry.gateway_mac.as_deref() == Some(gateway.as_str())
    })
}

pub(crate) fn wake_adapter(order: &rmt_protocol::wake::WakeOrder) -> Result<Entry, &'static str> {
    matching_adapter(adapters().ok_or("adapter")?, order, own_mac)
}

fn matching_adapter(
    adapters: Vec<Adapter>,
    order: &rmt_protocol::wake::WakeOrder,
    is_own_mac: impl FnOnce(Mac) -> Option<bool>,
) -> Result<Entry, &'static str> {
    let entry = select(adapters)
        .into_iter()
        .find(|entry| {
            entry.network.octets() == order.network
                && entry.prefix == order.prefix
                && entry.gateway_mac == Some(order.gateway_mac)
        })
        .ok_or("adapter")?;
    if is_own_mac(order.target_mac).ok_or("adapter")? {
        return Err("self_mac");
    }
    Ok(entry)
}

// Own addresses include interfaces excluded by the report's filter and interfaces without IPv4.
fn own_mac(target: Mac) -> Option<bool> {
    let mut table = ptr::null_mut();
    // SAFETY: The API initializes the table pointer and owns its allocation.
    unsafe {
        if GetIfTable2(&mut table) != NO_ERROR || table.is_null() {
            return None;
        }
        let rows = std::slice::from_raw_parts(
            ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(),
            (*table).NumEntries as usize,
        );
        let found = rows.iter().any(|row| {
            mac(&row.PhysicalAddress, row.PhysicalAddressLength) == Some(target)
                || mac(&row.PermanentPhysicalAddress, row.PhysicalAddressLength) == Some(target)
        });
        FreeMibTable(table.cast());
        Some(found)
    }
}

fn neighbors() -> Vec<(u32, Ipv4Addr, Mac)> {
    let mut table = ptr::null_mut();
    // SAFETY: The API returns one allocation with NumEntries initialized rows. Copy the
    // relevant fields before freeing it. Reading Ipv4 follows the AF_INET union discriminant.
    unsafe {
        if GetIpNetTable2(AF_INET, &mut table) != NO_ERROR || table.is_null() {
            return Vec::new();
        }
        let rows = std::slice::from_raw_parts(
            ptr::addr_of!((*table).Table).cast::<MIB_IPNET_ROW2>(),
            (*table).NumEntries as usize,
        );
        let out = rows
            .iter()
            .filter_map(|row| {
                // NL_NEIGHBOR_STATE values for Stale, Reachable and Permanent.
                if row.Address.si_family != AF_INET || !matches!(row.State.0, 4 | 5 | 6) {
                    return None;
                }
                let address = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
                Some((
                    row.InterfaceIndex,
                    address,
                    mac(&row.PhysicalAddress, row.PhysicalAddressLength)?,
                ))
            })
            .collect();
        FreeMibTable(table.cast());
        out
    }
}

// SAFETY: The caller supplies a SOCKET_ADDRESS in the live adapter enumeration buffer.
unsafe fn ipv4(addr: SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    if addr.lpSockaddr.is_null()
        || addr.iSockaddrLength < std::mem::size_of::<SOCKADDR_IN>() as i32
        || (*addr.lpSockaddr).sa_family != AF_INET
    {
        return None;
    }
    let sin = &*addr.lpSockaddr.cast::<SOCKADDR_IN>();
    Some(Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes()))
}

fn adapters() -> Option<Vec<Adapter>> {
    let mut size = 16 * 1024u32;
    for _ in 0..4 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: The buffer is aligned, writable and remains live throughout the traversal.
        unsafe {
            let status = GetAdaptersAddresses(
                AF_INET.0.into(),
                GAA_FLAG_INCLUDE_GATEWAYS,
                None,
                Some(head),
                &mut size,
            );
            if status == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if status == ERROR_NO_DATA.0 {
                return Some(Vec::new());
            }
            if status != NO_ERROR.0 {
                return None;
            }
            let neighbors = neighbors();
            let mut out = Vec::new();
            let mut next = head;
            while let Some(adapter) = next.as_ref() {
                next = adapter.Next;
                let index = adapter.Anonymous1.Anonymous.IfIndex;
                let mut row = MIB_IF_ROW2 {
                    InterfaceIndex: index,
                    ..Default::default()
                };
                if GetIfEntry2(&mut row) != NO_ERROR {
                    continue;
                }
                // The SDK declares these flags as adjacent one-bit fields in a UINT8.
                let flags = *ptr::addr_of!(row.InterfaceAndOperStatusFlags).cast::<u8>();
                let mut gateway_ptr = adapter.FirstGatewayAddress;
                let mut gateway = None;
                while let Some(gw) = gateway_ptr.as_ref() {
                    gateway = ipv4(gw.Address);
                    if gateway.is_some() {
                        break;
                    }
                    gateway_ptr = gw.Next;
                }
                let mut addresses = Vec::new();
                let mut address_ptr = adapter.FirstUnicastAddress;
                while let Some(address) = address_ptr.as_ref() {
                    if let Some(ip) = ipv4(address.Address) {
                        addresses.push((ip, address.OnLinkPrefixLength));
                    }
                    address_ptr = address.Next;
                }
                out.push(Adapter {
                    up: adapter.OperStatus == IfOperStatusUp,
                    ethernet: adapter.IfType == 6, // IF_TYPE_ETHERNET_CSMACD
                    hardware: flags & 1 != 0,
                    connector: flags & 4 != 0,
                    mac: mac(&adapter.PhysicalAddress, adapter.PhysicalAddressLength),
                    gateway,
                    gateway_mac: neighbors.iter().find_map(|&(i, addr, mac)| {
                        (i == index && Some(addr) == gateway).then_some(mac)
                    }),
                    index,
                    metric: adapter.Ipv4Metric,
                    addresses,
                });
            }
            return Some(out);
        }
    }
    None
}

static INTERFACE_CHANGED: Notify = Notify::const_new();

unsafe extern "system" fn on_interface_change(
    _context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    INTERFACE_CHANGED.notify_one();
}

pub(crate) struct InterfaceNotifications(HANDLE);

// The notification handle can be canceled from a different thread, outside its callback.
unsafe impl Send for InterfaceNotifications {}

impl InterfaceNotifications {
    pub(crate) fn subscribe() -> Option<Self> {
        let mut handle = HANDLE::default();
        // SAFETY: The callback uses process-lifetime state only. The handle out-parameter is valid.
        let status = unsafe {
            NotifyIpInterfaceChange(
                AF_INET,
                Some(on_interface_change),
                None,
                BOOLEAN(0),
                &mut handle,
            )
        };
        if status == NO_ERROR {
            Some(Self(handle))
        } else {
            None
        }
    }

    pub(crate) async fn changed() {
        INTERFACE_CHANGED.notified().await;
    }
}

impl Drop for InterfaceNotifications {
    fn drop(&mut self) {
        // SAFETY: This is the handle returned by NotifyIpInterfaceChange; this is not the callback.
        unsafe {
            let _ = CancelMibChangeNotify2(self.0);
        }
    }
}

pub(crate) const DEBOUNCE: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_and_gateway_mac_parser_requires_nonzero_unicast() {
        assert_eq!(mac(&[0; 6], 6), None);
        assert_eq!(mac(&[1, 0, 0, 0, 0, 1], 6), None);
        let local_unicast = [2, 0, 0, 0, 0, 1];
        assert_eq!(mac(&local_unicast, 6), Some(local_unicast));
    }

    fn adapter(index: u32, metric: u32, resolved: bool, addresses: &[(u8, u8)]) -> Adapter {
        Adapter {
            up: true,
            ethernet: true,
            connector: true,
            hardware: true,
            mac: Some([2, 0, 0, 0, 0, index as u8]),
            gateway: Some(Ipv4Addr::new(192, 168, 0, 1)),
            gateway_mac: resolved.then_some([2, 0, 0, 0, 1, 1]),
            index,
            metric,
            addresses: addresses
                .iter()
                .map(|&(segment, prefix)| (Ipv4Addr::new(192, 168, segment, 10), prefix))
                .collect(),
        }
    }

    #[test]
    fn report_filters_deduplicates_prioritizes_and_caps() {
        let mut vethernet = adapter(1, 0, true, &[(1, 24)]);
        vethernet.connector = false;
        let mut no_gateway = adapter(2, 0, true, &[(2, 24)]);
        no_gateway.gateway = None;
        let mut software = adapter(3, 0, true, &[(3, 24)]);
        software.hardware = false;
        let report = report_entries(vec![
            vethernet,
            no_gateway,
            software,
            adapter(4, 0, true, &[(4, 15), (4, 31), (4, 32)]),
            adapter(5, 1, false, &[(5, 24), (6, 24), (7, 24)]),
            adapter(6, 10, true, &[(8, 24), (9, 24), (8, 24)]),
            adapter(7, 9, true, &[(10, 24)]),
        ]);
        let networks: Vec<_> = report.iter().map(|e| e.ipv4_network.as_str()).collect();
        assert_eq!(
            networks,
            [
                "192.168.10.0/24",
                "192.168.8.0/24",
                "192.168.9.0/24",
                "192.168.5.0/24"
            ]
        );
        assert!(report[3].gateway_mac.is_none());
    }

    #[test]
    fn report_keeps_the_highest_ranked_entry_for_each_wire_key() {
        let mut lower_rank = adapter(1, 10, true, &[(8, 24)]);
        let higher_rank = adapter(2, 1, true, &[(8, 24), (9, 24), (10, 24)]);
        lower_rank.mac = higher_rank.mac;
        lower_rank.gateway_mac = Some([2, 0, 0, 0, 1, 2]);
        let report = report_entries(vec![
            lower_rank,
            higher_rank,
            adapter(3, 20, true, &[(11, 24)]),
        ]);
        let networks: Vec<_> = report.iter().map(|e| e.ipv4_network.as_str()).collect();
        assert_eq!(
            networks,
            [
                "192.168.8.0/24",
                "192.168.9.0/24",
                "192.168.10.0/24",
                "192.168.11.0/24"
            ]
        );
        assert_eq!(report[0].gateway_mac.as_deref(), Some("02:00:00:00:01:01"));
    }

    #[test]
    fn wake_requires_fresh_matching_network_gateway_and_a_nonlocal_target() {
        let read = || vec![adapter(6, 10, true, &[(8, 24), (9, 24)])];
        let mut order = rmt_protocol::wake::WakeOrder {
            request_id: [0; 16],
            target_mac: [2, 0, 0, 0, 2, 2],
            network: [192, 168, 8, 0],
            prefix: 24,
            gateway_mac: [2, 0, 0, 0, 1, 1],
            issued_at_ms: 0,
            expires_at_ms: 1,
        };
        assert_eq!(
            matching_adapter(read(), &order, |_| Some(false))
                .unwrap()
                .index,
            6
        );
        assert_eq!(
            matching_adapter(read(), &order, |mac| Some(mac == order.target_mac)).unwrap_err(),
            "self_mac"
        );
        assert_eq!(
            matching_adapter(read(), &order, |_| None).unwrap_err(),
            "adapter"
        );
        order.gateway_mac[5] = 2;
        assert_eq!(
            matching_adapter(read(), &order, |_| Some(false)).unwrap_err(),
            "adapter"
        );
        order.gateway_mac[5] = 1;
        order.network[2] = 10;
        assert_eq!(
            matching_adapter(read(), &order, |_| Some(false)).unwrap_err(),
            "adapter"
        );
    }

    #[test]
    fn fifth_prefix_is_locally_eligible_but_missing_from_the_wire_snapshot() {
        let read = || vec![adapter(6, 10, true, &[(8, 24), (9, 24), (10, 24), (11, 24), (12, 24)])];
        let mut order = rmt_protocol::wake::WakeOrder {
            request_id: [0; 16],
            target_mac: [2, 0, 0, 0, 2, 2],
            network: [192, 168, 12, 0],
            prefix: 24,
            gateway_mac: [2, 0, 0, 0, 1, 1],
            issued_at_ms: 0,
            expires_at_ms: 1,
        };
        let snapshot = report_entries(read());
        assert_eq!(snapshot.len(), 4);
        assert!(matching_adapter(read(), &order, |_| Some(false)).is_ok());
        assert!(!snapshot_matches(&snapshot, &order));
        order.network[2] = 11;
        assert!(snapshot_matches(&snapshot, &order));
        order.gateway_mac[5] = 2;
        assert!(!snapshot_matches(&snapshot, &order));
    }

    #[test]
    fn ties_use_interface_index_then_lowest_local_address() {
        let mut second = adapter(9, 10, true, &[(8, 24)]);
        second.addresses.push((Ipv4Addr::new(192, 168, 8, 1), 24));
        let first = adapter(6, 10, true, &[(9, 24)]);
        let selected = select(vec![second, first]);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].index, 6);
        assert_eq!(selected[1].address, Ipv4Addr::new(192, 168, 8, 1));
    }
}
