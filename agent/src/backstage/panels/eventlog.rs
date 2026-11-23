//! Event-log panel — a read-only view of a Windows event-log channel (System, Application,
//! Security, …), rendered natively in the technician UI. Read-only, over the modern Windows
//! Event Log API (`EvtQuery`/`EvtNext`/`EvtRender`).
//!
//! Requires [`crate::backstage::rbac::Capability::EventLogRead`]. Note that reading the
//! **Security** channel requires the agent to hold `SeSecurityPrivilege` (LocalSystem does);
//! from a normal context that channel returns access-denied while System/Application read
//! fine. Rows carry `Option`s so the UI shows "—" rather than fabricating a value.
//!
//! Each event is rendered to its raw event XML and a few headline fields are extracted. The
//! fully-localized human message (`EvtFormatMessage` + publisher metadata) is a deliberate
//! follow-up — it needs the provider's message DLLs and is much heavier; the record id,
//! provider, event id, level, and timestamp already make a useful triage panel.

use serde::{Deserialize, Serialize};

/// One row in the event-log table. Shaped for direct JSON rendering in the technician UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventLogRow {
    /// The channel this came from ("System", "Application", …).
    pub channel: String,
    /// Monotonic per-channel record id.
    pub record_id: Option<u64>,
    /// Publishing provider/source name.
    pub provider: Option<String>,
    pub event_id: Option<u32>,
    /// Severity name mapped from the numeric Level (Critical/Error/Warning/Information/Verbose).
    pub level: Option<String>,
    /// ISO-8601 UTC timestamp exactly as the log recorded it (the UI parses/localizes it).
    pub time_created: Option<String>,
}

/// Map the numeric event Level to a severity name. Levels are defined by the Windows event
/// schema; 0 means "not set" and is commonly treated as Information.
pub fn level_name(level: u8) -> &'static str {
    match level {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        0 | 4 => "Information",
        5 => "Verbose",
        _ => "Unknown",
    }
}

/// Extract the text content of a simple `<Tag>value</Tag>` element from event XML.
fn tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    // Skip to the end of the opening tag (handles attributes like `<EventID Qualifiers="0">`).
    let gt = xml[start..].find('>')? + start + 1;
    let close = format!("</{tag}>");
    let end = xml[gt..].find(&close)? + gt;
    Some(xml[gt..end].trim())
}

/// Extract an attribute value scoped to the first occurrence of `<element`. Handles either
/// quote style — real `EvtRender` output single-quotes attributes (`Name='...'`) while other
/// tooling double-quotes them. Used for `<Provider Name=...>` and `<TimeCreated SystemTime=...>`.
fn attr<'a>(xml: &'a str, element: &str, attr_name: &str) -> Option<&'a str> {
    let el = xml.find(&format!("<{element}"))?;
    let tag_end = xml[el..].find('>')? + el;
    let region = &xml[el..tag_end];
    let key = format!("{attr_name}=");
    let after = region.find(&key)? + key.len();
    let quote = region[after..].chars().next()?; // ' or "
    if quote != '"' && quote != '\'' {
        return None;
    }
    let vs = after + 1;
    let ve = region[vs..].find(quote)? + vs;
    Some(&region[vs..ve])
}

/// Parse a rendered event XML string into an [`EventLogRow`] for the given channel.
pub fn parse_event_xml(channel: &str, xml: &str) -> EventLogRow {
    EventLogRow {
        channel: channel.to_string(),
        record_id: tag_text(xml, "EventRecordID").and_then(|s| s.parse().ok()),
        provider: attr(xml, "Provider", "Name").map(|s| s.chars().take(256).collect()),
        event_id: tag_text(xml, "EventID").and_then(|s| s.parse().ok()),
        level: tag_text(xml, "Level")
            .and_then(|s| s.parse::<u8>().ok())
            .map(|n| level_name(n).to_string()),
        time_created: attr(xml, "TimeCreated", "SystemTime").map(|s| s.chars().take(64).collect()),
    }
}

/// Query the most recent events from a channel (newest first). Real data on Windows; an empty
/// list off Windows (the row type stays portable so the dispatcher/`Response` compile there).
#[cfg(windows)]
pub fn query(channel: &str, max: usize) -> Vec<EventLogRow> {
    imp::query(channel, max).unwrap_or_default()
}

#[cfg(not(windows))]
pub fn query(_channel: &str, _max: usize) -> Vec<EventLogRow> {
    Vec::new()
}

#[cfg(windows)]
mod imp {
    use super::{parse_event_xml, EventLogRow};

    use windows::core::HSTRING;
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtRender, EvtQueryChannelPath, EvtQueryReverseDirection,
        EvtRenderEventXml, EVT_HANDLE,
    };

    /// RAII wrapper so every EVT_HANDLE is closed, including on the error paths.
    struct EvtGuard(EVT_HANDLE);
    impl Drop for EvtGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }

    pub(super) fn query(channel: &str, max: usize) -> Option<Vec<EventLogRow>> {
        if channel.len() > 256 || channel.chars().any(char::is_control) { return None; }
        let max = max.min(1000);
        unsafe {
            let path = HSTRING::from(channel);
            // Empty query "*" = all events on the channel; reverse = newest first.
            let handle = EvtQuery(
                None,
                &path,
                None,
                (EvtQueryChannelPath.0 | EvtQueryReverseDirection.0) as u32,
            )
            .ok()?;
            let results = EvtGuard(handle);

            let mut rows = Vec::with_capacity(max.min(256));
            let batch = 16usize;
            let mut scanned = 0usize;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);

            'outer: while rows.len() < max && scanned < 1000 && std::time::Instant::now() < deadline {
                // EvtNext fills raw handle values (isize); we wrap each into an EVT_HANDLE.
                let mut events = [0isize; 16];
                let mut returned = 0u32;
                let want = batch.min(max - rows.len()).min(1000 - scanned) as u32;

                let next = EvtNext(results.0, &mut events[..want as usize], 1000, 0, &mut returned);
                if next.is_err() {
                    // Clean end of the channel (ERROR_NO_MORE_ITEMS); anything else we stop on.
                    break;
                }
                if returned == 0 {
                    break;
                }

                for &raw in events.iter().take(returned as usize) {
                    scanned += 1;
                    let guard = EvtGuard(EVT_HANDLE(raw));
                    if let Some(xml) = render_xml(guard.0) {
                        rows.push(parse_event_xml(channel, &xml));
                    }
                    if rows.len() >= max {
                        break 'outer;
                    }
                }
            }
            Some(rows)
        }
    }

    /// Render one event handle to its event XML via the two-call size idiom.
    unsafe fn render_xml(event: EVT_HANDLE) -> Option<String> {
        let mut used = 0u32;
        let mut props = 0u32;

        // First call: size probe (expected to fail with ERROR_INSUFFICIENT_BUFFER).
        let probe = EvtRender(None, event, EvtRenderEventXml.0 as u32, 0, None, &mut used, &mut props);
        if probe.is_ok() || used == 0 {
            // Either nothing to render, or a genuine failure other than "need more room".
            if let Err(e) = probe {
                if e.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() {
                    return None;
                }
            }
        }

        if used > 1024 * 1024 { return None; }
        // `used` is a byte count; the XML is UTF-16.
        let mut buf: Vec<u16> = vec![0u16; (used as usize).div_ceil(2)];
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0 as u32,
            (buf.len() * 2) as u32,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut used,
            &mut props,
        )
        .ok()?;

        // Trim to the returned byte length and drop a trailing NUL if present.
        let mut chars = (used as usize) / 2;
        while chars > 0 && buf[chars - 1] == 0 {
            chars -= 1;
        }
        Some(String::from_utf16_lossy(&buf[..chars]))
    }

    // Keep the ERROR_NO_MORE_ITEMS import meaningful even though EvtNext's Err covers it; it
    // documents the expected terminal condition.
    #[allow(dead_code)]
    const _EXPECTED_END: windows::core::HRESULT = ERROR_NO_MORE_ITEMS.to_hresult();
}

#[cfg(test)]
mod tests {
    #[test]
    fn security_eventlog_projection_bounds_os_strings() {
        let xml = format!("<Event><Provider Name=\"{}\"/><TimeCreated SystemTime=\"{}\"/></Event>", "x".repeat(5000), "y".repeat(5000));
        let row = super::parse_event_xml("Application", &xml);
        assert_eq!(row.provider.unwrap().len(), 256);
        assert_eq!(row.time_created.unwrap().len(), 64);
    }

    use super::*;

    // A representative slice of real System-channel event XML.
    const SAMPLE: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager"/><EventID Qualifiers="16384">7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime="2026-07-26T14:03:21.1234567Z"/><EventRecordID>988271</EventRecordID><Channel>System</Channel><Computer>DESKTOP-RMT</Computer></System></Event>"#;

    #[test]
    fn parses_headline_fields_from_event_xml() {
        let row = parse_event_xml("System", SAMPLE);
        assert_eq!(row.channel, "System");
        assert_eq!(row.provider.as_deref(), Some("Service Control Manager"));
        assert_eq!(row.event_id, Some(7045));
        assert_eq!(row.level.as_deref(), Some("Information"));
        assert_eq!(row.record_id, Some(988271));
        assert_eq!(row.time_created.as_deref(), Some("2026-07-26T14:03:21.1234567Z"));
    }

    #[test]
    fn parses_single_quoted_attributes_from_real_evtrender_output() {
        // EvtRender emits single-quoted attributes — the shape the live panel actually sees.
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7040</EventID><Level>4</Level><TimeCreated SystemTime='2026-07-26T22:15:35.9Z'/><EventRecordID>988272</EventRecordID></System></Event>"#;
        let row = parse_event_xml("System", xml);
        assert_eq!(row.provider.as_deref(), Some("Service Control Manager"));
        assert_eq!(row.event_id, Some(7040));
        assert_eq!(row.record_id, Some(988272));
        assert_eq!(row.time_created.as_deref(), Some("2026-07-26T22:15:35.9Z"));
    }

    #[test]
    fn level_numbers_map_to_names() {
        assert_eq!(level_name(1), "Critical");
        assert_eq!(level_name(2), "Error");
        assert_eq!(level_name(3), "Warning");
        assert_eq!(level_name(4), "Information");
        assert_eq!(level_name(0), "Information");
        assert_eq!(level_name(5), "Verbose");
    }

    #[test]
    fn missing_fields_become_none_not_panics() {
        let row = parse_event_xml("Application", "<Event><System></System></Event>");
        assert_eq!(row.provider, None);
        assert_eq!(row.event_id, None);
        assert_eq!(row.record_id, None);
    }

    #[cfg(windows)]
    #[test]
    fn reads_real_system_channel_events() {
        // The System channel is readable without special privilege and is never empty on a
        // running machine.
        let rows = query("System", 10);
        assert!(!rows.is_empty(), "the System event log always has recent entries");
        assert!(rows.len() <= 10, "respects the max cap");
        // At least one row should carry a provider and an event id.
        assert!(rows.iter().any(|r| r.provider.is_some() && r.event_id.is_some()));
    }
}
