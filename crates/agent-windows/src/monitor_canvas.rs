//! Fixed virtual-desktop geometry for independent viewer monitor viewports.
use rmt_agent_core::{MonitorInfo, control::{CanvasMonitor, MonitorCanvas}};

/// Reject invalid/oversized layouts instead of publishing unsafe coordinate geometry.
pub(crate) fn layout(monitors: &[MonitorInfo]) -> Option<MonitorCanvas> {
    if monitors.is_empty() || monitors.len() > 64 { return None; }
    let left = monitors.iter().map(|m| i64::from(m.left)).min()?;
    let top = monitors.iter().map(|m| i64::from(m.top)).min()?;
    let right = monitors.iter().map(|m| i64::from(m.left) + i64::from(m.width)).max()?;
    let bottom = monitors.iter().map(|m| i64::from(m.top) + i64::from(m.height)).max()?;
    let width = u32::try_from(right - left).ok()?;
    let height = u32::try_from(bottom - top).ok()?;
    // VP8's coded dimension fields are 14 bits. Leave larger layouts on legacy primary capture.
    if width == 0 || height == 0 || width > 16383 || height > 16383 { return None; }
    let mut ids = std::collections::HashSet::new();
    let monitors = monitors.iter().map(|m| {
        if m.width == 0 || m.height == 0 || m.id == u32::MAX || !ids.insert(m.id) { return None; }
        Some(CanvasMonitor { id:m.id, x:u32::try_from(i64::from(m.left)-left).ok()?,
            y:u32::try_from(i64::from(m.top)-top).ok()?, width:m.width, height:m.height })
    }).collect::<Option<Vec<_>>>()?;
    Some(MonitorCanvas { width, height, monitors })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn m(id:u32, left:i32, top:i32, width:u32, height:u32)->MonitorInfo {
        MonitorInfo { id,left,top,width,height,dpi_scale:1.0 }
    }
    #[test] fn negative_origin_and_vertical_layout() {
        let c=layout(&[m(0,0,0,1920,1080),m(1,-1280,-1024,1280,1024)]).unwrap();
        assert_eq!((c.width,c.height),(3200,2104));
        assert_eq!((c.monitors[0].x,c.monitors[0].y),(1280,1024));
        assert_eq!((c.monitors[1].x,c.monitors[1].y),(0,0));
    }
    #[test] fn rejects_invalid_and_oversized_layouts() {
        assert!(layout(&[]).is_none());
        assert!(layout(&[m(0,0,0,0,1080)]).is_none());
        assert!(layout(&[m(0,i32::MIN,0,1920,1080),m(1,i32::MAX,0,1920,1080)]).is_none());
        assert!(layout(&[m(0,0,0,1920,1080),m(0,1920,0,1920,1080)]).is_none());
    }
    #[test] fn canvas_wire_roundtrip_keeps_geometry() {
        let c=layout(&[m(4,-1920,0,1920,1080),m(8,0,0,2560,1440)]).unwrap();
        let msg=rmt_agent_core::control::ControlMessage::MonitorCanvas(c);
        assert_eq!(rmt_agent_core::control::decode(&rmt_agent_core::control::encode(&msg)).unwrap(),msg);
    }
}
