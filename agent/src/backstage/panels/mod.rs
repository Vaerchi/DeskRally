//! Read-only and mutating tool panels — structured data rendered natively in the technician
//! UI (the headless backstage surface). Each panel is gated by a capability in
//! [`crate::backstage::rbac`] and invoked only through the [`crate::backstage::Dispatcher`].
//!
//! Panels are added here as they're implemented, cheapest/safest first:
//!   * [`process`] — process list (read-only). Implemented.
//!   * [`services`] — Windows service list (read-only). Implemented.
//!   * [`file`] — filesystem browse (read-only). Implemented.
//!   * [`sysinfo`] — machine identity + resource summary (read-only). Implemented.
//!   * [`eventlog`] — Windows event-log channel view (read-only). Implemented.
//!
//! The read-only Tier-1 surface is complete; mutating panels attach next.

pub mod eventlog;
pub mod file;
pub mod local_path;
pub mod process;
pub mod services;
pub mod sysinfo;
