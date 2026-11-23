//! The file-management seam (docs/58 §4-§5).
//!
//! The portable [`Dispatcher`](super::Dispatcher) authorizes, guards, confirms and audits; the OS
//! work lives behind [`FileManager`], implemented on Windows by the host (handle-relative, no
//! reparse traversal, identity-based protection of the agent's own directories). The split is
//! PREPARE then COMMIT so the objects that were checked are the objects that are changed:
//! [`FileManager::prepare`] resolves every operand to held handles and returns the guard decision,
//! the identity bytes the confirmation token binds to, and a one-shot commit that acts through those
//! same handles. Nothing is re-resolved by name between the two.

use super::audit::AuditAction;
use super::rbac::GuardRail;

/// One file-management operation, as requested (unresolved).
#[derive(Debug, Clone, Copy)]
pub enum FileOp<'a> {
    CreateDirectory { path: &'a str },
    Rename { from: &'a str, to: &'a str },
    Delete { path: &'a str },
    Place { transfer_id: uuid::Uuid, dest_dir: &'a str },
    Discard { transfer_id: uuid::Uuid },
}

/// Admission, checked by a commit immediately before its irreversible system call.
pub type Admit<'a> = &'a dyn Fn() -> bool;

/// A resolved operation holding its handles until it is committed or dropped.
pub struct Prepared {
    /// The guard decision for the RESOLVED operands.
    pub guard: GuardRail,
    /// Bytes identifying the resolved objects (volume serial + file id of each operand and of the
    /// destination parent). Folded into the confirmation token, so a retry confirms these objects
    /// and no others.
    pub identity: Vec<u8>,
    /// The audit action describing the resolved operation (recorded on a denial or a failure).
    pub audit: AuditAction,
    /// Perform the operation through the held handles. Returns the audit action of what was done.
    pub commit: Box<dyn FnOnce(Admit<'_>) -> Result<AuditAction, CommitError> + Send>,
}

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    /// Refused by a path rule or a protected-object rule. Audited as denied.
    #[error("{0}")]
    Refused(&'static str),
    /// The OS could not resolve the operands (missing parent, access denied...). Audited as failed.
    #[error("{0}")]
    Exec(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// Admission was refused at the irreversible step (the indicator was lost or the session ended).
    #[error("the guest's on-screen indicator is not visible, so this machine is not accepting changes")]
    NotAdmitted,
    #[error("{0}")]
    Exec(String),
}

pub trait FileManager: Send {
    fn prepare(&mut self, op: FileOp<'_>) -> Result<Prepared, PrepareError>;
}

/// The default: no file management (non-Windows builds, and any dispatcher a host did not equip).
pub struct Unsupported;

impl FileManager for Unsupported {
    fn prepare(&mut self, _op: FileOp<'_>) -> Result<Prepared, PrepareError> {
        Err(PrepareError::Exec("file management is only available on Windows agents".into()))
    }
}

/// A scriptable [`FileManager`] for the dispatcher's unit tests: it resolves every operation to the
/// identity bytes and guard it was given, and records whether a commit ran.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    pub struct FakeFiles {
        pub guard: Arc<Mutex<GuardRail>>,
        pub identity: Arc<Mutex<Vec<u8>>>,
        pub commits: Arc<AtomicUsize>,
        /// What the commit's admission check said, per commit.
        pub admitted: Arc<Mutex<Vec<bool>>>,
    }

    impl FakeFiles {
        pub fn new(guard: GuardRail, identity: &[u8]) -> Self {
            Self {
                guard: Arc::new(Mutex::new(guard)),
                identity: Arc::new(Mutex::new(identity.to_vec())),
                commits: Arc::new(AtomicUsize::new(0)),
                admitted: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl FileManager for FakeFiles {
        fn prepare(&mut self, op: FileOp<'_>) -> Result<Prepared, PrepareError> {
            let path = match op {
                FileOp::Delete { path } | FileOp::CreateDirectory { path } => format!("RESOLVED:{path}"),
                other => format!("RESOLVED:{other:?}"),
            };
            let commits = Arc::clone(&self.commits);
            let admitted = Arc::clone(&self.admitted);
            let done = AuditAction::FileDelete { path: path.clone() };
            Ok(Prepared {
                guard: self.guard.lock().unwrap().clone(),
                identity: self.identity.lock().unwrap().clone(),
                audit: AuditAction::FileDelete { path },
                commit: Box::new(move |admit| {
                    let ok = admit();
                    admitted.lock().unwrap().push(ok);
                    if !ok {
                        return Err(CommitError::NotAdmitted);
                    }
                    commits.fetch_add(1, Ordering::SeqCst);
                    Ok(done)
                }),
            })
        }
    }
}
