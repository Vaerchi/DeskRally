//! One power request shared by the control sessions that have asked to keep this machine awake.

use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, LazyLock, Mutex, Once,
};

use uuid::Uuid;
use windows::core::{w, PWSTR, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Power::{
    PowerClearRequest, PowerCreateRequest, PowerRequestDisplayRequired, PowerRequestSystemRequired,
    PowerSetRequest, POWER_REQUEST_TYPE,
};
use windows::Win32::System::Threading::{POWER_REQUEST_CONTEXT_SIMPLE_STRING, REASON_CONTEXT, REASON_CONTEXT_0};

pub(crate) const FEATURE: &str = "keep_awake_v1";

pub(crate) trait Backend {
    type Handle;

    fn create(&mut self) -> Result<Self::Handle>;
    fn set(&mut self, handle: &Self::Handle, kind: POWER_REQUEST_TYPE) -> Result<()>;
    fn clear(&mut self, handle: &Self::Handle, kind: POWER_REQUEST_TYPE);
    fn close(&mut self, handle: Self::Handle);
}

pub(crate) struct WindowsPower;

impl Backend for WindowsPower {
    // Store the owning HANDLE as an integer so it can be shared behind the process mutex.
    type Handle = isize;

    fn create(&mut self) -> Result<Self::Handle> {
        let context = REASON_CONTEXT {
            Version: 0, // POWER_REQUEST_CONTEXT_VERSION
            Flags: POWER_REQUEST_CONTEXT_SIMPLE_STRING,
            Reason: REASON_CONTEXT_0 {
                SimpleReasonString: PWSTR(w!("DeskRally remote session in progress").as_ptr().cast_mut()),
            },
        };
        unsafe { PowerCreateRequest(&context) }.map(|handle| handle.0 as isize)
    }

    fn set(&mut self, handle: &Self::Handle, kind: POWER_REQUEST_TYPE) -> Result<()> {
        unsafe { PowerSetRequest(HANDLE(*handle as _), kind) }
    }

    fn clear(&mut self, handle: &Self::Handle, kind: POWER_REQUEST_TYPE) {
        let _ = unsafe { PowerClearRequest(HANDLE(*handle as _), kind) };
    }

    fn close(&mut self, handle: Self::Handle) {
        let _ = unsafe { CloseHandle(HANDLE(handle as _)) };
    }
}

struct Holders<B: Backend> {
    backend: B,
    sessions: HashSet<Uuid>,
    request: Option<B::Handle>,
}

impl<B: Backend> Holders<B> {
    fn new(backend: B) -> Self {
        Self { backend, sessions: HashSet::new(), request: None }
    }

    fn acquire(&mut self, session: Uuid) -> Result<()> {
        if self.request.is_none() {
            let handle = self.backend.create()?;
            if let Err(error) = self.backend.set(&handle, PowerRequestSystemRequired) {
                self.backend.close(handle);
                return Err(error);
            }
            if let Err(error) = self.backend.set(&handle, PowerRequestDisplayRequired) {
                self.backend.clear(&handle, PowerRequestSystemRequired);
                self.backend.close(handle);
                return Err(error);
            }
            self.request = Some(handle);
        }
        self.sessions.insert(session);
        Ok(())
    }

    fn release(&mut self, session: Uuid) -> bool {
        if !self.sessions.remove(&session) {
            return false;
        }
        if self.sessions.is_empty() {
            if let Some(handle) = self.request.take() {
                self.backend.clear(&handle, PowerRequestDisplayRequired);
                self.backend.clear(&handle, PowerRequestSystemRequired);
                self.backend.close(handle);
            }
        }
        true
    }
}

static HOLDERS: LazyLock<Mutex<Holders<WindowsPower>>> =
    LazyLock::new(|| Mutex::new(Holders::new(WindowsPower)));
static LOG_FAILURE: Once = Once::new();

/// Either the async session or its capture thread can end this session's request.
pub(crate) struct Session<'a, B: Backend> {
    holders: &'a Mutex<Holders<B>>,
    id: Uuid,
    closed: Arc<AtomicBool>,
}

pub(crate) fn session() -> Session<'static, WindowsPower> {
    Session::new(&HOLDERS)
}

impl<B: Backend> Clone for Session<'_, B> {
    fn clone(&self) -> Self {
        Self { holders: self.holders, id: self.id, closed: self.closed.clone() }
    }
}

impl<'a, B: Backend> Session<'a, B> {
    fn new(holders: &'a Mutex<Holders<B>>) -> Self {
        Self { holders, id: Uuid::new_v4(), closed: Arc::new(AtomicBool::new(false)) }
    }

    pub(crate) fn set(&self, on: bool) -> bool {
        if !on {
            self.release();
            return false;
        }
        let mut holders = self.holders.lock().unwrap();
        if self.closed.load(Ordering::Relaxed) {
            return false;
        }
        match holders.acquire(self.id) {
            Ok(()) => true,
            Err(error) => {
                LOG_FAILURE.call_once(|| tracing::warn!(%error, "could not keep the remote machine awake"));
                false
            }
        }
    }

    pub(crate) fn release(&self) -> bool {
        self.holders.lock().unwrap().release(self.id)
    }

    pub(crate) fn is_held(&self) -> bool {
        self.holders.lock().unwrap().sessions.contains(&self.id)
    }

    pub(crate) fn close(&self) {
        let mut holders = self.holders.lock().unwrap();
        self.closed.store(true, Ordering::Relaxed);
        holders.release(self.id);
    }
}

impl<B: Backend> Drop for Session<'_, B> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
    }

    impl Fake {
        fn record(&mut self, call: &'static str) -> Result<()> {
            self.calls.push(call);
            if self.fail == Some(call) {
                return Err(windows::core::Error::from_hresult(windows::core::HRESULT(0x80004005u32 as i32)));
            }
            Ok(())
        }
    }

    impl Backend for Fake {
        type Handle = ();

        fn create(&mut self) -> Result<()> {
            self.record("create")
        }

        fn set(&mut self, _: &(), kind: POWER_REQUEST_TYPE) -> Result<()> {
            self.record(if kind == PowerRequestSystemRequired { "set system" } else { "set display" })
        }

        fn clear(&mut self, _: &(), kind: POWER_REQUEST_TYPE) {
            let _ = self.record(if kind == PowerRequestSystemRequired { "clear system" } else { "clear display" });
        }

        fn close(&mut self, _: ()) {
            let _ = self.record("close");
        }
    }

    #[test]
    fn sessions_share_one_request_and_acquisition_is_idempotent() {
        let mut holders = Holders::new(Fake::default());
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        holders.acquire(first).unwrap();
        holders.acquire(first).unwrap();
        holders.acquire(second).unwrap();
        assert!(holders.release(first));
        assert!(!holders.release(first));
        assert_eq!(holders.backend.calls, ["create", "set system", "set display"]);
        assert!(holders.release(second));
        assert_eq!(
            holders.backend.calls,
            ["create", "set system", "set display", "clear display", "clear system", "close"],
        );
        assert!(holders.request.is_none());
    }

    #[test]
    fn dropping_either_session_guard_releases_and_prevents_reacquisition() {
        let holders = Mutex::new(Holders::new(Fake::default()));
        let session = Session::new(&holders);
        let capture = session.clone();
        assert!(session.set(true));
        drop(capture);
        assert!(!session.set(true));
        assert_eq!(
            holders.lock().unwrap().backend.calls,
            ["create", "set system", "set display", "clear display", "clear system", "close"],
        );
    }

    #[test]
    fn release_allows_later_acquisition_and_close_prevents_it() {
        let holders = Mutex::new(Holders::new(Fake::default()));
        let session = Session::new(&holders);
        assert!(session.set(true));

        assert!(session.release());
        assert!(!session.is_held());
        assert_eq!(holders.lock().unwrap().backend.calls.last(), Some(&"close"));

        assert!(session.set(true));
        session.close();
        assert!(!session.is_held());
        assert!(!session.set(true));
        assert_eq!(holders.lock().unwrap().backend.calls.last(), Some(&"close"));
    }

    #[test]
    fn acquisition_failures_undo_partial_requests() {
        for (fail, expected) in [
            ("create", &["create"][..]),
            ("set system", &["create", "set system", "close"][..]),
            ("set display", &["create", "set system", "set display", "clear system", "close"][..]),
        ] {
            let mut holders = Holders::new(Fake { fail: Some(fail), ..Fake::default() });
            let session = Uuid::new_v4();
            assert!(holders.acquire(session).is_err());
            assert_eq!(holders.backend.calls.as_slice(), expected);
            assert!(holders.request.is_none());
            assert!(!holders.release(session));
            holders.backend.fail = None;
            holders.acquire(session).unwrap();
            assert!(holders.release(session));
        }
    }
}
