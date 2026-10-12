//! The C ABI of the client core, declared in `include/warren.h`, which the
//! native shells link as a static library: the macOS menu-bar app signs in
//! and shows status through it, and the packet tunnel provider runs the
//! tunnel engine through it, handing packets across. Everything behind it
//! is [`warren_client`]; this crate only converts between C and Rust.
//!
//! Each function checks its pointers for NULL and its strings for UTF-8,
//! and never unwinds across the boundary.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_void};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use warren_client::control::{Account, OrgTrust};
use warren_client::engine::{Engine, EngineOptions, NetworkSettings, Platform, Status};
use warren_client::signin::{self, SignInOptions};
use warren_client::state::Store;

/// `warren_open_url_fn`.
pub type OpenUrlFn = extern "C" fn(ctx: *mut c_void, url: *const c_char);
/// `warren_deliver_fn`.
pub type DeliverFn = extern "C" fn(ctx: *mut c_void, packet: *const u8, len: usize);
/// `warren_settings_fn`.
pub type SettingsFn = extern "C" fn(ctx: *mut c_void, settings_json: *const c_char) -> bool;
/// `warren_event_fn`.
pub type EventFn = extern "C" fn(ctx: *mut c_void, event_json: *const c_char);

/// The shell's context pointer.
#[derive(Clone, Copy)]
struct Ctx(*mut c_void);

// SAFETY: warren.h requires the shell to accept callbacks with this context
// from any thread, concurrently, for as long as they are registered.
unsafe impl Send for Ctx {}
// SAFETY: as above.
unsafe impl Sync for Ctx {}

fn owned(s: String) -> *mut c_char {
    // Interior NUL bytes cannot occur in JSON or in the messages built
    // here; replace them rather than fail if one ever does.
    CString::new(s.replace('\0', " "))
        .expect("no NUL bytes")
        .into_raw()
}

fn error_json(reason: &str, message: &str) -> *mut c_char {
    owned(json!({ "error": message, "reason": reason }).to_string())
}

/// Reads a C string argument; `None` for NULL or invalid UTF-8.
///
/// # Safety
/// `p` is NULL or a valid NUL-terminated string that outlives the call.
unsafe fn arg<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("warren")
        .build()
        .map_err(|e| e.to_string())
}

fn catch<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe, fallback: T) -> T {
    std::panic::catch_unwind(f).unwrap_or(fallback)
}

/// The version string.
#[unsafe(no_mangle)]
pub extern "C" fn warren_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Releases a string this library returned.
///
/// # Safety
/// `s` is NULL or a string this library returned and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warren_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` came from CString::into_raw in this library.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// The saved state's status, as JSON.
///
/// # Safety
/// `home` is NULL or a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warren_status_json(home: *const c_char) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantee.
    let Some(home) = (unsafe { arg(home) }) else {
        return error_json("invalid_argument", "no state directory given");
    };
    let home = PathBuf::from(home);
    catch(
        move || {
            let Some(store) = Store::existing(&home) else {
                return error_json("not_signed_in", "not signed in");
            };
            match Account::load(&store) {
                Ok(a) => owned(serde_json::to_string(&Status::offline(&a)).unwrap_or_default()),
                Err(e) => error_json("not_signed_in", &e),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Signs in and enrolls the device.
///
/// # Safety
/// `home` and `org_url` are valid NUL-terminated strings; `fingerprint` is
/// NULL or one; `open_url` is a valid function that accepts `ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warren_login(
    home: *const c_char,
    org_url: *const c_char,
    fingerprint: *const c_char,
    timeout_secs: u32,
    open_url: OpenUrlFn,
    ctx: *mut c_void,
) -> *mut c_char {
    // SAFETY: forwarded from the caller's guarantees.
    let (home, org, pin) = unsafe { (arg(home), arg(org_url), arg(fingerprint)) };
    let (Some(home), Some(org)) = (home, org) else {
        return error_json(
            "invalid_argument",
            "a state directory and an organization URL are required",
        );
    };
    let trust = match pin {
        Some(p) => match OrgTrust::pinned(p) {
            Ok(t) => t,
            Err(e) => return error_json("invalid_argument", &e),
        },
        None => OrgTrust::System,
    };
    let (home, org) = (PathBuf::from(home), org.to_owned());
    let ctx = Ctx(ctx);
    catch(
        move || {
            let result = (|| -> Result<serde_json::Value, String> {
                let store = Store::open(&home)?;
                let opts = SignInOptions {
                    org_url: org,
                    trust,
                    key_storage: None,
                    fresh: false,
                    timeout: Duration::from_secs(u64::from(timeout_secs.max(1))),
                };
                let done = runtime()?.block_on(signin::sign_in(&store, opts, move |url| {
                    if let Ok(c) = CString::new(url) {
                        let ctx = ctx;
                        open_url(ctx.0, c.as_ptr());
                    }
                }))?;
                Ok(json!({
                    "org": done.account.profile.org_url,
                    "user": done.account.profile.user,
                    "device": done.device,
                    "key_storage": done.account.key.storage().describe(),
                    "key_note": done.key_note,
                    "certificate": done.certificate.map(|c| c.times),
                    "pending": done.pending.map(|e| json!({ "reason": e.reason, "detail": e.detail })),
                }))
            })();
            match result {
                Ok(v) => owned(v.to_string()),
                Err(e) => error_json("sign_in_failed", &e),
            }
        },
        std::ptr::null_mut(),
    )
}

/// The shell, as the engine sees it.
struct Shell {
    ctx: Ctx,
    deliver: DeliverFn,
    settings: SettingsFn,
}

impl Platform for Shell {
    fn deliver(&self, packet: &[u8]) {
        (self.deliver)(self.ctx.0, packet.as_ptr(), packet.len());
    }

    fn apply(&self, s: &NetworkSettings) -> Result<Vec<String>, String> {
        let text = serde_json::to_string(s).map_err(|e| e.to_string())?;
        let c = CString::new(text).map_err(|e| e.to_string())?;
        if (self.settings)(self.ctx.0, c.as_ptr()) {
            Ok(Vec::new())
        } else {
            Err("the system did not accept the tunnel's network settings".into())
        }
    }
}

/// A running engine and the runtime it runs on.
pub struct WarrenTunnel {
    runtime: tokio::runtime::Runtime,
    engine: Arc<Engine>,
    events: tokio::task::JoinHandle<()>,
}

/// Starts the tunnel engine.
///
/// # Safety
/// `home` is a valid NUL-terminated string; the callbacks are valid
/// functions that accept `ctx` from any thread until
/// [`warren_tunnel_stop`] returns; `error` is NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warren_tunnel_start(
    home: *const c_char,
    ctx: *mut c_void,
    deliver: DeliverFn,
    settings: SettingsFn,
    event: EventFn,
    error: *mut *mut c_char,
) -> *mut WarrenTunnel {
    let fail = |message: String| {
        if !error.is_null() {
            // SAFETY: the caller guarantees `error` is valid for a write.
            unsafe { *error = owned(message) };
        }
        std::ptr::null_mut()
    };
    // SAFETY: forwarded from the caller's guarantee.
    let Some(home) = (unsafe { arg(home) }) else {
        return fail("no state directory given".into());
    };
    let home = PathBuf::from(home);
    let ctx = Ctx(ctx);
    let started = catch(
        move || -> Result<WarrenTunnel, String> {
            let runtime = runtime()?;
            let store = Store::open(&home)?;
            let account = Account::load(&store)?;
            let shell = Arc::new(Shell {
                ctx,
                deliver,
                settings,
            });
            let engine = Arc::new(
                runtime
                    .block_on(Engine::start(account, shell, EngineOptions::default()))
                    .map_err(|e| e.message)?,
            );
            let mut rx = engine.subscribe();
            let events = runtime.spawn(async move {
                use tokio::sync::broadcast::error::RecvError;
                loop {
                    let e = match rx.recv().await {
                        Ok(e) => e,
                        // A shell that fell behind misses some events, not
                        // all later ones.
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => return,
                    };
                    if let Ok(c) = CString::new(serde_json::to_string(&e).unwrap_or_default()) {
                        let ctx = ctx;
                        event(ctx.0, c.as_ptr());
                    }
                }
            });
            Ok(WarrenTunnel {
                runtime,
                engine,
                events,
            })
        },
        Err("the client core failed unexpectedly".into()),
    );
    match started {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(e) => fail(e),
    }
}

/// Gives the engine a packet.
///
/// # Safety
/// `tunnel` is NULL or a live tunnel; `packet` is valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warren_tunnel_send(
    tunnel: *mut WarrenTunnel,
    packet: *const u8,
    len: usize,
) {
    if tunnel.is_null() || packet.is_null() {
        return;
    }
    // SAFETY: the caller guarantees a live tunnel and a readable packet.
    let (t, p) = unsafe { (&*tunnel, std::slice::from_raw_parts(packet, len)) };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| t.engine.send(p)));
}

/// The engine's status, as JSON.
///
/// # Safety
/// `tunnel` is NULL or a live tunnel.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warren_tunnel_status_json(tunnel: *mut WarrenTunnel) -> *mut c_char {
    if tunnel.is_null() {
        return error_json("invalid_argument", "no tunnel given");
    }
    // SAFETY: the caller guarantees a live tunnel.
    let t = unsafe { &*tunnel };
    let status = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| t.engine.status()));
    match status {
        Ok(s) => owned(serde_json::to_string(&s).unwrap_or_default()),
        Err(_) => error_json("internal", "the client core failed unexpectedly"),
    }
}

/// Stops the engine and frees it.
///
/// # Safety
/// `tunnel` is NULL or a live tunnel, which this call frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warren_tunnel_stop(tunnel: *mut WarrenTunnel) {
    if tunnel.is_null() {
        return;
    }
    // SAFETY: the caller hands back ownership of a tunnel this library
    // allocated.
    let t = unsafe { Box::from_raw(tunnel) };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        t.runtime.block_on(t.engine.stop());
        t.events.abort();
        t.runtime.shutdown_timeout(Duration::from_secs(2));
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(s: *mut c_char) -> serde_json::Value {
        assert!(!s.is_null());
        // SAFETY: a string this library returned.
        let text = unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_owned();
        // SAFETY: as above, freed once.
        unsafe { warren_string_free(s) };
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn the_version_is_the_package_version() {
        // SAFETY: a static NUL-terminated string.
        let v = unsafe { CStr::from_ptr(warren_version()) };
        assert_eq!(v.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn missing_state_is_explained() {
        let home = CString::new("/nonexistent/warren-ffi-test").unwrap();
        // SAFETY: a valid string.
        let v = take(unsafe { warren_status_json(home.as_ptr()) });
        assert_eq!(v["reason"], "not_signed_in");
        // SAFETY: NULL is allowed.
        let v = take(unsafe { warren_status_json(std::ptr::null()) });
        assert_eq!(v["reason"], "invalid_argument");

        extern "C" fn deliver(_: *mut c_void, _: *const u8, _: usize) {}
        extern "C" fn settings(_: *mut c_void, _: *const c_char) -> bool {
            true
        }
        extern "C" fn event(_: *mut c_void, _: *const c_char) {}
        let mut error = std::ptr::null_mut();
        let dir = std::env::temp_dir().join(format!(
            "warren-ffi-{}",
            warren_core::keys::hex(&warren_core::keys::random_bytes::<6>().unwrap())
        ));
        let home = CString::new(dir.to_str().unwrap()).unwrap();
        // SAFETY: valid strings and functions; `error` is writable.
        let t = unsafe {
            warren_tunnel_start(
                home.as_ptr(),
                std::ptr::null_mut(),
                deliver,
                settings,
                event,
                &mut error,
            )
        };
        assert!(t.is_null());
        // SAFETY: the error string this library set.
        let message = unsafe { CStr::from_ptr(error) }
            .to_str()
            .unwrap()
            .to_owned();
        // SAFETY: freed once.
        unsafe { warren_string_free(error) };
        assert!(message.contains("warren login"), "{message}");
        // SAFETY: NULL tunnels are ignored.
        unsafe {
            warren_tunnel_send(std::ptr::null_mut(), std::ptr::null(), 0);
            warren_tunnel_stop(std::ptr::null_mut());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
