//! Privilege separation for `sudo warren up` on macOS.
//!
//! Creating a utun interface and changing routes need root; nothing else
//! the client does does. So `warren up` opens the interface as root, forks
//! a small route helper that stays root, and runs everything else (TLS,
//! QUIC, HTTP, the device key) as the user who ran `sudo`, which also keeps
//! the client's state and keys the user's own. The helper only configures
//! the interface it created and adds or removes routes through it, never a
//! default route or a local range, and exits when the tunnel process does;
//! closing the interface removes every route through it.
//!
//! `fork`, `setgid`, `initgroups` and `setuid` are the only calls here that
//! need `unsafe`; each is a thin, checked wrapper, and the fork happens
//! before the process starts any thread.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;

use warren_core::bundle::IpNet;
use warren_core::utun;

/// The user `sudo` ran as, whom the tunnel process becomes.
#[derive(Debug, Clone)]
pub struct User {
    /// User ID.
    pub uid: libc::uid_t,
    /// Primary group ID.
    pub gid: libc::gid_t,
    /// Login name.
    pub name: String,
    /// Home directory.
    pub home: PathBuf,
}

/// Whether the process runs as root.
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The user behind `sudo`, from `SUDO_UID`; `None` when root itself ran
/// warren.
pub fn sudo_user() -> Result<Option<User>, String> {
    let Some(uid) = std::env::var("SUDO_UID").ok().filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    let uid: libc::uid_t = uid
        .parse()
        .map_err(|_| format!("SUDO_UID={uid} is not a user ID"))?;
    if uid == 0 {
        return Ok(None);
    }
    lookup(uid).map(Some)
}

fn lookup(uid: libc::uid_t) -> Result<User, String> {
    // SAFETY: an all-zero passwd is a valid value to be overwritten.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pw`, `buf` (of the length passed) and `result` are valid
    // for writes for the duration of the call; on success `result` points
    // at `pw`, whose strings point into `buf`.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return Err(format!("no user with ID {uid}"));
    }
    // SAFETY: on success `pw_name` and `pw_dir` are NUL-terminated strings
    // inside `buf`, which is still alive.
    let (name, home) = unsafe {
        (
            CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned(),
            CStr::from_ptr(pw.pw_dir).to_string_lossy().into_owned(),
        )
    };
    Ok(User {
        uid,
        gid: pw.pw_gid,
        name,
        home: PathBuf::from(home),
    })
}

/// Becomes `user` for good: its groups, then its group and user IDs, and
/// checks that root cannot be regained.
pub fn drop_to(user: &User) -> Result<(), String> {
    let name = CString::new(user.name.as_str()).map_err(|_| "user name has a NUL byte")?;
    // SAFETY: plain system calls with valid arguments; each result is
    // checked. initgroups takes the gid as a C int on macOS.
    unsafe {
        if libc::initgroups(name.as_ptr(), user.gid as libc::c_int) != 0 {
            return Err(format!("initgroups: {}", std::io::Error::last_os_error()));
        }
        if libc::setgid(user.gid) != 0 {
            return Err(format!("setgid: {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(user.uid) != 0 {
            return Err(format!("setuid: {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(0) == 0 || libc::geteuid() == 0 {
            return Err("still able to regain root after dropping privileges".into());
        }
    }
    // SAFETY: setting environment variables before any thread exists.
    unsafe {
        std::env::set_var("HOME", &user.home);
        std::env::set_var("USER", &user.name);
        std::env::set_var("LOGNAME", &user.name);
    }
    Ok(())
}

/// What the route helper may be asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Set the MTU and the tunnel addresses.
    Configure {
        /// The tunnel MTU.
        mtu: u16,
        /// The device's tunnel addresses.
        addresses: Vec<IpAddr>,
    },
    /// Route a range into the tunnel.
    Add(IpNet),
    /// Remove a route.
    Delete(IpNet),
}

impl Request {
    /// The request as one line.
    pub fn encode(&self) -> String {
        match self {
            Request::Configure { mtu, addresses } => {
                let a: Vec<String> = addresses.iter().map(ToString::to_string).collect();
                format!("configure {mtu} {}\n", a.join(" "))
            }
            Request::Add(n) => format!("add {n}\n"),
            Request::Delete(n) => format!("delete {n}\n"),
        }
    }

    /// Parses and checks a request line: the MTU at least the floor, real
    /// unicast tunnel addresses, and routes that are neither default nor
    /// local, so even a compromised tunnel process cannot use the helper
    /// to capture all traffic or loopback.
    pub fn decode(line: &str) -> Result<Request, String> {
        let mut words = line.split_whitespace();
        let req = match words.next() {
            Some("configure") => {
                let mtu: u16 = words
                    .next()
                    .and_then(|m| m.parse().ok())
                    .filter(|m| (warren_core::params::TUNNEL_MTU_FLOOR..=9000).contains(m))
                    .ok_or("bad MTU")?;
                let addresses = words
                    .map(|a| a.parse::<IpAddr>().map_err(|_| format!("bad address {a}")))
                    .collect::<Result<Vec<_>, _>>()?;
                if addresses.is_empty() || addresses.len() > 2 {
                    return Err("one IPv4 and one IPv6 address at most".into());
                }
                if addresses
                    .iter()
                    .any(|a| a.is_loopback() || a.is_multicast() || a.is_unspecified())
                {
                    return Err("not a tunnel address".into());
                }
                return Ok(Request::Configure { mtu, addresses });
            }
            Some("add") => Request::Add(route(words.next())?),
            Some("delete") => Request::Delete(route(words.next())?),
            _ => return Err("unknown request".into()),
        };
        if words.next().is_some() {
            return Err("trailing words".into());
        }
        Ok(req)
    }
}

fn route(word: Option<&str>) -> Result<IpNet, String> {
    let net: IpNet = word
        .ok_or("missing range")?
        .parse()
        .map_err(|e: warren_core::bundle::BundleError| e.to_string())?;
    let local: [&str; 6] = [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::1/128",
        "fe80::/10",
    ];
    let reserved = local
        .iter()
        .chain(&["ff00::/8"])
        .map(|r| r.parse::<IpNet>().expect("valid range"))
        .any(|r| r.covers(&net));
    if reserved || warren_client::engine::too_broad(&net) {
        return Err(format!("{net} is not an app range"));
    }
    Ok(net)
}

/// Runs the route helper until the tunnel process goes away. Called in the
/// forked child, which stays root and keeps only this socket.
pub fn serve(interface: &str, socket: UnixStream) -> ! {
    // The terminal's Ctrl-C reaches the whole process group; the helper
    // leaves stopping to the tunnel process and exits when it does.
    // SAFETY: setting signal dispositions to SIG_IGN is always sound.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let mut out = match socket.try_clone() {
        Ok(s) => s,
        // SAFETY: _exit ends the forked child without running the parent's
        // exit handlers.
        Err(_) => unsafe { libc::_exit(1) },
    };
    for line in BufReader::new(socket).lines() {
        let Ok(line) = line else { break };
        let result = Request::decode(&line).and_then(|req| {
            match req {
                Request::Configure { mtu, addresses } => {
                    let (v4, v6) = utun::split_addresses(&addresses);
                    utun::configure(interface, mtu, v4, v6)
                }
                Request::Add(n) => utun::add_route(interface, &n),
                Request::Delete(n) => utun::delete_route(interface, &n),
            }
            .map_err(|e| e.to_string())
        });
        let reply = match result {
            Ok(()) => "ok\n".to_owned(),
            Err(e) => format!("error {}\n", e.replace('\n', " ")),
        };
        if out.write_all(reply.as_bytes()).is_err() {
            break;
        }
    }
    // SAFETY: as above.
    unsafe { libc::_exit(0) }
}

/// The tunnel process's handle on the route helper.
#[derive(Debug)]
pub struct Helper {
    stream: Mutex<BufReader<UnixStream>>,
}

impl Helper {
    /// Wraps the tunnel process's end of the socket.
    pub fn new(stream: UnixStream) -> Helper {
        Helper {
            stream: Mutex::new(BufReader::new(stream)),
        }
    }

    /// Asks the helper and waits for its answer.
    pub fn ask(&self, req: &Request) -> Result<(), String> {
        let mut s = self.stream.lock().map_err(|_| "helper lock poisoned")?;
        s.get_mut()
            .write_all(req.encode().as_bytes())
            .map_err(|e| format!("the route helper is gone: {e}"))?;
        let mut reply = String::new();
        s.read_line(&mut reply)
            .map_err(|e| format!("the route helper is gone: {e}"))?;
        match reply.trim_end().split_once(' ') {
            None if reply.trim_end() == "ok" => Ok(()),
            Some(("error", why)) => Err(why.to_owned()),
            _ => Err("the route helper is gone".into()),
        }
    }
}

/// Which side of the fork this is.
pub enum Forked {
    /// The tunnel process, with its end of the helper socket.
    Parent(UnixStream),
    /// The helper, which never returns from [`serve`].
    Child(UnixStream),
}

/// Forks the route helper. Call before starting any thread.
pub fn fork_helper() -> Result<Forked, String> {
    let (parent, child) =
        UnixStream::pair().map_err(|e| format!("cannot create the helper socket: {e}"))?;
    // SAFETY: the process has a single thread here (no runtime has started),
    // so the child may run arbitrary code after fork.
    match unsafe { libc::fork() } {
        -1 => Err(format!("fork: {}", std::io::Error::last_os_error())),
        0 => {
            drop(parent);
            Ok(Forked::Child(child))
        }
        _ => {
            drop(child);
            Ok(Forked::Parent(parent))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        for r in [
            Request::Configure {
                mtu: 1280,
                addresses: vec!["100.96.0.2".parse().unwrap(), "fd00::2".parse().unwrap()],
            },
            Request::Add("10.77.0.0/24".parse().unwrap()),
            Request::Delete("fd77::/64".parse().unwrap()),
        ] {
            assert_eq!(Request::decode(r.encode().trim_end()).unwrap(), r);
        }
    }

    #[test]
    fn the_helper_refuses_what_is_not_an_app_route() {
        for bad in [
            "add 0.0.0.0/0",
            "add ::/0",
            "add 127.0.0.0/8",
            "add 127.0.0.1/32",
            "add 0.0.0.0/1",
            "add fe80::/64",
            "add ff02::/16",
            "add 224.0.0.0/8",
            "add 10.0.0.1/8",
            "add 10.0.0.0/8 extra",
            "configure 1200 100.96.0.2",
            "configure 1280",
            "configure 1280 127.0.0.1",
            "configure 1280 1.1.1.1 fd00::1 fd00::2",
            "route 10.0.0.0/8",
            "",
        ] {
            assert!(Request::decode(bad).is_err(), "{bad}");
        }
        assert!(Request::decode("add 128.0.0.0/1").is_err());
        assert!(Request::decode("add 2000::/3").is_err());
        assert!(Request::decode("add 10.0.0.0/8").is_ok());
        assert!(Request::decode("add fd00::/8").is_ok());
    }

    #[test]
    fn the_current_user_is_found() {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let me = lookup(uid).unwrap();
        assert_eq!(me.uid, uid);
        assert!(!me.name.is_empty());
    }
}
