//! The Linux TUN device (kernel forwarding mode, docs/design.md section 10)
//! and the interface, route and NAT setup around it.
//!
//! Opening the device needs one `ioctl`; each call is a thin, checked
//! wrapper. Interface addresses,
//! routes and NAT are configured through the system's `ip` and `nft`
//! commands with fixed argument lists (no shell), which keeps netlink and
//! nftables libraries out of the dependency closure.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use tokio::io::unix::AsyncFd;

use crate::bundle::IpNet;

const TUNSETIFF: u64 = 0x4004_54ca;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFNAMSIZ: usize = 16;

/// A TUN device carrying raw IP packets (no packet information header).
#[derive(Debug)]
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl Tun {
    /// Creates (or attaches to) the TUN interface `name`. Needs
    /// `CAP_NET_ADMIN`.
    pub fn create(name: &str) -> io::Result<Tun> {
        if name.is_empty()
            || name.len() >= IFNAMSIZ
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        let path = CString::new("/dev/net/tun").expect("no NUL");
        // SAFETY: `path` is a valid NUL-terminated string; `open` has no
        // other preconditions and returns -1 on failure, checked below.
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly opened descriptor that nothing else
        // owns; `OwnedFd` closes it exactly once.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // struct ifreq: the name in the first 16 bytes, then a union whose
        // first member is the short `ifr_flags`. 40 bytes covers the union
        // on every Linux ABI.
        let mut ifr = [0u8; 40];
        ifr[..name.len()].copy_from_slice(name.as_bytes());
        ifr[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
        // SAFETY: TUNSETIFF reads and writes a `struct ifreq`, and `ifr` is
        // a properly sized, writable buffer that outlives the call.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = ifr[..IFNAMSIZ]
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(IFNAMSIZ);
        let name = String::from_utf8_lossy(&ifr[..end]).into_owned();
        Ok(Tun {
            fd: AsyncFd::new(fd)?,
            name,
        })
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one packet.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let result = guard.try_io(|fd| {
                // SAFETY: `buf` is a valid writable region of `buf.len()`
                // bytes for the duration of the call.
                let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes one packet without waiting; a full device queue drops it, as
    /// a congested link would.
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        // SAFETY: `packet` is a valid readable region of `packet.len()`
        // bytes for the duration of the call.
        let n = unsafe {
            libc::write(
                self.fd.get_ref().as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }
}

fn run(program: &str, args: &[&str], input: Option<&str>) -> io::Result<()> {
    use std::io::Write;
    let mut cmd = Command::new(program);
    cmd.args(args);
    if input.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{program}: {e}")))?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Sets the MTU, brings the interface up, adds addresses, and routes
/// `routes` through it.
pub fn configure(name: &str, mtu: u16, addrs: &[IpNet], routes: &[IpNet]) -> io::Result<()> {
    run(
        "ip",
        &["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"],
        None,
    )?;
    for a in addrs {
        let family = if a.addr.is_ipv4() { "-4" } else { "-6" };
        run(
            "ip",
            &[family, "addr", "replace", &a.to_string(), "dev", name],
            None,
        )?;
    }
    for r in routes {
        let family = if r.addr.is_ipv4() { "-4" } else { "-6" };
        run(
            "ip",
            &[family, "route", "replace", &r.to_string(), "dev", name],
            None,
        )?;
    }
    Ok(())
}

/// The nftables table warren owns for source NAT.
pub const NAT_TABLE: &str = "warren";

/// Enables forwarding and masquerades traffic from `sources` (the device
/// pools) leaving through any interface but the tunnel, in a table warren
/// owns and replaces as a whole.
pub fn enable_nat(tun: &str, sources: &[IpNet]) -> io::Result<()> {
    let v4: Vec<String> = sources
        .iter()
        .filter(|s| s.addr.is_ipv4())
        .map(ToString::to_string)
        .collect();
    let v6: Vec<String> = sources
        .iter()
        .filter(|s| s.addr.is_ipv6())
        .map(ToString::to_string)
        .collect();
    if !v4.is_empty() {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    }
    if !v6.is_empty() {
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    }
    disable_nat();
    let mut rules = String::new();
    for (family, saddr, set) in [("ip", "ip", &v4), ("ip6", "ip6", &v6)] {
        if set.is_empty() {
            continue;
        }
        rules.push_str(&format!(
            "table {family} {NAT_TABLE} {{\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    {saddr} saddr {{ {} }} oifname != \"{tun}\" masquerade\n  }}\n}}\n",
            set.join(", ")
        ));
    }
    run("nft", &["-f", "-"], Some(&rules))
}

/// Removes warren's NAT table, ignoring a missing one.
pub fn disable_nat() {
    for family in ["ip", "ip6"] {
        let _ = run("nft", &["delete", "table", family, NAT_TABLE], None);
    }
}
