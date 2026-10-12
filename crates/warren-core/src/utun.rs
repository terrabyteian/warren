//! The macOS utun device: the packet tunnel of the command-line client
//! (docs/macos.md), and the interface address and route setup around it.
//! The menu-bar app's NetworkExtension gets its packets from the system
//! instead and needs none of this.
//!
//! Opening a utun interface takes a kernel control socket, one `ioctl` to
//! look up the utun control and a `connect`, as root; reading and writing
//! packets take `readv` and `writev`, because every packet carries a 4-byte
//! address-family header. Each call is a thin, checked wrapper. Addresses
//! and routes are configured through the system's `ifconfig` and `route`
//! commands with fixed argument lists (no shell), as the Linux device does
//! with `ip`.
#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use tokio::io::unix::AsyncFd;

use crate::bundle::IpNet;

/// The kernel control that creates utun interfaces.
const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control";

/// Where the system's network tools live; full paths, so `PATH` under
/// `sudo` cannot substitute them.
const IFCONFIG: &str = "/sbin/ifconfig";
const ROUTE: &str = "/sbin/route";

/// An open utun interface that is not yet registered with the async
/// runtime: it can be opened before the runtime starts (and before the
/// process gives up root) and moved into it later.
#[derive(Debug)]
pub struct UtunHandle {
    fd: OwnedFd,
    name: String,
}

impl UtunHandle {
    /// The interface name, for example `utun4`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Registers the device with the current tokio runtime.
    pub fn into_async(self) -> io::Result<Utun> {
        Ok(Utun {
            fd: AsyncFd::new(self.fd)?,
            name: self.name,
        })
    }
}

/// Creates a new utun interface with the next free unit number. Needs root.
pub fn open() -> io::Result<UtunHandle> {
    // SAFETY: plain socket(2) call; the result is checked below.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly opened descriptor that nothing else owns;
    // `OwnedFd` closes it exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; libc::MAX_KCTL_NAME],
    };
    for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL) {
        *dst = *src as libc::c_char;
    }
    // SAFETY: CTLIOCGINFO reads the name from and writes the ID into a
    // `struct ctl_info`, which `info` is, and it outlives the call.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let addr = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        // Unit 0 asks the kernel for the next free utun unit.
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: `addr` is a valid `sockaddr_ctl` of the length passed, and
    // outlives the call.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut len = name.len() as libc::socklen_t;
    // SAFETY: UTUN_OPT_IFNAME writes at most `len` bytes of the interface
    // name into `name`, which is writable for that length.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    let name = String::from_utf8_lossy(&name[..end]).into_owned();
    set_nonblocking(&fd)?;
    Ok(UtunHandle { fd, name })
}

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own, with integer arguments only.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above; FD_CLOEXEC keeps the device out of child processes
    // such as `route`.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The address-family header a utun packet starts with: `AF_INET` or
/// `AF_INET6` as a 32-bit big-endian integer.
pub fn family_header(packet: &[u8]) -> Option<[u8; 4]> {
    let af = match packet.first()? >> 4 {
        4 => libc::AF_INET,
        6 => libc::AF_INET6,
        _ => return None,
    };
    Some((af as u32).to_be_bytes())
}

/// A utun interface registered with the async runtime. Dropping it closes
/// the descriptor, which destroys the interface and every route through it.
#[derive(Debug)]
pub struct Utun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl Utun {
    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one IP packet into `buf`, without its address-family header.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let result = guard.try_io(|fd| {
                let mut header = [0u8; 4];
                let iov = [
                    libc::iovec {
                        iov_base: header.as_mut_ptr().cast(),
                        iov_len: header.len(),
                    },
                    libc::iovec {
                        iov_base: buf.as_mut_ptr().cast(),
                        iov_len: buf.len(),
                    },
                ];
                // SAFETY: both iovecs point at writable buffers of the
                // stated lengths that outlive the call.
                let n = unsafe { libc::readv(fd.as_raw_fd(), iov.as_ptr(), 2) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok((n as usize).saturating_sub(header.len()))
                }
            });
            match result {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes one IP packet without waiting; a full device queue drops it,
    /// as a congested link would.
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        let Some(header) = family_header(packet) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an IPv4 or IPv6 packet",
            ));
        };
        let iov = [
            libc::iovec {
                iov_base: header.as_ptr().cast_mut().cast(),
                iov_len: header.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast(),
                iov_len: packet.len(),
            },
        ];
        // SAFETY: both iovecs point at readable buffers of the stated
        // lengths that outlive the call; writev does not write through
        // them.
        let n = unsafe { libc::writev(self.fd.get_ref().as_raw_fd(), iov.as_ptr(), 2) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(e.kind(), io::ErrorKind::WouldBlock)
                || e.raw_os_error() == Some(libc::ENOBUFS)
            {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let out = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("{program}: {e}")))?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Whether `name` looks like a utun interface, so the route helper never
/// touches any other interface.
pub fn is_utun_name(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|n| !n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit()))
}

fn check_name(name: &str) -> io::Result<()> {
    if is_utun_name(name) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a utun interface"),
        ))
    }
}

/// Sets the MTU, brings the interface up and gives it the device's tunnel
/// addresses as point-to-point host addresses.
pub fn configure(
    name: &str,
    mtu: u16,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
) -> io::Result<()> {
    check_name(name)?;
    run(IFCONFIG, &[name, "mtu", &mtu.to_string(), "up"])?;
    if let Some(a) = v4 {
        let a = a.to_string();
        run(IFCONFIG, &[name, "inet", &format!("{a}/32"), &a, "alias"])?;
    }
    if let Some(a) = v6 {
        run(
            IFCONFIG,
            &[name, "inet6", &a.to_string(), "prefixlen", "128", "alias"],
        )?;
    }
    Ok(())
}

/// The arguments of `route` for adding or deleting `net` through `name`.
pub fn route_args(add: bool, name: &str, net: &IpNet) -> Vec<String> {
    let family = if net.addr.is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    };
    vec![
        "-q".into(),
        "-n".into(),
        if add { "add" } else { "delete" }.into(),
        family.into(),
        net.to_string(),
        "-interface".into(),
        name.into(),
    ]
}

/// Routes `net` through the interface. Refuses a default route: warren
/// tunnels only internal apps (G14).
pub fn add_route(name: &str, net: &IpNet) -> io::Result<()> {
    check_name(name)?;
    if net.len < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a default route, or anything wider than a /8, never goes through warren",
        ));
    }
    let args = route_args(true, name, net);
    run(ROUTE, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Removes a route added with [`add_route`].
pub fn delete_route(name: &str, net: &IpNet) -> io::Result<()> {
    check_name(name)?;
    let args = route_args(false, name, net);
    run(ROUTE, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// The first tunnel address of each family in `addrs`.
pub fn split_addresses(addrs: &[IpAddr]) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let v4 = addrs.iter().find_map(|a| match a {
        IpAddr::V4(v) => Some(*v),
        IpAddr::V6(_) => None,
    });
    let v6 = addrs.iter().find_map(|a| match a {
        IpAddr::V6(v) => Some(*v),
        IpAddr::V4(_) => None,
    });
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_headers_follow_the_ip_version() {
        let v4 = crate::packet::udp(
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:2".parse().unwrap(),
            b"x",
        );
        let v6 = crate::packet::udp(
            "[fd00::1]:1".parse().unwrap(),
            "[fd00::2]:2".parse().unwrap(),
            b"x",
        );
        assert_eq!(family_header(&v4), Some([0, 0, 0, 2]));
        assert_eq!(family_header(&v6), Some([0, 0, 0, 30]));
        assert_eq!(family_header(&[0x50]), None);
        assert_eq!(family_header(&[]), None);
    }

    #[test]
    fn only_utun_interfaces_are_touched() {
        assert!(is_utun_name("utun0"));
        assert!(is_utun_name("utun12"));
        assert!(!is_utun_name("utun"));
        assert!(!is_utun_name("en0"));
        assert!(!is_utun_name("utun1;"));
        assert!(!is_utun_name("utun 1"));
        assert!(add_route("en0", &"10.0.0.0/8".parse().unwrap()).is_err());
    }

    #[test]
    fn routes_are_split_tunnel_only() {
        let err = add_route("utun9", &"0.0.0.0/0".parse().unwrap()).unwrap_err();
        assert!(err.to_string().contains("default route"));
        assert_eq!(
            route_args(true, "utun3", &"10.77.0.0/24".parse().unwrap()),
            [
                "-q",
                "-n",
                "add",
                "-inet",
                "10.77.0.0/24",
                "-interface",
                "utun3"
            ]
        );
        assert_eq!(
            route_args(false, "utun3", &"fd77::/64".parse().unwrap()),
            [
                "-q",
                "-n",
                "delete",
                "-inet6",
                "fd77::/64",
                "-interface",
                "utun3"
            ]
        );
    }
}
