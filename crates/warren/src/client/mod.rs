//! The command-line client (docs/macos.md): `warren login`, `warren up`,
//! `warren status`, `warren down` and `warren logout`.
//!
//! `login` signs in through the system browser and enrolls the device;
//! `sudo warren up` runs the tunnel on a utun interface until `warren down`
//! or Ctrl-C, printing every connection and block as it happens; `status`
//! asks a running `up` (or reads the saved state) and says what is going
//! on. Only `up` needs root, and it gives it up for everything but routes
//! (see [`privsep`]).

#[cfg(target_os = "macos")]
mod privsep;
#[cfg(target_os = "macos")]
mod up;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Arg, ArgAction, ArgMatches, Command};
use warren_client::control::{self, Account, OrgTrust};
use warren_client::engine::Status;
use warren_client::signin::{self, SignInOptions};
use warren_client::state::Store;
use warren_core::clock;

fn home_arg() -> Arg {
    Arg::new("home")
        .long("home")
        .value_name("DIR")
        .help("Where the client keeps its state [default: ~/Library/Application Support/warren, or $WARREN_HOME]")
}

/// The client's subcommands.
pub fn commands() -> Vec<Command> {
    vec![
        Command::new("login")
            .about("Sign in to your organization in the browser and enroll this device")
            .arg(
                Arg::new("org")
                    .required(true)
                    .value_name("ORG_URL")
                    .help("Your organization's warren URL, for example https://warren.example.com"),
            )
            .arg(
                Arg::new("fingerprint")
                    .long("fingerprint")
                    .value_name("SHA256")
                    .help("Trust the deployment root with this SHA-256 fingerprint instead of the system's trust store (warren admin deployment shows it)"),
            )
            .arg(
                Arg::new("no-browser")
                    .long("no-browser")
                    .action(ArgAction::SetTrue)
                    .help("Print the sign-in URL instead of opening a browser"),
            )
            .arg(
                Arg::new("fresh")
                    .long("fresh")
                    .action(ArgAction::SetTrue)
                    .help("Ask the identity provider to authenticate you afresh"),
            )
            .arg(
                Arg::new("timeout")
                    .long("timeout")
                    .value_name("SECONDS")
                    .default_value("300")
                    .value_parser(clap::value_parser!(u64))
                    .help("How long to wait for the browser"),
            )
            .arg(home_arg()),
        Command::new("up")
            .about("Connect: route your internal apps through warren (needs sudo on macOS)")
            .arg(
                Arg::new("transport")
                    .long("transport")
                    .value_name("MODE")
                    .default_value("auto")
                    .value_parser(["auto", "quic", "h2"])
                    .help("QUIC with the HTTP/2 fallback, or only one of them"),
            )
            .arg(
                Arg::new("log-level")
                    .long("log-level")
                    .value_name("LEVEL")
                    .default_value("error")
                    .help("Diagnostic logs on stderr, as JSON: error, warn, info, debug or trace"),
            )
            .arg(home_arg()),
        Command::new("status")
            .about("Show the sign-in, the device, the tunnels and recent blocks")
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help("Print the status as JSON"),
            )
            .arg(home_arg()),
        Command::new("down")
            .about("Disconnect a running warren up")
            .arg(home_arg()),
        Command::new("logout")
            .about("Forget the sign-in and delete this device's key")
            .arg(home_arg()),
    ]
}

/// The names of the client's subcommands.
#[cfg(test)]
pub const NAMES: [&str; 5] = ["login", "up", "status", "down", "logout"];

/// Runs a client subcommand; `None` if `name` is not one.
pub fn run(name: &str, m: &ArgMatches) -> Option<ExitCode> {
    let result = match name {
        "login" => login(m),
        "up" => up(m),
        "status" => status(m),
        "down" => down(m),
        "logout" => logout(m),
        _ => return None,
    };
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warren {name}: {e}");
            ExitCode::FAILURE
        }
    })
}

/// The state directory for this invocation.
fn home(m: &ArgMatches) -> Result<PathBuf, String> {
    match m.get_one::<String>("home") {
        Some(h) => Ok(PathBuf::from(h)),
        None => warren_client::state::default_home(),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("warren")
        .build()
        .map_err(|e| e.to_string())
}

/// When a Unix time is, for people.
pub fn when(secs: i64) -> String {
    let left = secs - clock::now_secs();
    let rel = if left >= 0 {
        format!("in {}", span(left))
    } else {
        format!("{} ago", span(-left))
    };
    format!("{} ({rel})", clock::rfc3339(secs))
}

fn span(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

/// Shows the sign-in page: `$BROWSER` if set, the system's browser
/// otherwise, and the URL in any case.
fn open_browser(url: &str, print_only: bool) {
    if print_only {
        eprintln!("Open this URL in a browser to sign in:\n\n  {url}\n");
        return;
    }
    let program = std::env::var("BROWSER")
        .ok()
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| {
            if cfg!(target_os = "macos") {
                "/usr/bin/open".into()
            } else {
                "xdg-open".into()
            }
        });
    eprintln!("Opening your browser to sign in. If it does not open, visit:\n\n  {url}\n");
    match std::process::Command::new(&program)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            // Reap it whenever it ends; sign-in does not wait for it.
            std::thread::spawn(move || child.wait());
        }
        Err(e) => eprintln!("(could not start {program}: {e})"),
    }
}

fn login(m: &ArgMatches) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if privsep::is_root() && std::env::var_os("SUDO_UID").is_some() {
        return Err(
            "run warren login without sudo: it signs you in as yourself, and only warren up needs sudo".into(),
        );
    }
    let dir = home(m)?;
    let store = Store::open(&dir)?;
    let org_url = m.get_one::<String>("org").expect("required").clone();
    let org = control::org_url(&org_url)?;
    if ask_up(&dir, "status").is_some()
        && store.profile().ok().flatten().is_some_and(|p| p.org_url != org)
    {
        return Err("warren is up for another organization; run `warren down` first".into());
    }
    let trust = match m.get_one::<String>("fingerprint") {
        Some(f) => OrgTrust::pinned(f)?,
        None => OrgTrust::System,
    };
    let opts = SignInOptions {
        org_url,
        trust,
        key_storage: None,
        fresh: m.get_flag("fresh"),
        timeout: Duration::from_secs(*m.get_one::<u64>("timeout").expect("defaulted")),
    };
    let print_only = m.get_flag("no-browser");
    let system_trust = opts.trust == OrgTrust::System;
    let done = runtime()?
        .block_on(signin::sign_in(&store, opts, |url| {
            open_browser(url, print_only)
        }))
        .map_err(|e| {
            if system_trust && e.contains("does not trust the certificate") {
                format!(
                    "{e}\nIf your organization's warren uses a certificate from its own authority, ask an administrator for the deployment root fingerprint (warren admin deployment shows it) and run warren login with --fingerprint."
                )
            } else {
                e
            }
        })?;
    let p = &done.account.profile;
    if let Some(old) = &done.replaced {
        println!("Replaced the sign-in to {old}.");
    }
    println!(
        "Signed in to {} as {}.",
        p.org_url,
        p.user.email.as_deref().unwrap_or(&p.user.id)
    );
    let storage = done.account.key.storage();
    println!(
        "Device {} {} (key: {}).",
        done.device.id,
        if done.reused_key {
            "signed in again"
        } else {
            "enrolled"
        },
        storage.describe()
    );
    if let Some(note) = &done.key_note {
        println!(
            "Note: {note}. The device key is a software key instead, which administrators see as such."
        );
    }
    match (&done.certificate, &done.pending) {
        (Some(_), _) => {
            let n = done.entitlements.as_ref().map_or(0, |e| e.apps.len());
            println!(
                "You can reach {n} app{}. Run `sudo warren up` to connect.",
                if n == 1 { "" } else { "s" }
            );
        }
        (None, Some(e)) if e.reason == "device_not_approved" => println!(
            "This device is waiting for an administrator to approve it: device {}. Run `sudo warren up` once it is approved.",
            done.device.id
        ),
        (None, Some(e)) => println!("No certificate yet: {e}"),
        (None, None) => println!(
            "This device is {}: device {}.",
            done.device.status, done.device.id
        ),
    }
    if ask_up(&dir, "renew").is_some_and(|r| r.trim() == "ok") {
        println!("The running warren up now uses this sign-in.");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn up(m: &ArgMatches) -> Result<(), String> {
    up::run(m)
}

#[cfg(not(target_os = "macos"))]
fn up(_: &ArgMatches) -> Result<(), String> {
    Err("this release runs the tunnel on macOS only; Linux and Windows clients come later".into())
}

/// Sends one command to a running `warren up` and returns its answer;
/// `None` if none is running.
fn ask_up(dir: &Path, command: &str) -> Option<String> {
    let path = dir.join(warren_client::state::CONTROL_SOCKET);
    let mut s = std::os::unix::net::UnixStream::connect(&path).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    s.write_all(format!("{command}\n").as_bytes()).ok()?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).ok()?;
    Some(line)
}

fn status(m: &ArgMatches) -> Result<(), String> {
    let dir = home(m)?;
    let Some(store) = Store::existing(&dir) else {
        return Err("not signed in; run `warren login <organization URL>` first".into());
    };
    let live = ask_up(&dir, "status").and_then(|l| serde_json::from_str::<Status>(&l).ok());
    let up = live.is_some();
    let status = match live {
        Some(s) => s,
        None => Status::offline(&Account::load(&store)?),
    };
    if m.get_flag("json") {
        let mut v = serde_json::to_value(&status).map_err(|e| e.to_string())?;
        v["up"] = up.into();
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    print!("{}", render(&status, up));
    Ok(())
}

/// Status, for people.
pub fn render(s: &Status, up: bool) -> String {
    let mut out = String::new();
    let mut line = |k: &str, v: String| out.push_str(&format!("{k:<13} {v}\n"));
    line(
        "warren",
        if up {
            "up".into()
        } else {
            "down (run `sudo warren up` to connect)".into()
        },
    );
    line("organization", s.org.clone());
    line("user", s.user.clone());
    line(
        "device",
        format!("{} ({}), key: {}", s.device, s.device_status, s.key_storage),
    );
    line("session", format!("ends {}", when(s.session_expires_at)));
    match &s.certificate {
        Some(c) => line(
            "certificate",
            format!(
                "valid until {}, renews {}",
                when(c.not_after),
                when(c.renew_at)
            ),
        ),
        None => line("certificate", "none yet".into()),
    }
    if up {
        if s.network.addresses.is_empty() {
            line("addresses", "-".into());
        } else {
            let a: Vec<String> = s
                .network
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect();
            line("addresses", a.join(", "));
        }
        let routes: Vec<String> = s.network.routes.iter().map(ToString::to_string).collect();
        line(
            "routes",
            if routes.is_empty() {
                "none".into()
            } else {
                routes.join(", ")
            },
        );
        for sk in &s.network.skipped {
            line(
                "not routed",
                format!("{} ({}): {}", sk.range, sk.app, sk.why),
            );
        }
        out.push_str("tunnels\n");
        for g in &s.groups {
            let detail = match g.state.as_str() {
                "connected" => format!(
                    "connected through {} over {} since {}",
                    g.relay.as_deref().unwrap_or("?"),
                    g.carrier.as_deref().unwrap_or("?"),
                    clock::rfc3339(g.since)
                ),
                "down" => format!("down: {}", g.reason.as_deref().unwrap_or("unknown")),
                other => other.to_owned(),
            };
            out.push_str(&format!("  {:<11} {detail}\n", g.name));
        }
    }
    if !s.apps.is_empty() {
        out.push_str("apps\n");
        for a in &s.apps {
            out.push_str(&format!(
                "  {:<11} {:<11} via {:<10} {}\n",
                a.name,
                a.access,
                a.group,
                a.destinations.join("; ")
            ));
        }
    }
    if !s.recent.is_empty() {
        out.push_str("recent\n");
        for r in &s.recent {
            out.push_str(&format!("  {} {}\n", clock::rfc3339(r.at), r.message));
        }
    }
    out
}

fn down(m: &ArgMatches) -> Result<(), String> {
    let dir = home(m)?;
    match ask_up(&dir, "down") {
        Some(reply) if reply.trim() == "ok" => {
            let socket = dir.join(warren_client::state::CONTROL_SOCKET);
            for _ in 0..100 {
                if !socket.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            println!("warren is down.");
            Ok(())
        }
        Some(reply) => Err(format!("warren up answered: {}", reply.trim())),
        None => {
            println!("warren is not up.");
            Ok(())
        }
    }
}

fn logout(m: &ArgMatches) -> Result<(), String> {
    let dir = home(m)?;
    if ask_up(&dir, "status").is_some() {
        return Err("warren is up; run `warren down` first".into());
    }
    let Some(store) = Store::existing(&dir) else {
        println!("Not signed in.");
        return Ok(());
    };
    let device = store
        .profile()
        .ok()
        .flatten()
        .and_then(|p| p.device.map(|d| d.id));
    store.clear()?;
    println!("Signed out and deleted this device's key.");
    if let Some(d) = device {
        println!(
            "An administrator can revoke the device so its last certificate stops working at once: warren admin devices revoke {d}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use warren_client::engine::{GroupStatus, NetworkSettings, Recent};

    #[test]
    fn status_reads_as_a_summary() {
        let s = Status {
            org: "https://warren.example.com".into(),
            user: "ada@example.com".into(),
            device: "d-1".into(),
            device_status: "approved".into(),
            key_storage: "Secure Enclave (hardware-bound)".into(),
            session_expires_at: clock::now_secs() + 3600,
            certificate: None,
            network: NetworkSettings {
                addresses: vec!["100.96.0.2".parse().unwrap()],
                mtu: 1280,
                routes: vec!["10.77.0.0/24".parse().unwrap()],
                skipped: Vec::new(),
            },
            groups: vec![GroupStatus {
                name: "homelab".into(),
                state: "connected".into(),
                relay: Some("relay.example.com".into()),
                carrier: Some("QUIC".into()),
                reason: None,
                since: 0,
            }],
            apps: Vec::new(),
            recent: vec![Recent {
                at: 0,
                message: "blocked tcp 10.77.0.20:7: no [no_rule]".into(),
            }],
        };
        let text = render(&s, true);
        assert!(text.starts_with("warren        up\n"), "{text}");
        assert!(text.contains("routes        10.77.0.0/24"), "{text}");
        assert!(text.contains("homelab     connected through relay.example.com over QUIC"));
        assert!(text.contains("[no_rule]"));
        let down = render(&s, false);
        assert!(down.contains("sudo warren up"));
        assert!(!down.contains("routes"));
    }

    #[test]
    fn spans_are_short() {
        assert_eq!(span(30), "30 s");
        assert_eq!(span(600), "10 min");
        assert_eq!(span(4 * 3600), "4 h");
        assert_eq!(span(7 * 86_400), "7 days");
    }
}
