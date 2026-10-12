//! `sudo warren up` on macOS: the tunnel on a utun interface.
//!
//! As root it opens the interface and forks the route helper, then becomes
//! the user who ran `sudo` and runs the engine: packets the system routes
//! into the interface go to the engine, packets from the tunnels go back
//! out, and every event is printed as it happens. `warren status` and
//! `warren down` reach it through a socket in the user's state directory.
//! Stopping closes the interface, which removes every route through it.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use clap::ArgMatches;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::watch;
use warren_client::control::Account;
use warren_client::engine::{Engine, EngineOptions, NetworkSettings, Platform};
use warren_client::state::Store;
use warren_core::bundle::IpNet;
use warren_core::utun::{self, Utun};
use warren_masque::session::TransportMode;

use super::privsep::{self, Forked, Helper, Request};

/// The utun interface and the route helper, as the engine sees them.
struct UtunPlatform {
    utun: Arc<Utun>,
    helper: Helper,
    applied: Mutex<Option<BTreeSet<String>>>,
}

impl Platform for UtunPlatform {
    fn deliver(&self, packet: &[u8]) {
        if let Err(e) = self.utun.send(packet) {
            tracing::warn!(error = %e, "utun write failed");
        }
    }

    fn apply(&self, s: &NetworkSettings) -> Result<Vec<String>, String> {
        let mut applied = self.applied.lock().map_err(|_| "lock poisoned")?;
        let mut warnings = Vec::new();
        let old = match applied.take() {
            Some(old) => old,
            None => {
                // IPv4 is required; a Mac without IPv6 only loses IPv6 apps.
                let (v4, v6) = utun::split_addresses(&s.addresses);
                let v4 = v4.ok_or("the certificate carries no IPv4 tunnel address")?;
                self.helper
                    .ask(&Request::Configure {
                        mtu: s.mtu,
                        addresses: vec![v4.into()],
                    })
                    .map_err(|e| format!("cannot configure {}: {e}", self.utun.name()))?;
                if let Some(v6) = v6
                    && let Err(e) = self.helper.ask(&Request::Configure {
                        mtu: s.mtu,
                        addresses: vec![v6.into()],
                    })
                {
                    warnings.push(format!(
                        "no IPv6 on {} ({e}); apps reached over IPv6 will not work",
                        self.utun.name()
                    ));
                }
                BTreeSet::new()
            }
        };
        let want: BTreeSet<String> = s.routes.iter().map(ToString::to_string).collect();
        let mut now = BTreeSet::new();
        for r in &want {
            if old.contains(r) {
                now.insert(r.clone());
                continue;
            }
            let net: IpNet = r.parse().map_err(|e| format!("{r}: {e}"))?;
            match self.helper.ask(&Request::Add(net)) {
                Ok(()) => {
                    now.insert(r.clone());
                }
                Err(e) => warnings.push(format!(
                    "could not route {r} through warren ({e}); another interface may already route it"
                )),
            }
        }
        for r in old.difference(&want) {
            if let Ok(net) = r.parse::<IpNet>()
                && let Err(e) = self.helper.ask(&Request::Delete(net))
            {
                warnings.push(format!("could not remove the route for {r}: {e}"));
            }
        }
        *applied = Some(now);
        Ok(warnings)
    }
}

/// The local time of day, for event lines.
fn clock_time() -> String {
    #![allow(unsafe_code)]
    let now = warren_core::clock::now_secs() as libc::time_t;
    // SAFETY: an all-zero tm is a valid value to be overwritten.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; localtime_r is the
    // thread-safe variant.
    if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() {
        return String::new();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

pub fn run(m: &ArgMatches) -> Result<(), String> {
    if !privsep::is_root() {
        return Err(
            "warren up creates a network interface, which needs root: run `sudo warren up`".into(),
        );
    }
    let user = privsep::sudo_user()?;
    let handle = utun::open().map_err(|e| format!("cannot create the tunnel interface: {e}"))?;
    let helper = match privsep::fork_helper()? {
        Forked::Child(socket) => {
            let name = handle.name().to_owned();
            // The helper keeps only its socket: the tunnel process holds the
            // interface, and the interface goes away with it.
            drop(handle);
            privsep::serve(&name, socket)
        }
        Forked::Parent(socket) => socket,
    };
    if let Some(u) = &user {
        privsep::drop_to(u)?;
    }
    let dir = super::home(m)?;
    warren_core::logging::init(
        m.get_one::<String>("log-level")
            .map_or("error", String::as_str),
    );
    let transport = match m.get_one::<String>("transport").map(String::as_str) {
        Some("quic") => TransportMode::QuicOnly,
        Some("h2") => TransportMode::Http2Only,
        _ => TransportMode::Auto,
    };
    let runtime = super::runtime()?;
    runtime.block_on(serve(dir, handle, Helper::new(helper), transport))
}

async fn serve(
    dir: std::path::PathBuf,
    handle: utun::UtunHandle,
    helper: Helper,
    transport: TransportMode,
) -> Result<(), String> {
    if super::ask_up(&dir, "status").is_some() {
        return Err("warren is already up; `warren status` shows it".into());
    }
    let store = Store::open(&dir)?;
    let account = Account::load(&store)?;
    let utun = Arc::new(handle.into_async().map_err(|e| e.to_string())?);
    let platform = Arc::new(UtunPlatform {
        utun: utun.clone(),
        helper,
        applied: Mutex::new(None),
    });
    println!(
        "Connecting to {} as {} on {}...",
        account.profile.org_url,
        account
            .profile
            .user
            .email
            .as_deref()
            .unwrap_or(&account.profile.user.id),
        utun.name()
    );
    let options = EngineOptions {
        transport,
        ..EngineOptions::default()
    };
    let engine = Arc::new(
        Engine::start(account, platform, options)
            .await
            .map_err(|e| e.message)?,
    );
    let mut events = engine.subscribe();
    let status = engine.status();
    println!(
        "warren is up: {} app{}, {} route{} through {}. Stop with Ctrl-C or `warren down`.",
        status.apps.len(),
        if status.apps.len() == 1 { "" } else { "s" },
        status.network.routes.len(),
        if status.network.routes.len() == 1 {
            ""
        } else {
            "s"
        },
        utun.name()
    );

    // Packets the system routes into the interface.
    let reader = {
        let (utun, engine) = (utun.clone(), engine.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                match utun.recv(&mut buf).await {
                    Ok(n) if n > 0 => engine.send(&buf[..n]),
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("warren up: reading {}: {e}", utun.name());
                        return;
                    }
                }
            }
        })
    };

    // `warren status` and `warren down`.
    let socket = store.control_socket();
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    }
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let control = {
        let (engine, stop_tx) = (engine.clone(), stop_tx.clone());
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let (engine, stop_tx) = (engine.clone(), stop_tx.clone());
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut line = String::new();
                    if BufReader::new(r).read_line(&mut line).await.is_err() {
                        return;
                    }
                    let reply = match line.trim() {
                        "status" => serde_json::to_string(&engine.status()).unwrap_or_default(),
                        "down" => {
                            stop_tx.send_replace(true);
                            "ok".into()
                        }
                        "renew" => {
                            engine.renew_now();
                            "ok".into()
                        }
                        _ => "error unknown command".into(),
                    };
                    let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                });
            }
        })
    };

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| e.to_string())?;
    loop {
        tokio::select! {
            e = events.recv() => match e {
                Ok(e) => println!("{} {}", clock_time(), e.message()),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    println!("{} ({n} events not shown)", clock_time());
                }
                Err(_) => break,
            },
            _ = stop_rx.changed() => break,
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    println!("Disconnecting...");
    engine.stop().await;
    reader.abort();
    control.abort();
    let _ = std::fs::remove_file(&socket);
    println!("warren is down.");
    Ok(())
}
