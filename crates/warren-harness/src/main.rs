//! `warren-harness`: the data path's test client, test PKI, stand-in apps
//! and benchmarks. A test tool, never shipped.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{Value, json};
use warren_client::{ClientConfig, ClientEvent};
use warren_core::bundle::IpNet;
use warren_core::packet;
use warren_core::pki::TrustBundle;
use warren_core::quic::TransportTuning;
use warren_core::tls::Credentials;
use warren_harness::pki::{ClientCert, TestPki, pem, write_credentials};
use warren_masque::session::{RelayAddress, TransportMode};

fn cli() -> Command {
    let conn_args = |c: Command| {
        c.arg(
            Arg::new("relay")
                .long("relay")
                .required(true)
                .action(ArgAction::Append)
                .value_name("NAME@HOST:PORT"),
        )
        .arg(Arg::new("group").long("group").required(true))
        .arg(Arg::new("cert").long("cert").required(true))
        .arg(Arg::new("key").long("key").required(true))
        .arg(
            Arg::new("trust-bundle")
                .long("trust-bundle")
                .required(true)
                .value_name("DIR"),
        )
        .arg(Arg::new("trust-domain").long("trust-domain").required(true))
        .arg(
            Arg::new("transport")
                .long("transport")
                .default_value("auto")
                .value_parser(["auto", "quic", "h2"]),
        )
        .arg(
            Arg::new("fallback-delay-ms")
                .long("fallback-delay-ms")
                .default_value("300")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("tunnel-mtu")
                .long("tunnel-mtu")
                .default_value("1280")
                .value_parser(clap::value_parser!(u16)),
        )
    };
    Command::new("warren-harness")
        .about("Test client, test PKI, stand-in apps and benchmarks for warren's data path")
        .subcommand_required(true)
        .subcommand(
            Command::new("pki")
                .about("Write a test PKI: trust bundle, relay, connector and client credentials")
                .arg(Arg::new("dir").long("dir").required(true))
                .arg(Arg::new("trust-domain").long("trust-domain").required(true))
                .arg(
                    Arg::new("relay-dns")
                        .long("relay-dns")
                        .action(ArgAction::Append)
                        .required(true),
                )
                .arg(Arg::new("group").long("group").required(true))
                .arg(
                    Arg::new("client")
                        .long("client")
                        .action(ArgAction::Append)
                        .value_name("USER,DEVICE,IPV4,IPV6")
                        .help("A user+device certificate to issue"),
                ),
        )
        .subcommand(
            Command::new("join-serve")
                .about("Stand in for the control plane's join endpoint, with a fresh test PKI")
                .arg(Arg::new("dir").long("dir").required(true))
                .arg(Arg::new("trust-domain").long("trust-domain").required(true))
                .arg(
                    Arg::new("listen")
                        .long("listen")
                        .required(true)
                        .value_name("ADDR"),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .required(true)
                        .help("DNS name tokens use for the endpoint"),
                )
                .arg(
                    Arg::new("relay-dns")
                        .long("relay-dns")
                        .action(ArgAction::Append)
                        .required(true),
                )
                .arg(Arg::new("group").long("group").required(true))
                .arg(
                    Arg::new("client")
                        .long("client")
                        .action(ArgAction::Append)
                        .value_name("USER,DEVICE,IPV4,IPV6"),
                ),
        )
        .subcommand(
            Command::new("idp")
                .about("Run a test OpenID Connect provider that signs one user in without a form")
                .arg(Arg::new("listen").long("listen").required(true).value_name("ADDR"))
                .arg(
                    Arg::new("host")
                        .long("host")
                        .default_value("localhost")
                        .help("The host name in the issuer URL and the TLS certificate"),
                )
                .arg(Arg::new("client-id").long("client-id").default_value("warren"))
                .arg(
                    Arg::new("user")
                        .long("user")
                        .required(true)
                        .value_name("SUB,EMAIL,GROUP+GROUP,AMR+AMR"),
                )
                .arg(
                    Arg::new("dir")
                        .long("dir")
                        .required(true)
                        .help("Where to write ca.pem, the IdP's test CA"),
                ),
        )
        .subcommand(
            Command::new("connector")
                .about("macOS: a connector that forwards through a utun interface with address translation (tests only; needs root)")
                .arg(Arg::new("group").long("group").required(true))
                .arg(
                    Arg::new("relay")
                        .long("relay")
                        .required(true)
                        .action(ArgAction::Append)
                        .value_name("NAME@HOST:PORT"),
                )
                .arg(Arg::new("join-token").long("join-token").required(true))
                .arg(Arg::new("bundle").long("bundle").required(true))
                .arg(Arg::new("audit").long("audit"))
                .arg(
                    Arg::new("map")
                        .long("map")
                        .required(true)
                        .action(ArgAction::Append)
                        .value_name("APP=LOCAL")
                        .help("An app's IPv4 address and the local address that serves it"),
                )
                .arg(
                    Arg::new("peers")
                        .long("peers")
                        .default_value("10.88.0.0/24")
                        .help("The range client addresses are translated into"),
                ),
        )
        .subcommand(
            Command::new("serve")
                .about("Run stand-in apps")
                .arg(
                    Arg::new("tcp-echo")
                        .long("tcp-echo")
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("udp-echo")
                        .long("udp-echo")
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("tcp-sink")
                        .long("tcp-sink")
                        .action(ArgAction::Append),
                )
                .arg(Arg::new("tls").long("tls").value_name("ADDR"))
                .arg(Arg::new("tls-cert").long("tls-cert"))
                .arg(Arg::new("tls-key").long("tls-key")),
        )
        .subcommand(conn_args(
            Command::new("client")
                .about("Open a tunnel and run probes through it")
                .arg(
                    Arg::new("tun")
                        .long("tun")
                        .value_name("NAME")
                        .help("Linux: route through a TUN device"),
                )
                .arg(
                    Arg::new("route")
                        .long("route")
                        .action(ArgAction::Append)
                        .value_name("CIDR"),
                )
                .arg(
                    Arg::new("bind")
                        .long("bind")
                        .action(ArgAction::Append)
                        .value_name("NAME=APP@ADDRESS"),
                )
                .arg(
                    Arg::new("probe")
                        .long("probe")
                        .action(ArgAction::Append)
                        .value_name("KIND=TARGET")
                        .help("tcp-echo, tcp-deny, udp-echo, udp-deny or ping"),
                )
                .arg(Arg::new("bench-echo").long("bench-echo").value_name("ADDR"))
                .arg(Arg::new("bench-sink").long("bench-sink").value_name("ADDR"))
                .arg(
                    Arg::new("seconds")
                        .long("seconds")
                        .default_value("5")
                        .value_parser(clap::value_parser!(f64)),
                )
                .arg(
                    Arg::new("hold")
                        .long("hold")
                        .value_parser(clap::value_parser!(f64)),
                ),
        ))
        .subcommand(
            Command::new("bench")
                .about("Benchmarks: in-process, plain TCP or TLS over TCP")
                .arg(
                    Arg::new("mode")
                        .long("mode")
                        .default_value("inprocess")
                        .value_parser(["inprocess", "tcp", "tls"]),
                )
                .arg(Arg::new("echo").long("echo"))
                .arg(Arg::new("sink").long("sink"))
                .arg(Arg::new("target").long("target"))
                .arg(Arg::new("server-name").long("server-name"))
                .arg(Arg::new("ca").long("ca"))
                .arg(Arg::new("label").long("label").default_value(""))
                .arg(
                    Arg::new("seconds")
                        .long("seconds")
                        .default_value("5")
                        .value_parser(clap::value_parser!(f64)),
                ),
        )
}

fn s<'a>(m: &'a ArgMatches, name: &str) -> &'a str {
    m.get_one::<String>(name).map_or("", String::as_str)
}

fn sock(v: &str) -> Result<SocketAddr, String> {
    v.to_socket_addrs()
        .map_err(|e| format!("{v}: {e}"))?
        .next()
        .ok_or_else(|| format!("{v}: no address"))
}

fn emit(v: Value) {
    println!("{v}");
}

fn pki_cmd(m: &ArgMatches) -> Result<(), String> {
    let dir = PathBuf::from(s(m, "dir"));
    let pki = TestPki::new(s(m, "trust-domain"));
    pki.write_bundle(&dir.join("trust"))
        .map_err(|e| e.to_string())?;
    let dns: Vec<&str> = m
        .get_many::<String>("relay-dns")
        .expect("required")
        .map(String::as_str)
        .collect();
    write_credentials(&dir, "relay", &pki.relay("r1", &dns)).map_err(|e| e.to_string())?;
    write_credentials(&dir, "connector", &pki.connector(s(m, "group"), "c1"))
        .map_err(|e| e.to_string())?;
    // A server certificate for the TLS baseline, under the infrastructure CA.
    write_credentials(&dir, "tls", &pki.relay("tls", &dns)).map_err(|e| e.to_string())?;
    for c in m.get_many::<String>("client").into_iter().flatten() {
        let parts: Vec<&str> = c.split(',').collect();
        let [user, device, v4, v6] = parts[..] else {
            return Err(format!("--client {c}: expected USER,DEVICE,IPV4,IPV6"));
        };
        write_credentials(
            &dir,
            &format!("client-{user}-{device}"),
            &pki.client(&ClientCert::new(user, device, v4, v6)),
        )
        .map_err(|e| e.to_string())?;
    }
    std::fs::write(
        dir.join("root-ca.der.pem"),
        pem("CERTIFICATE", &pki.root.cert),
    )
    .map_err(|e| e.to_string())?;
    emit(json!({ "pki": dir.display().to_string(), "trust_domain": pki.trust_domain }));
    Ok(())
}

/// Writes the trust bundle and client credentials, mints one relay and one
/// connector token into `tokens.json`, and serves joins until stopped.
async fn join_serve_cmd(m: &ArgMatches) -> Result<(), String> {
    let dir = PathBuf::from(s(m, "dir"));
    let pki = Arc::new(TestPki::new(s(m, "trust-domain")));
    pki.write_bundle(&dir.join("trust"))
        .map_err(|e| e.to_string())?;
    for c in m.get_many::<String>("client").into_iter().flatten() {
        let parts: Vec<&str> = c.split(',').collect();
        let [user, device, v4, v6] = parts[..] else {
            return Err(format!("--client {c}: expected USER,DEVICE,IPV4,IPV6"));
        };
        write_credentials(
            &dir,
            &format!("client-{user}-{device}"),
            &pki.client(&ClientCert::new(user, device, v4, v6)),
        )
        .map_err(|e| e.to_string())?;
    }
    let server =
        warren_harness::join::JoinServer::start_on(pki, s(m, "name"), sock(s(m, "listen"))?)
            .await
            .map_err(|e| e.to_string())?;
    let dns: Vec<&str> = m
        .get_many::<String>("relay-dns")
        .expect("required")
        .map(String::as_str)
        .collect();
    let tokens = json!({
        "relay": server.mint(None, &dns).encode(),
        "connector": server.mint(Some(s(m, "group")), &[]).encode(),
    });
    std::fs::write(dir.join("tokens.json"), tokens.to_string()).map_err(|e| e.to_string())?;
    emit(json!({ "serving": "join", "addr": server.addr.to_string() }));
    std::future::pending::<()>().await;
    Ok(())
}

async fn idp_cmd(m: &ArgMatches) -> Result<(), String> {
    let dir = PathBuf::from(s(m, "dir"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let user = warren_harness::idp::IdpUser::parse(s(m, "user"))?;
    let idp = warren_harness::idp::TestIdp::start(
        sock(s(m, "listen"))?,
        s(m, "host"),
        s(m, "client-id"),
        None,
        user,
    )
    .await
    .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ca.pem"), &idp.ca_pem).map_err(|e| e.to_string())?;
    emit(json!({ "serving": "idp", "issuer": idp.issuer, "addr": idp.addr.to_string() }));
    std::future::pending::<()>().await;
    Ok(())
}

fn relay_args(m: &ArgMatches) -> Result<Vec<RelayAddress>, String> {
    m.get_many::<String>("relay")
        .expect("required")
        .map(|r| {
            let (name, addr) = r
                .split_once('@')
                .ok_or_else(|| format!("--relay {r}: expected NAME@HOST:PORT"))?;
            let addr = sock(addr)?;
            Ok(RelayAddress {
                name: name.into(),
                quic: addr,
                tcp: addr,
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
async fn connector_cmd(m: &ArgMatches) -> Result<(), String> {
    use std::net::Ipv4Addr;
    use warren_connector::{Connector, ConnectorConfig, SystemResolver};
    use warren_core::audit::{AuditSink, NodeInfo};
    use warren_core::bundle::{Bundle, NodeState};
    use warren_core::join::{JoinToken, NodeKey};

    let group = s(m, "group").to_owned();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token = JoinToken::parse(s(m, "join-token"), now).map_err(|e| e.to_string())?;
    let key = NodeKey::generate().map_err(|e| e.to_string())?;
    let joined = warren_masque::join::join(&token, &key)
        .await
        .map_err(|e| e.to_string())?;
    let bundle_path = PathBuf::from(s(m, "bundle"));
    let bundle = Bundle::load(&bundle_path).map_err(|e| e.to_string())?;
    let apps = m
        .get_many::<String>("map")
        .expect("required")
        .map(|spec| {
            let (app, local) = spec
                .split_once('=')
                .ok_or_else(|| format!("--map {spec}: expected APP=LOCAL"))?;
            let parse = |a: &str| {
                a.parse::<Ipv4Addr>()
                    .map_err(|_| format!("--map {spec}: {a} is not an IPv4 address"))
            };
            Ok((parse(app)?, parse(local)?))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let peers: IpNet = s(m, "peers").parse().map_err(|e| format!("--peers: {e}"))?;
    let backend = warren_harness::utun_nat::start(apps, peers).map_err(|e| e.to_string())?;
    let audit = AuditSink::new(
        NodeInfo {
            role: "connector".into(),
            name: format!("connector/{group}/{}", joined.identity.id),
        },
        m.get_one::<String>("audit").map(Path::new),
    )
    .map_err(|e| format!("--audit: {e}"))?;
    let state = NodeState::new(bundle);
    let config = ConnectorConfig {
        group,
        relays: relay_args(m)?,
        transport: TransportMode::Auto,
        credentials: joined.credentials,
        trust: Arc::new(joined.trust),
        policy: Arc::new(warren_core::policy::StaticPolicy::new(state.clone())),
        state,
        audit,
        resolver: Arc::new(SystemResolver),
        synthetic_pools: vec![
            warren_core::params::SYNTHETIC_POOL_V4
                .parse::<IpNet>()
                .expect("valid"),
            warren_core::params::SYNTHETIC_POOL_V6
                .parse::<IpNet>()
                .expect("valid"),
        ],
        tunnel_mtu: warren_core::params::TUNNEL_MTU,
        tuning: TransportTuning::default(),
    };
    let connector = Connector::start(config, backend).map_err(|e| e.to_string())?;
    emit(json!({ "serving": "connector", "id": joined.identity.id }));
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|e| e.to_string())?;
    while hup.recv().await.is_some() {
        match Bundle::load(&bundle_path)
            .map_err(|e| e.to_string())
            .and_then(|b| connector.reload(b))
        {
            Ok(()) => emit(json!({ "event": "reloaded" })),
            Err(e) => emit(json!({ "event": "reload_failed", "error": e })),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn connector_cmd(_: &ArgMatches) -> Result<(), String> {
    Err("the utun connector stand-in runs on macOS; use warren connector on Linux".into())
}

async fn serve_cmd(m: &ArgMatches) -> Result<(), String> {
    for a in m.get_many::<String>("tcp-echo").into_iter().flatten() {
        let l = warren_harness::serve::tcp_echo(sock(a)?)
            .await
            .map_err(|e| e.to_string())?;
        emit(json!({ "serving": "tcp-echo", "addr": l.to_string() }));
    }
    for a in m.get_many::<String>("udp-echo").into_iter().flatten() {
        let l = warren_harness::serve::udp_echo(sock(a)?)
            .await
            .map_err(|e| e.to_string())?;
        emit(json!({ "serving": "udp-echo", "addr": l.to_string() }));
    }
    for a in m.get_many::<String>("tcp-sink").into_iter().flatten() {
        let l = warren_harness::serve::tcp_sink(sock(a)?)
            .await
            .map_err(|e| e.to_string())?;
        emit(json!({ "serving": "tcp-sink", "addr": l.to_string() }));
    }
    if let Some(a) = m.get_one::<String>("tls") {
        let creds = Credentials::load(Path::new(s(m, "tls-cert")), Path::new(s(m, "tls-key")))?;
        let l = warren_harness::serve::tls_server(sock(a)?, creds)
            .await
            .map_err(|e| e.to_string())?;
        emit(json!({ "serving": "tls", "addr": l.to_string() }));
    }
    std::future::pending::<()>().await;
    Ok(())
}

fn client_config(m: &ArgMatches) -> Result<ClientConfig, String> {
    let relays = relay_args(m)?;
    let trust = TrustBundle::load_dir(s(m, "trust-domain"), Path::new(s(m, "trust-bundle")))
        .map_err(|e| e.to_string())?;
    Ok(ClientConfig {
        group: s(m, "group").into(),
        relays,
        transport: match s(m, "transport") {
            "quic" => TransportMode::QuicOnly,
            "h2" => TransportMode::Http2Only,
            _ => TransportMode::Auto,
        },
        credentials: Credentials::load(Path::new(s(m, "cert")), Path::new(s(m, "key")))?.into(),
        trust: Arc::new(trust),
        tunnel_mtu: *m.get_one::<u16>("tunnel-mtu").expect("defaulted"),
        fallback_delay: Duration::from_millis(
            *m.get_one::<u64>("fallback-delay-ms").expect("defaulted"),
        ),
        tuning: TransportTuning::default(),
    })
}

/// Splits an inclusive address range into CIDR blocks.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Vec<IpNet> {
    let (v6, mut a, b) = match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            (false, u128::from(u32::from(s)), u128::from(u32::from(e)))
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => (true, u128::from(s), u128::from(e)),
        _ => return Vec::new(),
    };
    let bits = if v6 { 128 } else { 32 };
    let mut out = Vec::new();
    while a <= b {
        let mut len = bits;
        while len > 0 {
            let fits = match 1u128.checked_shl(bits - len + 1) {
                Some(size) => a % size == 0 && a + (size - 1) <= b,
                None => a == 0 && b == u128::MAX,
            };
            if !fits {
                break;
            }
            len -= 1;
        }
        let addr = if v6 {
            IpAddr::V6(a.into())
        } else {
            IpAddr::V4((a as u32).into())
        };
        out.push(IpNet {
            addr,
            len: len as u8,
        });
        match 1u128
            .checked_shl(bits - len)
            .and_then(|step| a.checked_add(step))
        {
            Some(n) => a = n,
            None => break,
        }
    }
    out
}

async fn wait_denial(
    events: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
    within: Duration,
) -> Option<(String, String)> {
    let deadline = Instant::now() + within;
    loop {
        match tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            events.recv(),
        )
        .await
        {
            Ok(Some(ClientEvent::Denied(d))) => return Some((d.reason, d.message)),
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

async fn client_cmd(m: &ArgMatches) -> Result<(), String> {
    let config = client_config(m)?;
    let started = Instant::now();
    let tunnel = match warren_client::connect(config).await {
        Ok(t) => t,
        Err(e) => {
            emit(json!({ "event": "connect_failed", "error": e.to_string() }));
            return Err(e.to_string());
        }
    };
    let setup_ms = started.elapsed().as_secs_f64() * 1e3;
    let stats = tunnel.stats();
    emit(json!({
        "event": "connected",
        "setup_ms": (setup_ms * 1000.0).round() / 1000.0,
        "carrier": format!("{:?}", stats.carrier),
        "addresses": tunnel.info().addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "routes": tunnel.info().routes.len(),
    }));
    let mut tunnel = tunnel;
    let mut events = tunnel.events();
    let closer = tunnel.closer();
    let mut binds = Vec::new();
    for b in m.get_many::<String>("bind").into_iter().flatten() {
        let (name, rest) = b
            .split_once('=')
            .ok_or_else(|| format!("--bind {b}: expected NAME=APP@ADDRESS"))?;
        let (app, addr) = rest
            .split_once('@')
            .ok_or_else(|| format!("--bind {b}: expected NAME=APP@ADDRESS"))?;
        let addr: IpAddr = addr.parse().map_err(|e| format!("--bind {b}: {e}"))?;
        let r = tunnel.bind_name(addr, name, app).await;
        emit(
            json!({ "bind": name, "app": app, "address": addr.to_string(), "ok": r.is_ok(),
                     "reason": r.as_ref().err().map(|e| e.reason.clone()) }),
        );
        binds.push(addr);
    }
    let probes: Vec<String> = m
        .get_many::<String>("probe")
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    let mut failed = 0;
    match m.get_one::<String>("tun") {
        Some(name) => {
            #[cfg(target_os = "linux")]
            {
                let mut routes: Vec<IpNet> = m
                    .get_many::<String>("route")
                    .into_iter()
                    .flatten()
                    .map(|r| r.parse::<IpNet>().map_err(|e| e.to_string()))
                    .collect::<Result<_, _>>()?;
                if routes.is_empty() {
                    for r in &tunnel.info().routes {
                        routes.extend(range_to_cidrs(r.start, r.end));
                    }
                }
                let addrs: Vec<IpNet> = tunnel
                    .info()
                    .addresses
                    .iter()
                    .map(|a| IpNet {
                        addr: *a,
                        len: if a.is_ipv4() { 32 } else { 128 },
                    })
                    .collect();
                let tun = Arc::new(
                    warren_core::tun::Tun::create(name).map_err(|e| format!("TUN {name}: {e}"))?,
                );
                warren_core::tun::configure(tun.name(), tunnel.info().tunnel_mtu, &addrs, &routes)
                    .map_err(|e| format!("TUN {name}: {e}"))?;
                let sender = tunnel.sender();
                let reader = tun.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65_536];
                    while let Ok(n) = reader.recv(&mut buf).await {
                        sender.send(&buf[..n]);
                    }
                });
                let writer = tun.clone();
                tokio::spawn(async move {
                    while let Some(p) = tunnel.recv().await {
                        let _ = writer.send(&p);
                    }
                });
                for probe in &probes {
                    failed += u32::from(!os_probe(probe, &mut events).await);
                }
                if let (Some(echo), Some(sink)) = (
                    m.get_one::<String>("bench-echo"),
                    m.get_one::<String>("bench-sink"),
                ) {
                    let secs = *m.get_one::<f64>("seconds").expect("defaulted");
                    let r = warren_harness::bench::tcp_suite(sock(echo)?, sock(sink)?, secs)
                        .await
                        .map_err(|e| e.to_string())?;
                    emit(json!({ "bench": "warren", "setup_ms": setup_ms, "results": r }));
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (name, &mut events);
                return Err("--tun needs Linux".into());
            }
        }
        None => {
            for probe in &probes {
                failed += u32::from(!packet_probe(probe, &mut tunnel, &mut events).await);
            }
        }
    }
    if let Some(h) = m.get_one::<f64>("hold") {
        tokio::time::sleep(Duration::from_secs_f64(*h)).await;
    }
    // Close cleanly so the connector ends the session (and writes its flow
    // records) at once rather than at the idle timeout.
    closer.close();
    tokio::time::sleep(Duration::from_millis(100)).await;
    if failed > 0 {
        return Err(format!("{failed} probe(s) failed"));
    }
    Ok(())
}

/// A probe through the operating system's sockets (TUN mode).
#[cfg(target_os = "linux")]
async fn os_probe(spec: &str, events: &mut tokio::sync::mpsc::Receiver<ClientEvent>) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some((kind, target)) = spec.split_once('=') else {
        emit(json!({ "probe": spec, "ok": false, "error": "expected KIND=TARGET" }));
        return false;
    };
    let started = Instant::now();
    let result: Result<Value, String> = async {
        match kind {
            "tcp-echo" => {
                let mut s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(sock(target)?))
                    .await
                    .map_err(|_| "connect timed out".to_owned())?
                    .map_err(|e| e.to_string())?;
                let msg = vec![0x61u8; 100_000];
                let (mut r, mut w) = s.split();
                let write = async {
                    w.write_all(&msg).await?;
                    w.shutdown().await
                };
                let mut back = Vec::new();
                let read = r.read_to_end(&mut back);
                let (wr, rr) = tokio::join!(write, read);
                wr.map_err(|e| e.to_string())?;
                rr.map_err(|e| e.to_string())?;
                if back != msg {
                    return Err(format!("echoed {} of {} bytes", back.len(), msg.len()));
                }
                Ok(json!({ "bytes": back.len() }))
            }
            "udp-echo" => {
                let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
                s.connect(sock(target)?).await.map_err(|e| e.to_string())?;
                s.send(b"warren udp probe").await.map_err(|e| e.to_string())?;
                let mut buf = [0u8; 64];
                let n = tokio::time::timeout(Duration::from_secs(5), s.recv(&mut buf))
                    .await
                    .map_err(|_| "no echo".to_owned())?
                    .map_err(|e| e.to_string())?;
                (buf[..n] == b"warren udp probe"[..]).then(|| json!({})).ok_or_else(|| "bad echo".to_owned())
            }
            "tcp-deny" => {
                let r = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(sock(target)?)).await;
                let fast = started.elapsed();
                match r {
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                    Ok(Ok(_)) => return Err("connected; expected a denial".into()),
                    Ok(Err(e)) => return Err(format!("failed differently: {e}")),
                    Err(_) => return Err("timed out instead of failing fast".into()),
                }
                let (reason, message) = wait_denial(events, Duration::from_secs(2))
                    .await
                    .ok_or_else(|| "no deny reason arrived".to_owned())?;
                Ok(json!({ "refused_ms": fast.as_secs_f64() * 1e3, "reason": reason, "message": message }))
            }
            "udp-deny" => {
                let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
                s.connect(sock(target)?).await.map_err(|e| e.to_string())?;
                let _ = s.send(b"x").await;
                let (reason, message) = wait_denial(events, Duration::from_secs(3))
                    .await
                    .ok_or_else(|| "no deny reason arrived".to_owned())?;
                Ok(json!({ "reason": reason, "message": message }))
            }
            _ => Err(format!("unknown probe {kind}")),
        }
    }
    .await;
    report(kind, target, started, result)
}

fn report(kind: &str, target: &str, started: Instant, result: Result<Value, String>) -> bool {
    let ms = started.elapsed().as_secs_f64() * 1e3;
    match result {
        Ok(mut v) => {
            v["probe"] = json!(kind);
            v["target"] = json!(target);
            v["ok"] = json!(true);
            v["ms"] = json!(ms);
            emit(v);
            true
        }
        Err(e) => {
            emit(json!({ "probe": kind, "target": target, "ok": false, "error": e, "ms": ms }));
            false
        }
    }
}

/// A probe built from raw packets (no TUN needed).
async fn packet_probe(
    spec: &str,
    t: &mut warren_client::Tunnel,
    events: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
) -> bool {
    let Some((kind, target)) = spec.split_once('=') else {
        emit(json!({ "probe": spec, "ok": false, "error": "expected KIND=TARGET" }));
        return false;
    };
    let started = Instant::now();
    let v4 = t.info().addresses.iter().copied().find(IpAddr::is_ipv4);
    let result: Result<Value, String> = async {
        let src_ip = v4.ok_or("no IPv4 tunnel address")?;
        match kind {
            "udp-echo" | "udp-deny" => {
                let dst = sock(target)?;
                let src = SocketAddr::new(
                    src_ip,
                    40_000 + (started.elapsed().subsec_nanos() % 20_000) as u16,
                );
                t.send(&packet::udp(src, dst, b"warren udp probe"));
                if kind == "udp-deny" {
                    let (reason, message) = wait_denial(events, Duration::from_secs(3))
                        .await
                        .ok_or_else(|| "no deny reason arrived".to_owned())?;
                    return Ok(json!({ "reason": reason, "message": message }));
                }
                let reply = tokio::time::timeout(Duration::from_secs(5), t.recv())
                    .await
                    .map_err(|_| "no echo".to_owned())?
                    .ok_or("tunnel closed")?;
                let p = packet::parse(&reply).map_err(|e| e.to_string())?;
                (packet::udp_payload(&reply, &p) == Some(&b"warren udp probe"[..]))
                    .then(|| json!({}))
                    .ok_or_else(|| "bad echo".to_owned())
            }
            "ping" => {
                let dst: IpAddr = target.parse().map_err(|e| format!("{e}"))?;
                t.send(&packet::icmp_echo(src_ip, dst, false, 7, 1, b"warren"));
                let reply = tokio::time::timeout(Duration::from_secs(5), t.recv())
                    .await
                    .map_err(|_| "no reply".to_owned())?
                    .ok_or("tunnel closed")?;
                let p = packet::parse(&reply).map_err(|e| e.to_string())?;
                p.is_icmp_echo()
                    .then(|| json!({}))
                    .ok_or_else(|| "not an echo reply".to_owned())
            }
            _ => Err(format!("probe {kind} needs --tun")),
        }
    }
    .await;
    report(kind, target, started, result)
}

async fn bench_cmd(m: &ArgMatches) -> Result<(), String> {
    let secs = *m.get_one::<f64>("seconds").expect("defaulted");
    let label = s(m, "label");
    let results = match s(m, "mode") {
        "inprocess" => warren_harness::bench::inprocess::run(secs).await,
        "tcp" => warren_harness::bench::tcp_suite(sock(s(m, "echo"))?, sock(s(m, "sink"))?, secs)
            .await
            .map_err(|e| e.to_string())?,
        "tls" => {
            use rustls::pki_types::pem::PemObject;
            let ca = rustls::pki_types::CertificateDer::from_pem_file(s(m, "ca"))
                .map_err(|e| e.to_string())?;
            warren_harness::bench::tls_suite(sock(s(m, "target"))?, s(m, "server-name"), &ca, secs)
                .await
                .map_err(|e| e.to_string())?
        }
        other => return Err(format!("unknown mode {other}")),
    };
    emit(json!({ "bench": label, "mode": s(m, "mode"), "results": results }));
    Ok(())
}

fn main() -> ExitCode {
    let matches = cli().get_matches();
    if let Ok(level) = std::env::var("WARREN_LOG") {
        warren_core::logging::init(&level);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let result = rt.block_on(async {
        match matches.subcommand() {
            Some(("pki", m)) => pki_cmd(m),
            Some(("join-serve", m)) => join_serve_cmd(m).await,
            Some(("idp", m)) => idp_cmd(m).await,
            Some(("connector", m)) => connector_cmd(m).await,
            Some(("serve", m)) => serve_cmd(m).await,
            Some(("client", m)) => client_cmd(m).await,
            Some(("bench", m)) => bench_cmd(m).await,
            _ => Err("unknown command".into()),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warren-harness: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_is_well_formed() {
        cli().debug_assert();
    }

    #[test]
    fn ranges_split_into_cidrs() {
        let nets = range_to_cidrs("10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        assert_eq!(
            nets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["10.0.0.0/24"]
        );
        let nets = range_to_cidrs("10.0.0.1".parse().unwrap(), "10.0.0.4".parse().unwrap());
        assert_eq!(
            nets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/32"]
        );
        let nets = range_to_cidrs("fd00::".parse().unwrap(), "fd00::ffff".parse().unwrap());
        assert_eq!(
            nets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["fd00::/112"]
        );
        let nets = range_to_cidrs(
            "::".parse().unwrap(),
            "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
        );
        assert_eq!(
            nets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["::/1"]
        );
        let nets = range_to_cidrs(
            "::".parse().unwrap(),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
        );
        assert_eq!(
            nets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["::/0"]
        );
        let nets = range_to_cidrs(
            "8000::".parse().unwrap(),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
        );
        assert_eq!(
            nets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["8000::/1"]
        );
        let nets = range_to_cidrs(
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        );
        assert_eq!(
            nets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["0.0.0.0/0"]
        );
    }
}
