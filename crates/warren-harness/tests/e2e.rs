//! End-to-end through client, relay and connector, in one process.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use warren_core::packet;
use warren_harness::deploy::{Deployment, Options, alice};
use warren_masque::session::TransportMode;

fn v4(t: &warren_client::Tunnel) -> IpAddr {
    t.info()
        .addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .expect("an IPv4 address")
}

async fn recv(t: &mut warren_client::Tunnel) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), t.recv())
        .await
        .expect("a reply in time")
        .expect("tunnel open")
        .to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_through_the_relay_over_quic() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .expect("tunnel");
    let src = SocketAddr::new(v4(&t), 40_000);
    let dst: SocketAddr = "10.77.0.10:7".parse().unwrap();
    t.send(&packet::udp(src, dst, b"hello warren"));
    let reply = recv(&mut t).await;
    let p = packet::parse(&reply).unwrap();
    assert_eq!((p.src_sock(), p.dst_sock()), (dst, src));
    assert_eq!(packet::udp_payload(&reply, &p).unwrap(), b"hello warren");
}

fn v6(t: &warren_client::Tunnel) -> IpAddr {
    t.info()
        .addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv6)
        .expect("an IPv6 address")
}

async fn next_denial(
    events: &mut tokio::sync::mpsc::Receiver<warren_client::ClientEvent>,
) -> warren_masque::capsule::FlowDenied {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(warren_client::ClientEvent::Denied(d))) => return d,
            Ok(Some(_)) => continue,
            other => panic!("no denial: {other:?}"),
        }
    }
}

fn find_record(
    records: &[serde_json::Value],
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    records
        .iter()
        .find(|r| pred(r))
        .cloned()
        .unwrap_or_else(|| panic!("no matching record in {records:#?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_and_icmp_through_the_tunnel() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let src = SocketAddr::new(v6(&t), 40_001);
    let dst: SocketAddr = "[fd77:7761::10]:7".parse().unwrap();
    t.send(&packet::udp(src, dst, b"over v6"));
    let reply = recv(&mut t).await;
    let p = packet::parse(&reply).unwrap();
    assert_eq!(p.src_sock(), dst);
    assert!(packet::checksums_valid(&reply));

    let ping = packet::icmp_echo(v4(&t), "10.77.0.10".parse().unwrap(), false, 99, 1, b"ping");
    t.send(&ping);
    let pong = recv(&mut t).await;
    let p = packet::parse(&pong).unwrap();
    assert_eq!(p.icmp, Some((0, 0)));
    assert_eq!(p.src_port, 99);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denies_fail_fast_with_a_reason_and_an_audit_record() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    let src = SocketAddr::new(v4(&t), 40_002);

    // No rule for "secret".
    t.send(&packet::udp(
        src,
        "10.77.0.20:7".parse().unwrap(),
        b"let me in",
    ));
    let reply = recv(&mut t).await;
    let p = packet::parse(&reply).unwrap();
    assert_eq!(p.icmp, Some((3, 13)), "administratively prohibited");
    let denial = next_denial(&mut events).await;
    assert_eq!(denial.reason, "no_rule");
    assert_eq!(denial.message, "No policy allows you to reach secret.");

    // A discoverable app says how to get access.
    t.send(&packet::udp(src, "10.77.0.30:7".parse().unwrap(), b"x"));
    let _ = recv(&mut t).await;
    let denial = next_denial(&mut events).await;
    assert_eq!(denial.reason, "request_access");

    // Outside every app.
    t.send(&packet::udp(src, "10.99.0.1:7".parse().unwrap(), b"x"));
    let _ = recv(&mut t).await;
    let denial = next_denial(&mut events).await;
    assert_eq!(denial.reason, "out_of_scope");

    // The right port of an app, the wrong protocol: TCP to the UDP-only
    // secret? secret is "any"; use echo-udp's address on a UDP port it does
    // not list.
    t.send(&packet::udp(src, "10.77.0.10:8".parse().unwrap(), b"x"));
    let _ = recv(&mut t).await;
    let denial = next_denial(&mut events).await;
    assert_eq!(denial.reason, "out_of_scope");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let records = d.audit_records();
    let r = find_record(&records, |r| r["status_code"] == "no_rule");
    assert_eq!(r["class_uid"], 4001);
    assert_eq!(r["action"], "Denied");
    assert_eq!(r["actor"]["user"]["uid"], "alice");
    assert_eq!(r["device"]["uid"], "mac-1");
    assert_eq!(r["unmapped"]["warren"]["app"], "secret");
    assert_eq!(r["metadata"]["uid"], denial_id_for(&records, "no_rule"));
}

fn denial_id_for(records: &[serde_json::Value], reason: &str) -> serde_json::Value {
    find_record(records, |r| r["status_code"] == reason)["unmapped"]["warren"]["decision_id"]
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn names_bind_to_their_owning_app_and_translate() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    let src = SocketAddr::new(v4(&t), 40_003);

    // grafana.lab.test is owned by the exact-host app, not the wildcard.
    let rejected = t
        .bind_name("100.80.0.5".parse().unwrap(), "grafana.lab.test", "lab-web")
        .await
        .unwrap_err();
    assert_eq!(rejected.reason, "name_not_in_app");
    assert!(!rejected.message.contains("grafana\u{20}app"));
    assert!(!rejected.message.contains(" grafana "));

    let synthetic: IpAddr = "100.80.0.6".parse().unwrap();
    t.bind_name(synthetic, "grafana.lab.test", "grafana")
        .await
        .unwrap();
    let dst = SocketAddr::new(synthetic, 7);
    t.send(&packet::udp(src, dst, b"via a name"));
    let reply = recv(&mut t).await;
    let p = packet::parse(&reply).unwrap();
    assert_eq!(
        p.src_sock(),
        dst,
        "the reply comes from the synthetic address"
    );
    assert!(packet::checksums_valid(&reply));
    assert_eq!(packet::udp_payload(&reply, &p).unwrap(), b"via a name");
    // The backend saw the real address.
    let seen = d.backend.seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|s| packet::parse(s).unwrap().dst == "10.77.0.10".parse::<IpAddr>().unwrap())
    );

    // A wildcard name resolving outside the group's scope is refused.
    let outside: IpAddr = "100.80.0.7".parse().unwrap();
    t.bind_name(outside, "outside.lab.test", "lab-web")
        .await
        .unwrap();
    t.send(&packet::udp(src, SocketAddr::new(outside, 7), b"x"));
    let _ = recv(&mut t).await;
    assert_eq!(next_denial(&mut events).await.reason, "out_of_scope");

    // An unbound synthetic address stands for nothing.
    t.send(&packet::udp(src, "100.80.0.99:7".parse().unwrap(), b"x"));
    let _ = recv(&mut t).await;
    assert_eq!(next_denial(&mut events).await.reason, "out_of_scope");
}

async fn echo_ok(t: &mut warren_client::Tunnel, port: u16, payload: &[u8]) {
    let src = SocketAddr::new(v4(t), port);
    let dst: SocketAddr = "10.77.0.10:7".parse().unwrap();
    t.send(&packet::udp(src, dst, payload));
    let reply = recv(t).await;
    let p = packet::parse(&reply).unwrap();
    assert_eq!(p.src_sock(), dst);
    assert_eq!(packet::udp_payload(&reply, &p).unwrap(), payload);
}

/// A UDP address that swallows everything, like a network blocking UDP 443.
fn udp_blackhole() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = s.local_addr().unwrap();
    std::mem::forget(s);
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_fallback_when_udp_is_blocked() {
    let d = Deployment::start(Options::default()).await;
    let mut config = d.client(&alice(), TransportMode::Auto);
    config.relays[0].quic = udp_blackhole();
    config.fallback_delay = Duration::from_millis(100);
    let started = std::time::Instant::now();
    let mut t = warren_client::connect(config)
        .await
        .expect("falls back to HTTP/2");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "fallback took {:?}",
        started.elapsed()
    );
    assert_eq!(
        t.stats().carrier,
        Some(warren_masque::tunnel::CarrierKind::Http2)
    );
    echo_ok(&mut t, 41_000, b"over TCP 443").await;
    // A 1280-byte packet crosses the HTTP/2 hop and the QUIC hop.
    let src = SocketAddr::new(v4(&t), 41_001);
    let big = packet::udp(src, "10.77.0.10:7".parse().unwrap(), &[0x5a; 1252]);
    assert_eq!(big.len(), 1280);
    t.send(&big);
    assert_eq!(recv(&mut t).await.len(), 1280);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connectors_attach_over_http2_too() {
    let d = Deployment::start(Options {
        connector_transport: TransportMode::Http2Only,
        ..Options::default()
    })
    .await;
    // A QUIC client spliced to an HTTP/2-attached connector.
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    echo_ok(&mut t, 41_100, b"mixed carriers").await;
    // And an HTTP/2 client to the same connector.
    let mut t2 = warren_client::connect(d.client(&alice(), TransportMode::Http2Only))
        .await
        .unwrap();
    echo_ok(&mut t2, 41_101, b"both on TCP").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mtu_floor_is_enforced_and_always_delivered() {
    let d = Deployment::start(Options {
        connector_tuning: warren_core::quic::TransportTuning {
            fixed_outer_mtu: Some(1200),
        },
        ..Options::default()
    })
    .await;

    // A tunnel MTU below the floor is refused outright.
    let mut low = d.client(&alice(), TransportMode::QuicOnly);
    low.tunnel_mtu = 1200;
    match warren_client::connect(low).await {
        Err(warren_client::ConnectError::MtuFloor(_)) => {}
        other => panic!("expected an MTU floor error, got {other:?}"),
    }

    // Both outer hops pinned to QUIC's 1200-byte minimum: full-size inner
    // packets cannot ride in DATAGRAM frames, yet 1280-byte IP packets
    // still arrive, carried on the streams instead.
    let mut config = d.client(&alice(), TransportMode::QuicOnly);
    config.tuning.fixed_outer_mtu = Some(1200);
    let mut t = warren_client::connect(config)
        .await
        .expect("tunnel on a constrained path");
    let src = SocketAddr::new(v4(&t), 42_000);
    let dst: SocketAddr = "10.77.0.10:7".parse().unwrap();
    let floor = packet::udp(src, dst, &[0xa5; 1252]);
    assert_eq!(floor.len(), 1280);
    t.send(&floor);
    let reply = recv(&mut t).await;
    assert_eq!(reply.len(), 1280);
    assert!(t.stats().constrained(), "{:?}", t.stats());

    // Bigger than the tunnel MTU: answered at the client ingress.
    let over = packet::udp(src, dst, &[1; 1400]);
    t.send(&over);
    let icmp = packet::parse(&recv(&mut t).await).unwrap();
    assert_eq!(icmp.icmp, Some((3, 4)), "fragmentation needed");
    let over6 = packet::udp(
        SocketAddr::new(v6(&t), 42_001),
        "[fd77:7761::10]:7".parse().unwrap(),
        &[1; 1400],
    );
    t.send(&over6);
    let icmp6 = packet::parse(&recv(&mut t).await).unwrap();
    assert_eq!(icmp6.icmp, Some((2, 0)), "packet too big");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spoofed_sources_are_dropped() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let before = d.connector.metrics().dropped.get();
    let spoofed: SocketAddr = "100.96.0.77:5000".parse().unwrap();
    t.send(&packet::udp(
        spoofed,
        "10.77.0.10:7".parse().unwrap(),
        b"not me",
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(d.connector.metrics().dropped.get() > before);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), t.recv())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_initiated_flows_need_an_opt_in() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let device = SocketAddr::new(v4(&t), 5555);
    // "secret" did not opt in.
    d.backend.inject(packet::udp(
        "10.77.0.20:9999".parse().unwrap(),
        device,
        b"knock",
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), t.recv())
            .await
            .is_err()
    );
    let refusal = d
        .backend
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter_map(|s| packet::parse(s).ok())
        .any(|p| p.icmp == Some((3, 13)) && p.dst == "10.77.0.20".parse::<IpAddr>().unwrap());
    assert!(refusal, "the server was told no");
    // "pusher" opted in, and alice may reach it.
    d.backend.inject(packet::udp(
        "10.77.0.40:9999".parse().unwrap(),
        device,
        b"notify",
    ));
    let got = recv(&mut t).await;
    assert_eq!(
        packet::parse(&got).unwrap().src_sock(),
        "10.77.0.40:9999".parse().unwrap()
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let records = d.audit_records();
    let r = find_record(&records, |r| r["status_code"] == "server_initiated_blocked");
    assert_eq!(r["connection_info"]["direction"], "Inbound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_must_be_approved() {
    let d = Deployment::start(Options::default()).await;
    let cert = warren_harness::pki::ClientCert::new(
        "alice",
        "unapproved-mac",
        "100.96.0.9",
        "fd00:7761:7272:6e00::9",
    );
    let mut t = warren_client::connect(d.client(&cert, TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    t.send(&packet::udp(
        SocketAddr::new(v4(&t), 1),
        "10.77.0.10:7".parse().unwrap(),
        b"x",
    ));
    let _ = recv(&mut t).await;
    assert_eq!(next_denial(&mut events).await.reason, "device_not_approved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_groups_are_refused_with_a_reason() {
    let d = Deployment::start(Options::default()).await;
    let mut config = d.client(&alice(), TransportMode::QuicOnly);
    config.group = "nowhere".into();
    match warren_client::connect(config).await {
        Err(warren_client::ConnectError::Refused { error, details }) => {
            assert_eq!(error, "destination_unavailable");
            assert!(details.contains("nowhere"), "{details}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connector_revocation_cuts_the_session_with_a_notice() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    echo_ok(&mut t, 43_000, b"before").await;
    let mut v2 = warren_harness::deploy::test_bundle(2);
    v2["revoked"] = serde_json::json!({ "devices": ["mac-1"] });
    let started = std::time::Instant::now();
    d.connector
        .reload(warren_harness::deploy::compile(&v2))
        .unwrap();
    let mut saw_notice = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(warren_client::ClientEvent::Notice(n))) => {
                assert_eq!(n.reason, "revoked");
                saw_notice = true;
            }
            Ok(Some(warren_client::ClientEvent::Closed(_))) => break,
            Ok(Some(_)) => {}
            other => panic!("session not cut: {other:?}"),
        }
    }
    assert!(saw_notice, "the connector explained the cut");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "cut within the revocation deadline"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let records = d.audit_records();
    let flow = find_record(&records, |r| r["metadata"]["log_name"] == "flow");
    assert_eq!(flow["unmapped"]["warren"]["end_reason"], "revoked");
    assert!(flow["traffic"]["packets"].as_u64().unwrap() >= 2);
    // Older bundles are refused.
    assert!(
        d.connector
            .reload(warren_harness::deploy::compile(
                &warren_harness::deploy::test_bundle(1)
            ))
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_revocation_cuts_the_outer_connection_for_good() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    echo_ok(&mut t, 43_100, b"before").await;
    let mut v2 = warren_harness::deploy::test_bundle(2);
    v2["revoked"] = serde_json::json!({ "users": ["alice"] });
    let cut = d
        .relay()
        .reload(warren_harness::deploy::compile(&v2))
        .unwrap();
    assert_eq!(cut, 1, "the relay closed the client's outer connection");
    loop {
        match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(warren_client::ClientEvent::Closed(reason))) => {
                assert!(reason.contains("revoked"), "{reason}");
                break;
            }
            Ok(Some(_)) => {}
            other => panic!("client kept retrying: {other:?}"),
        }
    }
    // A new connection is refused during the handshake.
    match warren_client::connect(d.client(&alice(), TransportMode::Auto)).await {
        Err(warren_client::ConnectError::Rejected(_)) => {}
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn losing_a_relay_migrates_the_inner_session() {
    let d = Deployment::start(Options {
        relays: 2,
        ..Options::default()
    })
    .await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    echo_ok(&mut t, 44_000, b"via the first relay").await;
    d.relays[0].shutdown();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), events.recv()).await {
            Ok(Some(warren_client::ClientEvent::PathChanged { .. })) => break,
            Ok(Some(warren_client::ClientEvent::Closed(r))) => panic!("session closed: {r}"),
            Ok(Some(_)) => {}
            other => panic!("no path change: {other:?}"),
        }
    }
    // Same inner session, same flow, new path.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let src = SocketAddr::new(v4(&t), 44_000);
        t.send(&packet::udp(src, "10.77.0.10:7".parse().unwrap(), b"after"));
        match tokio::time::timeout(Duration::from_millis(500), t.recv()).await {
            Ok(Some(reply)) => {
                let p = packet::parse(&reply).unwrap();
                assert_eq!(packet::udp_payload(&reply, &p).unwrap(), b"after");
                break;
            }
            _ => assert!(
                std::time::Instant::now() < deadline,
                "no traffic after migration"
            ),
        }
    }
    assert_eq!(
        d.connector.metrics().sessions_total.get(),
        1,
        "the inner session was not re-established"
    );
}

async fn next_notice(
    events: &mut tokio::sync::mpsc::Receiver<warren_client::ClientEvent>,
) -> warren_masque::capsule::Notice {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(warren_client::ClientEvent::Notice(n))) => return n,
            Ok(Some(_)) => continue,
            other => panic!("no notice: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_refresh_extends_the_session() {
    use warren_harness::pki::KeyPair;
    let d = Deployment::start(Options::default()).await;
    let key = KeyPair::generate();
    // A certificate with five seconds left.
    let mut short = d.pki.client_spec(&alice());
    short.not_after = short.not_before + 65;
    let creds = d.pki.issue_client_with_key(&short, &key);
    let mut t = warren_client::connect(d.client_with(creds, TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    echo_ok(&mut t, 46_000, b"before refresh").await;

    // The renewed certificate for the same device key, bound to this
    // session by the key's signature over the session's exporter.
    let renewed = d
        .pki
        .issue_client_with_key(&d.pki.client_spec(&alice()), &key);
    t.refresh_certificate(renewed.clone(), |exporter| Ok(key.sign(exporter)))
        .await
        .unwrap();

    // A certificate for another key is refused, as is a bad signature.
    let other = KeyPair::generate();
    let foreign = d
        .pki
        .issue_client_with_key(&d.pki.client_spec(&alice()), &other);
    // Signed by the other key, so the outer path renews but the connector
    // refuses the session-bound refresh.
    t.refresh_certificate(foreign, |exporter| Ok(other.sign(exporter)))
        .await
        .unwrap();
    assert_eq!(
        next_notice(&mut events).await.reason,
        "certificate_refresh_failed",
        "foreign key"
    );
    t.refresh_certificate(renewed.clone(), |_| {
        Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    })
    .await
    .unwrap();
    assert_eq!(
        next_notice(&mut events).await.reason,
        "certificate_refresh_failed",
        "bad signature"
    );

    // Past the original certificate's expiry, the session lives on.
    tokio::time::sleep(Duration::from_secs(6)).await;
    echo_ok(&mut t, 46_001, b"after refresh").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_end_with_their_certificate() {
    let d = Deployment::start(Options::default()).await;
    let mut short = d.pki.client_spec(&alice());
    short.not_after = short.not_before + 63;
    let mut t =
        warren_client::connect(d.client_with(d.pki.issue_client(&short), TransportMode::QuicOnly))
            .await
            .unwrap();
    let mut events = t.events();
    echo_ok(&mut t, 47_000, b"while valid").await;
    let mut ended = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < deadline && !ended {
        match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Some(warren_client::ClientEvent::Closed(_))) => ended = true,
            Ok(Some(warren_client::ClientEvent::Notice(n))) => {
                assert!(n.reason.contains("expired"), "{n:?}")
            }
            _ => {}
        }
    }
    assert!(ended, "the session outlived its certificate");
}

/// A decision point that asks for a fresh MFA sign-in for everything.
#[derive(Debug)]
struct RequireStepUp;

impl warren_core::policy::PolicyDecisionPoint for RequireStepUp {
    fn decide(&self, req: &warren_core::policy::FlowRequest<'_>) -> warren_core::policy::Decision {
        let mut d = warren_core::policy::Decision::deny(
            warren_core::policy::Reason::MfaRequired,
            format!(
                "Sign in again with multi-factor authentication to reach {}.",
                req.app.name
            ),
            42,
        );
        d.rules = vec!["test/step-up".into()];
        d
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_enforcement_interface_takes_any_decision_point() {
    let d = Deployment::start(Options {
        policy: Some(std::sync::Arc::new(RequireStepUp)),
        ..Options::default()
    })
    .await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    t.send(&packet::udp(
        SocketAddr::new(v4(&t), 48_000),
        "10.77.0.10:7".parse().unwrap(),
        b"x",
    ));
    let _ = recv(&mut t).await;
    let denial = next_denial(&mut events).await;
    assert_eq!(denial.reason, "mfa_required");
    assert_eq!(
        denial.message,
        "Sign in again with multi-factor authentication to reach echo-udp."
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let records = d.audit_records();
    let r = find_record(&records, |r| r["status_code"] == "mfa_required");
    assert_eq!(r["policy"]["uid"], "test/step-up");
    assert_eq!(r["unmapped"]["warren"]["policy_version"], 42);
    // The invariants still come first: no decision point can open what is
    // outside every app.
    t.send(&packet::udp(
        SocketAddr::new(v4(&t), 48_001),
        "10.99.0.1:7".parse().unwrap(),
        b"x",
    ));
    let _ = recv(&mut t).await;
    assert_eq!(next_denial(&mut events).await.reason, "out_of_scope");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn name_bindings_follow_ownership_across_reloads() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    let synthetic: IpAddr = "100.80.0.9".parse().unwrap();
    t.bind_name(synthetic, "grafana.lab.test", "grafana")
        .await
        .unwrap();
    let src = SocketAddr::new(v4(&t), 49_000);
    t.send(&packet::udp(src, SocketAddr::new(synthetic, 7), b"bound"));
    let _ = recv(&mut t).await;

    // The next bundle drops the grafana app: its name now belongs to the
    // lab-web wildcard, so the old binding no longer admits flows.
    let mut v2 = warren_harness::deploy::test_bundle(2);
    let apps = v2["apps"].as_array_mut().unwrap();
    apps.retain(|a| a["name"] != "grafana");
    v2["rules"][0]["what"]["apps"] = serde_json::json!(["echo-udp", "echo-tcp", "pusher"]);
    d.connector
        .reload(warren_harness::deploy::compile(&v2))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    t.send(&packet::udp(
        SocketAddr::new(v4(&t), 49_001),
        SocketAddr::new(synthetic, 7),
        b"stale",
    ));
    let _ = recv(&mut t).await;
    assert_eq!(next_denial(&mut events).await.reason, "out_of_scope");
    // Binding it to its new owner works.
    t.bind_name(synthetic, "grafana.lab.test", "lab-web")
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewal_keeps_the_inner_session_on_its_replica() {
    use warren_harness::pki::KeyPair;
    let d = Deployment::start(Options {
        replicas: 2,
        ..Options::default()
    })
    .await;
    let key = KeyPair::generate();
    let creds = d
        .pki
        .issue_client_with_key(&d.pki.client_spec(&alice()), &key);
    let mut t = warren_client::connect(d.client_with(creds, TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    echo_ok(&mut t, 47_000, b"before renewal").await;
    let sessions = |c: &warren_connector::Connector| c.metrics().sessions_total.get();
    let holder = sessions(&d.connector);
    assert_eq!(holder + sessions(&d.replicas[0]), 1);

    // The replica holding the session carries this client's splice, so
    // least-loaded alone would send the renewed path to the other one.
    let renewed = d
        .pki
        .issue_client_with_key(&d.pki.client_spec(&alice()), &key);
    t.refresh_certificate(renewed, |exporter| Ok(key.sign(exporter)))
        .await
        .unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), events.recv()).await {
            Ok(Some(warren_client::ClientEvent::PathChanged { .. })) => break,
            Ok(Some(warren_client::ClientEvent::Closed(r))) => panic!("session closed: {r}"),
            Ok(Some(_)) => {}
            other => panic!("no path change: {other:?}"),
        }
    }
    echo_ok(&mut t, 47_001, b"after renewal").await;
    assert_eq!(sessions(&d.connector), holder);
    assert_eq!(sessions(&d.replicas[0]), 1 - holder);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn draining_keeps_sessions_and_stops_new_splices_on_either_carrier() {
    for transport in [TransportMode::QuicOnly, TransportMode::Http2Only] {
        let d = Deployment::start(Options {
            connector_transport: transport,
            ..Options::default()
        })
        .await;
        let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
            .await
            .unwrap();
        echo_ok(&mut t, 48_000, b"before the drain").await;
        let drain = d.connector.drain(Duration::from_secs(30));
        tokio::pin!(drain);
        let during = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            echo_ok(&mut t, 48_001, b"during the drain").await;
            match warren_client::connect(d.client(&alice(), TransportMode::QuicOnly)).await {
                Err(warren_client::ConnectError::Refused { error, details }) => {
                    assert_eq!(error, "destination_unavailable", "{transport:?}");
                    assert!(
                        details.contains("no connector of group"),
                        "{transport:?}: the relay should not splice to a draining replica: {details}"
                    );
                }
                other => panic!("{transport:?}: expected a refusal, got {other:?}"),
            }
        };
        tokio::select! {
            () = &mut drain => panic!("{transport:?}: the drain ended early"),
            () = during => {}
        }
        d.connector.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_icmp_errors_only_go_back_to_the_server() {
    let d = Deployment::start(Options::default()).await;
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let device = SocketAddr::new(v4(&t), 5556);
    let pusher: IpAddr = "10.77.0.40".parse().unwrap();
    d.backend.inject(packet::udp(
        SocketAddr::new(pusher, 9999),
        device,
        b"notify",
    ));
    let got = recv(&mut t).await;
    let pg = packet::parse(&got).unwrap();
    let err =
        packet::icmp_error(&got, &pg, packet::IcmpError::AdminProhibited, device.ip()).unwrap();
    let mut elsewhere = err.clone();
    let pe = packet::parse(&elsewhere).unwrap();
    let other: IpAddr = "10.77.0.20".parse().unwrap();
    packet::rewrite_addr(&mut elsewhere, &pe, packet::Side::Destination, other).unwrap();
    t.send(&elsewhere);
    t.send(&err);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let errors: Vec<IpAddr> = d
        .backend
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter_map(|s| packet::parse(s).ok())
        .filter(|p| p.icmp == Some((3, 13)))
        .map(|p| p.dst)
        .collect();
    assert_eq!(errors, vec![pusher]);
}

fn set_ipv4_fragmenting(pkt: &mut [u8], id: u16, dont_fragment: bool) {
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6] = if dont_fragment { 0x40 } else { 0 };
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ck = packet::checksum(&pkt[..20], 0);
    pkt[10..12].copy_from_slice(&ck.to_be_bytes());
}

/// A tunnel with a name-app flow from `port` to grafana.lab.test (bound to
/// 100.80.0.6, really 10.77.0.10:7).
async fn name_flow(d: &Deployment, port: u16) -> (warren_client::Tunnel, SocketAddr) {
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let synthetic: IpAddr = "100.80.0.6".parse().unwrap();
    t.bind_name(synthetic, "grafana.lab.test", "grafana")
        .await
        .unwrap();
    let src = SocketAddr::new(v4(&t), port);
    t.send(&packet::udp(src, SocketAddr::new(synthetic, 7), b"open"));
    let _ = recv(&mut t).await;
    (t, src)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn too_big_answers_go_to_the_real_server_of_a_name_flow() {
    let d = Deployment::start(Options::default()).await;
    let (_t, src) = name_flow(&d, 49_000).await;
    let real: SocketAddr = "10.77.0.10:7".parse().unwrap();
    let mut big = packet::udp(real, src, &[7; 1400]);
    set_ipv4_fragmenting(&mut big, 1, true);
    d.backend.inject(big);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let answers: Vec<IpAddr> = d
        .backend
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter_map(|s| packet::parse(s).ok())
        .filter(|p| p.icmp == Some((3, 4)))
        .map(|p| p.dst)
        .collect();
    assert_eq!(answers, vec![real.ip()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn return_fragments_need_a_flow_and_are_translated() {
    let d = Deployment::start(Options::default()).await;
    let (mut t, src) = name_flow(&d, 49_100).await;
    let real: SocketAddr = "10.77.0.10:7".parse().unwrap();
    let synthetic: IpAddr = "100.80.0.6".parse().unwrap();
    let fragments = |id: u16, from: SocketAddr| {
        let mut big = packet::udp(from, src, &[9; 1800]);
        set_ipv4_fragmenting(&mut big, id, false);
        let p = packet::parse(&big).unwrap();
        packet::fragment_v4(&big, &p, 1000).unwrap()
    };
    // A non-first fragment whose first fragment never matched a flow.
    let stray = fragments(77, "10.77.0.20:9999".parse().unwrap());
    d.backend.inject(stray[1].clone());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), t.recv())
            .await
            .is_err(),
        "a stray fragment reached the client"
    );
    for f in fragments(78, real) {
        d.backend.inject(f);
    }
    for _ in 0..2 {
        let got = recv(&mut t).await;
        let p = packet::parse(&got).unwrap();
        assert!(p.fragment.is_some());
        assert_eq!(
            p.src, synthetic,
            "every fragment comes from the synthetic address"
        );
        assert_eq!(p.dst, src.ip());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reloads_reach_every_session_of_a_device() {
    let d = Deployment::start(Options::default()).await;
    let mut first = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut first_events = first.events();
    echo_ok(&mut first, 49_200, b"first").await;
    // A second session from the same device takes over its addresses.
    let mut second = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut second_events = second.events();
    echo_ok(&mut second, 49_201, b"second").await;
    let mut v2 = warren_harness::deploy::test_bundle(2);
    v2["revoked"] = serde_json::json!({ "devices": ["mac-1"] });
    d.connector
        .reload(warren_harness::deploy::compile(&v2))
        .unwrap();
    for events in [&mut first_events, &mut second_events] {
        assert_eq!(next_notice(events).await.reason, "revoked");
    }
}

async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !ok() {
        assert!(std::time::Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bind_streams_roll_over_under_load_and_retire_when_drained() {
    // Ten devices, so each session owns its addresses.
    let mut bundle = warren_harness::deploy::test_bundle(1);
    let devices = bundle["devices"].as_array_mut().unwrap();
    for i in 0..10 {
        devices.push(serde_json::json!({ "id": format!("load-{i}"), "approved": true }));
    }
    // Context IDs 1, 3, 5 and 7 per stream before it rolls over.
    let d = Deployment::start(Options {
        bind_rollover: 7,
        bundle,
        ..Options::default()
    })
    .await;
    let mut tunnels = Vec::new();
    for i in 0..10u16 {
        let cert = warren_harness::pki::ClientCert::new(
            "alice",
            &format!("load-{i}"),
            &format!("100.96.1.{}", i + 1),
            &format!("fd00:7761:7272:6e00::1:{}", i + 1),
        );
        let mut t = warren_client::connect(d.client(&cert, TransportMode::QuicOnly))
            .await
            .unwrap();
        echo_ok(&mut t, 50_000 + i, b"load").await;
        tunnels.push(t);
    }
    let m = d.relay().metrics();
    assert!(m.rollovers.get() >= 2, "rollovers: {}", m.rollovers.get());
    assert!(m.attachments.get() >= 2, "fresh streams opened alongside");
    for (i, t) in tunnels.iter_mut().enumerate() {
        echo_ok(t, 50_100 + i as u16, b"still here").await;
    }
    // The rolled-over streams drain as their clients leave, then close; the
    // newest stream carries on.
    for t in &tunnels {
        t.close();
    }
    drop(tunnels);
    eventually("rolled-over streams retired", || {
        m.retired.get() == m.rollovers.get() && m.attachments.get() == 1
    })
    .await;
    assert_eq!(d.connector.metrics().attachments.get(), 1);
    let mut t = warren_client::connect(d.client(&alice(), TransportMode::QuicOnly))
        .await
        .unwrap();
    echo_ok(&mut t, 50_200, b"after retirement").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewals_stay_on_their_replica_across_rollover() {
    use warren_harness::pki::KeyPair;
    // Context IDs 1, 3 and 5 per stream before it rolls over.
    let d = Deployment::start(Options {
        replicas: 2,
        bind_rollover: 5,
        ..Options::default()
    })
    .await;
    let key = KeyPair::generate();
    let creds = d
        .pki
        .issue_client_with_key(&d.pki.client_spec(&alice()), &key);
    let mut t = warren_client::connect(d.client_with(creds, TransportMode::QuicOnly))
        .await
        .unwrap();
    let mut events = t.events();
    echo_ok(&mut t, 51_000, b"before").await;
    let sessions = |c: &warren_connector::Connector| c.metrics().sessions_total.get();
    let holder = sessions(&d.connector);
    let renewed = d
        .pki
        .issue_client_with_key(&d.pki.client_spec(&alice()), &key);
    // Every renewal costs the holder's stream a context ID.
    for round in 0..6u16 {
        t.refresh_certificate(renewed.clone(), |exporter| Ok(key.sign(exporter)))
            .await
            .unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(10), events.recv()).await {
                Ok(Some(warren_client::ClientEvent::PathChanged { .. })) => break,
                Ok(Some(warren_client::ClientEvent::Closed(r))) => {
                    panic!("round {round}: session closed: {r}")
                }
                Ok(Some(_)) => {}
                other => panic!("round {round}: no path change: {other:?}"),
            }
        }
        echo_ok(&mut t, 51_001 + round, b"renewed").await;
    }
    assert_eq!(sessions(&d.connector), holder, "the session stayed put");
    assert_eq!(sessions(&d.replicas[0]), 1 - holder);
    let m = d.relay().metrics();
    assert!(m.rollovers.get() >= 2, "rollovers: {}", m.rollovers.get());
    // Every rolled-over stream but one still holding the client's splice
    // drains and closes.
    eventually("drained streams retired", || {
        let (rolled, retired) = (m.rollovers.get(), m.retired.get());
        retired + 1 >= rolled && m.attachments.get() == 2 + rolled - retired
    })
    .await;
    assert!(m.retired.get() >= 1);
}
