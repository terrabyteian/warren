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
