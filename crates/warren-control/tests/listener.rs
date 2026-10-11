//! The HTTPS listener: an operator-supplied certificate on the public host
//! for sign-in and enrollment, with the infrastructure certificate kept for
//! everything else, its reload, the per-source cap on unauthenticated
//! connections, and sources named by trusted proxies.

mod support;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::{Value, json};
use support::{IdpUser, RunningIdp, StubNode, TempDir, TestCa, free_port, pem_certs, write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use warren_control::config::Config;
use warren_control::web::{
    self, Body, Handler, ListenOptions, MAX_CONNECTIONS_PER_SOURCE, Peer, ServerCert,
};
use warren_control::{ControlPlane, Error, admin_request};
use warren_core::base64::pem;
use warren_core::join::JoinToken;
use warren_core::keys::SigningKey;
use warren_core::pki::oid;
use warren_policy::names::Cidr;

const PUBLIC_HOST: &str = "warren.example.test";
/// How the configuration spells it: hosts are case-insensitive.
const PUBLIC_HOST_AS_WRITTEN: &str = "Warren.Example.Test";
const INTERNAL_HOST: &str = "localhost";

/// A throwaway CA and a server certificate it issued for `host`.
struct OperatorPki {
    ca: Vec<u8>,
    leaf: Vec<u8>,
    chain_pem: String,
    key_pem: String,
}

impl OperatorPki {
    fn new(host: &str) -> OperatorPki {
        let ca = TestCa::new("operator CA");
        let key = SigningKey::generate().unwrap();
        let leaf = ca.leaf(&key, &[host], &[], &[oid::SERVER_AUTH]);
        OperatorPki {
            chain_pem: pem("CERTIFICATE", &leaf) + &pem("CERTIFICATE", &ca.der),
            key_pem: pem("PRIVATE KEY", &key.to_pkcs8().unwrap()),
            ca: ca.der,
            leaf,
        }
    }

    fn write(&self, dir: &TempDir) {
        write(&dir.path().join("tls/cert.pem"), &self.chain_pem);
        write(&dir.path().join("tls/key.pem"), &self.key_pem);
    }
}

/// A TLS client trusting only `roots`, offering `h2` and `http/1.1`.
fn connector(roots: &[&[u8]]) -> TlsConnector {
    let mut store = RootCertStore::empty();
    for der in roots {
        store.add(CertificateDer::from(der.to_vec())).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(store)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
}

/// Connects to 127.0.0.1:`port` asking for `host`.
async fn handshake(
    port: u16,
    host: &str,
    roots: &[&[u8]],
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    connector(roots)
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
}

/// The leaf certificate the server presented for `host`, verified against
/// `roots`.
async fn presented(port: u16, host: &str, roots: &[&[u8]]) -> std::io::Result<Vec<u8>> {
    let tls = handshake(port, host, roots).await?;
    Ok(tls.get_ref().1.peer_certificates().unwrap()[0].to_vec())
}

async fn start(dir: &TempDir, idp: &RunningIdp, port: u16) -> Result<ControlPlane, Error> {
    std::fs::create_dir_all(dir.path().join("policy")).unwrap();
    write(&dir.path().join("idp-ca.pem"), &idp.pki.ca_pem);
    let mut config = Config::parse(&format!(
        "trustDomain: example.test\n\
         publicUrl: https://{PUBLIC_HOST_AS_WRITTEN}:{port}\n\
         dnsNames: [{INTERNAL_HOST}]\n\
         tls:\n  certFile: tls/cert.pem\n  keyFile: tls/key.pem\n\
         listen: 127.0.0.1:{port}\n\
         dataDir: data\n\
         policyDir: policy\n\
         idp:\n  issuer: {issuer}\n  clientId: warren\n  caFile: idp-ca.pem\n",
        issuer = idp.idp.issuer,
    ))
    .unwrap();
    config.resolve_paths(dir.path());
    ControlPlane::start(config).await
}

async fn idp() -> RunningIdp {
    RunningIdp::start(IdpUser {
        sub: "00u-ada".into(),
        email: "ada@example.com".into(),
        groups: vec![],
        amr: vec![],
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_public_host_presents_the_operator_certificate() {
    let dir = TempDir::new("operator-cert");
    let idp = idp().await;
    let first = OperatorPki::new(PUBLIC_HOST);
    first.write(&dir);
    let port = free_port();
    let cp = start(&dir, &idp, port).await.unwrap();
    let bundle = cp.app().authority.trust_bundle();

    // A browser trusting only the operator's CA reaches the public host.
    let tls = handshake(port, PUBLIC_HOST, &[&first.ca]).await.unwrap();
    assert_eq!(
        tls.get_ref().1.peer_certificates().unwrap()[0].as_ref(),
        first.leaf
    );
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = sender
        .send_request(
            Request::get("/.well-known/warren")
                .header("host", PUBLIC_HOST)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let discovery: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(discovery["trust_domain"], "example.test");
    // Calls after enrollment are refused there: they belong where the
    // trust bundle verifies the control plane.
    let resp = sender
        .send_request(
            Request::get("/v1/entitlements")
                .header("host", PUBLIC_HOST)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    let problem: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(problem["reason"], "misdirected_request");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains(&format!("https://{INTERNAL_HOST}:{port}/v1")),
        "{problem}"
    );

    // The trust bundle does not vouch for the public host any more, but
    // still does for the internal name, where relays and connectors join,
    // fetch bundles and hold their event streams.
    let roots: Vec<Vec<u8>> = pem_certs(&bundle);
    let roots: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
    assert!(handshake(port, PUBLIC_HOST, &roots).await.is_err());
    assert!(handshake(port, INTERNAL_HOST, &[&first.ca]).await.is_err());
    let socket = cp.admin_socket.clone();
    let (status, body) = tokio::task::spawn_blocking(move || {
        admin_request(
            &socket,
            "POST",
            "/v1/admin/join-tokens",
            Some(r#"{"role":"relay","name":"relay1"}"#.into()),
        )
        .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(status, 201, "{body}");
    let token: Value = serde_json::from_str(&body).unwrap();
    let base = format!("https://{INTERNAL_HOST}:{port}");
    assert_eq!(token["control_plane"], base);
    let parsed = JoinToken::parse(
        token["token"].as_str().unwrap(),
        warren_core::clock::now_secs().unsigned_abs(),
    )
    .unwrap();
    assert_eq!(parsed.cp, format!("{INTERNAL_HOST}:{port}"));
    let node = StubNode::join(&base, token["token"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(node.get("/v1/node/bundle").await.status, StatusCode::OK);
    let mut events = node.events(None).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .unwrap()
            .is_some()
    );

    // Nothing changed on disk, so nothing reloads.
    assert_eq!(cp.reload_certificate(), Ok(false));

    // Replaced files are picked up on reload.
    let second = OperatorPki::new(PUBLIC_HOST);
    second.write(&dir);
    assert_eq!(cp.reload_certificate(), Ok(true));
    assert_eq!(
        presented(port, PUBLIC_HOST, &[&second.ca]).await.unwrap(),
        second.leaf
    );
    assert!(handshake(port, PUBLIC_HOST, &[&first.ca]).await.is_err());

    // A key that does not match is refused, and the last good certificate
    // stays in use.
    let third = OperatorPki::new(PUBLIC_HOST);
    write(&dir.path().join("tls/key.pem"), &third.key_pem);
    let e = cp.reload_certificate().unwrap_err();
    assert!(e.to_string().contains("does not match"), "{e}");
    assert_eq!(
        presented(port, PUBLIC_HOST, &[&second.ca]).await.unwrap(),
        second.leaf
    );
    write(&dir.path().join("tls/key.pem"), "not a key");
    assert!(cp.reload_certificate().is_err());
    assert_eq!(
        presented(port, PUBLIC_HOST, &[&second.ca]).await.unwrap(),
        second.leaf
    );

    // The internal name kept the infrastructure certificate throughout.
    assert!(presented(port, INTERNAL_HOST, &roots).await.is_ok());
    assert_eq!(node.get("/v1/node/bundle").await.status, StatusCode::OK);
    cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_that_does_not_load_stops_startup() {
    let idp = idp().await;

    let dir = TempDir::new("operator-cert-missing");
    let e = start(&dir, &idp, free_port()).await.err().unwrap();
    assert!(
        matches!(&e, Error::Config(m) if m.contains("cert.pem")),
        "{e}"
    );

    let dir = TempDir::new("operator-cert-mismatch");
    OperatorPki::new(PUBLIC_HOST).write(&dir);
    write(
        &dir.path().join("tls/key.pem"),
        &OperatorPki::new(PUBLIC_HOST).key_pem,
    );
    let e = start(&dir, &idp, free_port()).await.err().unwrap();
    assert!(
        matches!(&e, Error::Config(m) if m.contains("does not match")),
        "{e}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_source_cannot_hold_every_connection() {
    let idp = idp().await;
    let port: u16 = idp.idp.issuer.rsplit(':').next().unwrap().parse().unwrap();
    let ca = pem_certs(&idp.pki.ca_pem).remove(0);

    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_SOURCE {
        held.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    }
    // The source is at its cap: the next connection is closed at once.
    assert!(handshake(port, "localhost", &[&ca]).await.is_err());

    // Once the source lets some go, it can connect again.
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match handshake(port, "localhost", &[&ca]).await {
            Ok(_) => break,
            Err(e) if Instant::now() > deadline => panic!("still refused: {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Answers every request with the source and whether the peer presented a
/// certificate.
struct Echo;

impl Handler for Echo {
    async fn handle(self: Arc<Self>, _req: Request<Incoming>, peer: Arc<Peer>) -> Response<Body> {
        web::json(
            StatusCode::OK,
            &json!({
                "source": peer.addr.map(|a| a.to_string()),
                "authenticated": !peer.certificates.is_empty(),
            }),
        )
    }
}

/// A CA, a server certificate for localhost and a client certificate.
struct EchoPki {
    ca: Vec<u8>,
    server: (Vec<Vec<u8>>, Vec<u8>),
    client: (Vec<Vec<u8>>, Vec<u8>),
}

impl EchoPki {
    fn new() -> EchoPki {
        let ca = TestCa::new("echo CA");
        let server_key = SigningKey::generate().unwrap();
        let server = ca.leaf(&server_key, &["localhost"], &[], &[oid::SERVER_AUTH]);
        let client_key = SigningKey::generate().unwrap();
        let client = ca.leaf(
            &client_key,
            &[],
            &["warren://example.test/relay/n-1"],
            &[oid::CLIENT_AUTH],
        );
        EchoPki {
            server: (
                vec![server, ca.der.clone()],
                server_key.to_pkcs8().unwrap().to_vec(),
            ),
            client: (
                vec![client, ca.der.clone()],
                client_key.to_pkcs8().unwrap().to_vec(),
            ),
            ca: ca.der,
        }
    }

    /// Serves [`Echo`] on 127.0.0.1 with `options`, requiring nothing of
    /// clients but checking any certificate they present.
    async fn serve(&self, options: ListenOptions) -> (u16, tokio::sync::watch::Sender<bool>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cert = ServerCert::new(self.server.0.clone(), &self.server.1, vec![]).unwrap();
        let config = web::server_config(Arc::new(cert), std::slice::from_ref(&self.ca)).unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(web::serve_tls(
            listener,
            config,
            Arc::new(Echo),
            options,
            rx,
        ));
        (port, tx)
    }

    /// A TLS client trusting the CA, presenting the client certificate
    /// when `authenticate`.
    fn connector(&self, authenticate: bool) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.ca.clone())).unwrap();
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
        let mut config = if authenticate {
            builder
                .with_client_auth_cert(
                    self.client
                        .0
                        .iter()
                        .cloned()
                        .map(CertificateDer::from)
                        .collect(),
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.client.1.clone())),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsConnector::from(Arc::new(config))
    }
}

/// Completes TLS over `tcp` and asks the echo server who it thinks we are.
async fn echo(tcp: TcpStream, connector: &TlsConnector) -> std::io::Result<(Value, Held)> {
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(std::io::Error::other)?;
    let task = tokio::spawn(conn);
    let resp = sender
        .send_request(
            Request::get("/")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .map_err(std::io::Error::other)?;
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    Ok((
        serde_json::from_slice(&body).unwrap(),
        Held {
            _sender: sender,
            task,
        },
    ))
}

/// Keeps a connection open until dropped.
struct Held {
    _sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    task: tokio::task::JoinHandle<Result<(), hyper::Error>>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_unauthenticated_connections_count_against_their_source() {
    let pki = EchoPki::new();
    let (port, _stop) = pki
        .serve(ListenOptions {
            max_per_source: 2,
            trusted_proxies: vec![],
        })
        .await;
    let connect = || TcpStream::connect(("127.0.0.1", port));

    // Connections with a client certificate stop counting once verified.
    let mut held = Vec::new();
    for _ in 0..4 {
        let (who, conn) = echo(connect().await.unwrap(), &pki.connector(true))
            .await
            .unwrap();
        assert_eq!(who["authenticated"], true);
        held.push(conn);
    }

    // Two anonymous connections fill the source's allowance.
    let raw = [connect().await.unwrap(), connect().await.unwrap()];
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        echo(connect().await.unwrap(), &pki.connector(false))
            .await
            .is_err()
    );
    drop(raw);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match echo(connect().await.unwrap(), &pki.connector(false)).await {
            Ok((who, _)) => {
                assert_eq!(who["authenticated"], false);
                break;
            }
            Err(e) if Instant::now() > deadline => panic!("still refused: {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }

    // 0 turns the limit off.
    let (open_port, _stop) = pki
        .serve(ListenOptions {
            max_per_source: 0,
            trusted_proxies: vec![],
        })
        .await;
    let mut raw = Vec::new();
    for _ in 0..8 {
        raw.push(TcpStream::connect(("127.0.0.1", open_port)).await.unwrap());
    }
    let tcp = TcpStream::connect(("127.0.0.1", open_port)).await.unwrap();
    assert!(echo(tcp, &pki.connector(false)).await.is_ok());
}

/// A PROXY protocol version 2 header: `PROXY` for TCP over IPv4 from
/// `source`, or `LOCAL` when there is none.
fn proxy_header(source: Option<SocketAddrV4>) -> Vec<u8> {
    let mut out = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    match source {
        Some(src) => {
            out.extend([0x21, 0x11, 0, 12]);
            out.extend(src.ip().octets());
            out.extend([127, 0, 0, 1]);
            out.extend(src.port().to_be_bytes());
            out.extend(443u16.to_be_bytes());
        }
        None => out.extend([0x20, 0x00, 0, 0]),
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_proxies_name_the_real_source() {
    let pki = EchoPki::new();
    let (port, _stop) = pki
        .serve(ListenOptions {
            max_per_source: 1,
            trusted_proxies: vec![Cidr::parse("127.0.0.0/8").unwrap()],
        })
        .await;
    let via_proxy = |header: Vec<u8>| async move {
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tcp.write_all(&header).await.unwrap();
        tcp
    };
    let ada = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 5555);
    let (who, _first) = echo(
        via_proxy(proxy_header(Some(ada))).await,
        &pki.connector(false),
    )
    .await
    .unwrap();
    assert_eq!(who["source"], "203.0.113.7:5555");

    // The limit applies to the source the proxy names, not to the proxy.
    assert!(
        echo(
            via_proxy(proxy_header(Some(ada))).await,
            &pki.connector(false)
        )
        .await
        .is_err()
    );
    let bob = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 6000);
    let (who, _second) = echo(
        via_proxy(proxy_header(Some(bob))).await,
        &pki.connector(false),
    )
    .await
    .unwrap();
    assert_eq!(who["source"], "198.51.100.1:6000");

    // The proxy's own health checks use LOCAL and count as the proxy.
    let (who, _third) = echo(via_proxy(proxy_header(None)).await, &pki.connector(true))
        .await
        .unwrap();
    assert!(who["source"].as_str().unwrap().starts_with("127.0.0.1:"));

    // A trusted proxy that sends no header is refused.
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(echo(tcp, &pki.connector(true)).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_header_from_an_untrusted_address_is_refused_before_tls() {
    let pki = EchoPki::new();
    let (port, _stop) = pki.serve(ListenOptions::default()).await;
    let ada = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 5555);
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(&proxy_header(Some(ada))).await.unwrap();
    // Closed without a word: no TLS alert, as a header fed to the TLS
    // handshake would draw.
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut answer))
        .await
        .expect("the connection stayed open");
    assert!(
        read.is_err() || answer.is_empty(),
        "got {} bytes back",
        answer.len()
    );

    // An ordinary connection from the same address still works.
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(echo(tcp, &pki.connector(false)).await.is_ok());
}
