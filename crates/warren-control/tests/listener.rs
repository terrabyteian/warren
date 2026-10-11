//! The HTTPS listener: an operator-supplied certificate on the public host
//! with the infrastructure certificate kept for relays and connectors, its
//! reload, and the per-source connection cap.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::Value;
use support::{IdpUser, RunningIdp, StubNode, TempDir, free_port, write};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use warren_control::config::Config;
use warren_control::web::MAX_CONNECTIONS_PER_SOURCE;
use warren_control::{ControlPlane, Error, admin_request};
use warren_core::clock;
use warren_core::keys::SigningKey;
use warren_core::x509::{self, CertificateSpec, EMPTY_NAME, IssuerInfo, Usage};

const PUBLIC_HOST: &str = "warren.example.test";
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
        let ca_key = SigningKey::generate().unwrap();
        let name = x509::common_name("operator CA");
        let now = clock::now_secs();
        let issuer = IssuerInfo {
            name: name.clone(),
            key_id: ca_key.public_key().key_id(),
        };
        let ca = x509::build_certificate(
            &CertificateSpec {
                serial: [1; 16],
                not_before: now - 60,
                not_after: now + 86_400,
                subject: name,
                public_key: ca_key.public_key(),
                usage: Usage::Ca { path_len: 0 },
                uris: vec![],
                dns_names: vec![],
                identity: None,
            },
            &issuer,
            |tbs| ca_key.sign_der(tbs),
        )
        .unwrap();
        let key = SigningKey::generate().unwrap();
        let leaf = x509::build_certificate(
            &CertificateSpec {
                serial: [2; 16],
                not_before: now - 60,
                not_after: now + 86_400,
                subject: EMPTY_NAME.to_vec(),
                public_key: key.public_key(),
                usage: Usage::Leaf {
                    server_auth: true,
                    client_auth: false,
                },
                uris: vec![],
                dns_names: vec![host.into()],
                identity: None,
            },
            &issuer,
            |tbs| ca_key.sign_der(tbs),
        )
        .unwrap();
        OperatorPki {
            chain_pem: x509::pem_encode("CERTIFICATE", &leaf)
                + &x509::pem_encode("CERTIFICATE", &ca),
            key_pem: x509::pem_encode("PRIVATE KEY", &key.to_pkcs8().unwrap()),
            ca,
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
         publicUrl: https://{PUBLIC_HOST}:{port}\n\
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

    // The trust bundle does not vouch for the public host any more, but
    // still does for the internal name, where relays and connectors join,
    // fetch bundles and hold their event streams.
    let roots: Vec<Vec<u8>> = x509::pem_decode("CERTIFICATE", &bundle).unwrap();
    let roots: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
    assert!(handshake(port, PUBLIC_HOST, &roots).await.is_err());
    assert!(handshake(port, INTERNAL_HOST, &[&first.ca]).await.is_err());
    let socket = cp.admin_socket.clone();
    let (status, body) = tokio::task::spawn_blocking(move || {
        admin_request(
            &socket,
            "POST",
            "/v1/admin/join-tokens",
            Some(r#"{"role":"relay"}"#.into()),
        )
        .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(status, 201, "{body}");
    let token: Value = serde_json::from_str(&body).unwrap();
    let base = format!("https://{INTERNAL_HOST}:{port}");
    let node = StubNode::join(
        &base,
        token["token"].as_str().unwrap(),
        "relay1",
        &[],
        &bundle,
    )
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
    let ca = x509::pem_decode("CERTIFICATE", &idp.pki.ca_pem)
        .unwrap()
        .remove(0);

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
