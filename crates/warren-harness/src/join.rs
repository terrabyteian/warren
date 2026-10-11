//! A stand-in for the control plane's join endpoint (docs/protocol.md
//! section 10.3), issuing from the test PKI. It shows the issuer's side of
//! the exchange: single-use, expiring, role- and group-scoped tokens whose
//! secret is compared in constant time, and a certificate request whose
//! self-signature is verified before anything is issued.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use serde_json::json;
use tokio::net::TcpListener;
use warren_core::join::{self, BundleJson, JoinRequest, JoinResponse, JoinToken, sha256_hex};
use warren_core::{base64, params};
use warren_masque::h2::{H2Server, recv_chunk, send_all};
use warren_masque::http::ResponseHead;

use crate::pki::TestPki;

struct Minted {
    secret: Vec<u8>,
    role: String,
    group: Option<String>,
    dns: Vec<String>,
    exp: u64,
    used: bool,
}

/// A running join endpoint.
pub struct JoinServer {
    /// Where it listens.
    pub addr: SocketAddr,
    /// The name it answers to.
    pub name: String,
    tokens: Arc<Mutex<HashMap<String, Minted>>>,
    pki: Arc<TestPki>,
}

impl std::fmt::Debug for JoinServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinServer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut b)
        .expect("CSPRNG");
    b
}

impl JoinServer {
    /// Starts the endpoint on loopback, answering as `name`.
    pub async fn start(pki: Arc<TestPki>, name: &str) -> std::io::Result<JoinServer> {
        // Dual-stack, so a name resolving to either family reaches it.
        Self::start_on(pki, name, "[::]:0".parse().expect("valid")).await
    }

    /// Starts the endpoint on `listen`, answering as `name`.
    pub async fn start_on(
        pki: Arc<TestPki>,
        name: &str,
        listen: SocketAddr,
    ) -> std::io::Result<JoinServer> {
        let creds = pki.control_plane("cp1", &[name]);
        let mut config = rustls::ServerConfig::builder_with_provider(warren_core::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(std::io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(creds.chain, creds.key)
            .map_err(std::io::Error::other)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = warren_masque::tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(listen).await?;
        let addr = listener.local_addr()?;
        let tokens: Arc<Mutex<HashMap<String, Minted>>> = Arc::default();
        let (t, p) = (tokens.clone(), pki.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, t, p) = (acceptor.clone(), t.clone(), p.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut h2) = H2Server::handshake(tls).await else {
                        return;
                    };
                    // The connection only makes progress while accept()
                    // is polled, so each request is handled in its own task.
                    while let Some(Ok(mut req)) = h2.accept().await {
                        let (t, p) = (t.clone(), p.clone());
                        tokio::spawn(async move {
                            let mut body = BytesMut::new();
                            while let Ok(Some(c)) = recv_chunk(&mut req.recv).await {
                                if body.len() + c.len() > 64 * 1024 {
                                    break;
                                }
                                body.extend_from_slice(&c);
                            }
                            let (status, out) =
                                match (req.head.method.as_str(), req.head.path.as_deref()) {
                                    ("POST", Some(join::JOIN_PATH)) => handle(&t, &p, &body),
                                    _ => (404, json!({ "title": "not found" })),
                                };
                            let head =
                                ResponseHead::new(status).with("content-type", "application/json");
                            if let Ok(mut send) = req.respond(&head, false) {
                                let _ = send_all(&mut send, Bytes::from(out.to_string())).await;
                                let _ = send.send_data(Bytes::new(), true);
                            }
                        });
                    }
                });
            }
        });
        Ok(JoinServer {
            addr,
            name: name.to_owned(),
            tokens,
            pki,
        })
    }

    /// Mints a token for a relay (with its DNS names) or a connector in a
    /// group.
    pub fn mint(&self, group: Option<&str>, dns: &[&str]) -> JoinToken {
        let id = base64::encode_url(&random(9));
        let secret = random(32);
        let exp = now() + params::JOIN_TOKEN_LIFETIME.as_secs();
        let role = if group.is_some() {
            "connector"
        } else {
            "relay"
        };
        self.tokens.lock().expect("tokens lock").insert(
            id.clone(),
            Minted {
                secret: secret.clone(),
                role: role.to_owned(),
                group: group.map(str::to_owned),
                dns: dns.iter().map(|d| (*d).to_owned()).collect(),
                exp,
                used: false,
            },
        );
        JoinToken {
            td: self.pki.trust_domain.clone(),
            cp: format!("{}:{}", self.name, self.addr.port()),
            role: role.to_owned(),
            group: group.map(str::to_owned),
            root: sha256_hex(&self.pki.root.cert),
            id,
            secret: base64::encode_url(&secret),
            exp,
        }
    }
}

fn problem(status: u16, detail: &str) -> (u16, serde_json::Value) {
    (status, json!({ "title": "join refused", "detail": detail }))
}

fn handle(
    tokens: &Mutex<HashMap<String, Minted>>,
    pki: &TestPki,
    body: &[u8],
) -> (u16, serde_json::Value) {
    let Ok(req) = serde_json::from_slice::<JoinRequest>(body) else {
        return problem(400, "malformed request");
    };
    let Ok(token) = JoinToken::parse(&req.token, now()) else {
        return problem(401, "invalid or expired token");
    };
    let presented = base64::decode_url(&token.secret).unwrap_or_default();
    let mut all = tokens.lock().expect("tokens lock");
    let Some(minted) = all.get_mut(&token.id) else {
        return problem(401, "unknown token");
    };
    if aws_lc_rs::constant_time::verify_slices_are_equal(&minted.secret, &presented).is_err() {
        return problem(401, "unknown token");
    }
    if minted.used {
        return problem(409, "token already used");
    }
    if minted.exp <= now() || minted.role != token.role || minted.group != token.group {
        return problem(401, "token out of scope");
    }
    let Some(csr) = base64::decode(&req.csr) else {
        return problem(400, "malformed certificate request");
    };
    let spki = match join::verify_certificate_request(&csr) {
        Ok(s) => s,
        Err(e) => return problem(400, &e.to_string()),
    };
    // Spend the token only once the request is known good.
    minted.used = true;
    let node_id = format!("n{}", base64::encode_url(&random(6)));
    let uri = match &minted.group {
        Some(g) => format!("warren://{}/connector/{g}/{node_id}", pki.trust_domain),
        None => format!("warren://{}/relay/{node_id}", pki.trust_domain),
    };
    let dns: Vec<&str> = minted.dns.iter().map(String::as_str).collect();
    let chain = pki.issue_infra_for(&pki.infra_spec(&uri, &dns), &spki);
    let response = JoinResponse {
        chain: chain.iter().map(|c| base64::encode(c)).collect(),
        trust_bundle: BundleJson {
            root: base64::encode(&pki.root.cert),
            client_cas: vec![base64::encode(&pki.client_ca.cert)],
            infra_cas: vec![base64::encode(&pki.infra_ca.cert)],
        },
    };
    (
        200,
        serde_json::to_value(response).expect("response serializes"),
    )
}
