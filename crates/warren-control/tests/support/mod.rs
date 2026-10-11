//! Test fixtures: a scratch directory, a small OIDC provider served over
//! HTTPS, a simulated client with a software device key, and a stub node
//! that joins and listens to the revocation push channel.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use rustls::pki_types::PrivateKeyDer;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use warren_control::web::{self, Body, Client, Handler, Peer, Reply};
use warren_core::api::{
    CertificateRequest, CertificateResponse, DeviceInfo, EnrollRequest, Entitlements, Platform,
    SESSION_REQUEST_TYP, Session, SessionRequest,
};
use warren_core::cert::{self, CertSpec};
use warren_core::clock;
use warren_core::events::{Ack, AckRequest, Line};
use warren_core::identity::NodeRole;
use warren_core::join::{self, JoinToken, NodeKey};
use warren_core::jose::{self, Header, Jwk, b64url};
use warren_core::keys::{SigningKey, hex, random_bytes, sha256};
use warren_core::pki::{TrustBundle, oid};

/// A directory removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "warren-{name}-{}",
            hex(&random_bytes::<6>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A port that was free a moment ago.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A throwaway CA for test servers and clients.
pub struct TestCa {
    key: SigningKey,
    /// The CA certificate, DER.
    pub der: Vec<u8>,
    name: Vec<u8>,
    key_id: Vec<u8>,
}

impl TestCa {
    pub fn new(cn: &str) -> TestCa {
        let key = SigningKey::generate().unwrap();
        let spki = cert::p256_spki(key.public_key().point());
        let name = cert::name(Some(cn));
        let key_id = cert::spki_key_id(&spki).unwrap();
        let der = cert::issue(&CertSpec::ca(cn), &spki, &name, &key_id, |tbs| {
            key.sign_der(tbs)
        })
        .unwrap();
        TestCa {
            key,
            der,
            name,
            key_id,
        }
    }

    /// A day-long leaf for `key` with these names and extended key usages.
    pub fn leaf(&self, key: &SigningKey, dns: &[&str], uris: &[&str], eku: &[&[u8]]) -> Vec<u8> {
        let mut spec = CertSpec::leaf(86_400);
        spec.san_dns = dns.iter().map(|d| (*d).to_owned()).collect();
        spec.san_uris = uris.iter().map(|u| (*u).to_owned()).collect();
        spec.eku = eku.iter().map(|o| o.to_vec()).collect();
        cert::issue(
            &spec,
            &cert::p256_spki(key.public_key().point()),
            &self.name,
            &self.key_id,
            |tbs| self.key.sign_der(tbs),
        )
        .unwrap()
    }
}

/// Every certificate in PEM text, DER.
pub fn pem_certs(text: &str) -> Vec<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_slice_iter(text.as_bytes())
        .map(|c| c.unwrap().to_vec())
        .collect()
}

/// A CA and a TLS server certificate for `localhost`, for the test IdP.
pub struct TestPki {
    pub ca_pem: String,
    pub chain: Vec<Vec<u8>>,
    pub key_pkcs8: Vec<u8>,
}

impl TestPki {
    pub fn new() -> TestPki {
        let ca = TestCa::new("test IdP CA");
        let key = SigningKey::generate().unwrap();
        let leaf = ca.leaf(&key, &["localhost"], &[], &[oid::SERVER_AUTH]);
        TestPki {
            ca_pem: warren_core::base64::pem("CERTIFICATE", &ca.der),
            chain: vec![leaf, ca.der],
            key_pkcs8: key.to_pkcs8().unwrap().to_vec(),
        }
    }
}

/// The person the test IdP signs in next.
#[derive(Clone, Debug)]
pub struct IdpUser {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
    pub amr: Vec<String>,
}

struct PendingCode {
    nonce: String,
    challenge: String,
    redirect_uri: String,
    user: IdpUser,
}

/// A small OIDC provider: discovery, an authorization endpoint that signs
/// the current user in without a form, a token endpoint that checks PKCE
/// and the client secret, and a JWKS. ID tokens are ES256.
pub struct TestIdp {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub user: Mutex<IdpUser>,
    key: SigningKey,
    codes: Mutex<HashMap<String, PendingCode>>,
    pub token_requests: Mutex<u32>,
    /// The query of every authorization request, oldest first.
    pub authorize_requests: Mutex<Vec<HashMap<String, String>>>,
    /// Leave `auth_time` out of ID tokens, as some IdPs do.
    pub omit_auth_time: Mutex<bool>,
}

impl Handler for TestIdp {
    async fn handle(self: Arc<Self>, req: Request<Incoming>, _peer: Arc<Peer>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        match (req.method().clone(), path.as_str()) {
            (Method::GET, "/.well-known/openid-configuration") => web::json(
                StatusCode::OK,
                &json!({
                    "issuer": self.issuer,
                    "authorization_endpoint": format!("{}/authorize", self.issuer),
                    "token_endpoint": format!("{}/token", self.issuer),
                    "jwks_uri": format!("{}/jwks", self.issuer),
                    "response_types_supported": ["code"],
                    "id_token_signing_alg_values_supported": ["ES256"],
                }),
            ),
            (Method::GET, "/jwks") => {
                let mut jwk = serde_json::to_value(Jwk::from_key(self.key.public_key())).unwrap();
                jwk["use"] = json!("sig");
                jwk["alg"] = json!("ES256");
                web::json(StatusCode::OK, &json!({ "keys": [jwk] }))
            }
            (Method::GET, "/authorize") => {
                let q = web::query(&req).unwrap();
                self.authorize_requests
                    .lock()
                    .unwrap()
                    .push(q.iter().cloned().collect());
                let get = |k: &str| web::param(&q, k).unwrap_or("").to_owned();
                assert_eq!(get("response_type"), "code");
                assert_eq!(get("client_id"), self.client_id);
                assert_eq!(get("code_challenge_method"), "S256");
                assert!(get("scope").split(' ').any(|s| s == "openid"));
                let code = b64url(&random_bytes::<16>().unwrap());
                self.codes.lock().unwrap().insert(
                    code.clone(),
                    PendingCode {
                        nonce: get("nonce"),
                        challenge: get("code_challenge"),
                        redirect_uri: get("redirect_uri"),
                        user: self.user.lock().unwrap().clone(),
                    },
                );
                let location = format!(
                    "{}?{}",
                    get("redirect_uri"),
                    form_urlencoded::Serializer::new(String::new())
                        .append_pair("code", &code)
                        .append_pair("state", &get("state"))
                        .finish()
                );
                web::redirect(&location)
            }
            (Method::POST, "/token") => {
                *self.token_requests.lock().unwrap() += 1;
                let basic = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let form: HashMap<String, String> =
                    form_urlencoded::parse(&body).into_owned().collect();
                let expected = format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret))
                );
                if basic.as_deref() != Some(expected.as_str()) {
                    return web::json(
                        StatusCode::UNAUTHORIZED,
                        &json!({ "error": "invalid_client" }),
                    );
                }
                let Some(pending) = self.codes.lock().unwrap().remove(&form["code"]) else {
                    return web::json(
                        StatusCode::BAD_REQUEST,
                        &json!({ "error": "invalid_grant" }),
                    );
                };
                if b64url(&sha256(form["code_verifier"].as_bytes())) != pending.challenge
                    || form["redirect_uri"] != pending.redirect_uri
                {
                    return web::json(
                        StatusCode::BAD_REQUEST,
                        &json!({ "error": "invalid_grant" }),
                    );
                }
                let now = clock::now_secs();
                let mut claims = json!({
                    "iss": self.issuer,
                    "aud": self.client_id,
                    "sub": pending.user.sub,
                    "email": pending.user.email,
                    "email_verified": true,
                    "groups": pending.user.groups,
                    "amr": pending.user.amr,
                    "nonce": pending.nonce,
                    "iat": now,
                    "exp": now + 300,
                    "auth_time": now - 5,
                });
                if *self.omit_auth_time.lock().unwrap() {
                    claims.as_object_mut().unwrap().remove("auth_time");
                }
                let header = Header {
                    alg: "ES256".into(),
                    typ: "JWT".into(),
                    kid: Jwk::from_key(self.key.public_key()).kid,
                    jwk: None,
                    crit: None,
                };
                let id_token =
                    jose::sign(&header, claims.to_string().as_bytes(), &self.key).unwrap();
                web::json(
                    StatusCode::OK,
                    &json!({ "id_token": id_token, "access_token": "unused", "token_type": "Bearer" }),
                )
            }
            _ => web::json(StatusCode::NOT_FOUND, &json!({ "error": "not_found" })),
        }
    }
}

/// A running test IdP.
pub struct RunningIdp {
    pub idp: Arc<TestIdp>,
    pub pki: TestPki,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

impl RunningIdp {
    pub async fn start(user: IdpUser) -> RunningIdp {
        let pki = TestPki::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let idp = Arc::new(TestIdp {
            issuer: format!("https://localhost:{port}"),
            client_id: "warren".into(),
            client_secret: "s3cret".into(),
            user: Mutex::new(user),
            key: SigningKey::generate().unwrap(),
            codes: Mutex::new(HashMap::new()),
            token_requests: Mutex::new(0),
            authorize_requests: Mutex::new(Vec::new()),
            omit_auth_time: Mutex::new(false),
        });
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let key = provider
            .key_provider
            .load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(
                pki.key_pkcs8.clone().into(),
            ))
            .unwrap();
        let certified = rustls::sign::CertifiedKey::new(
            pki.chain
                .iter()
                .cloned()
                .map(rustls::pki_types::CertificateDer::from)
                .collect(),
            key,
        );
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(web::serve_tls(
            listener,
            Arc::new(config),
            idp.clone(),
            web::ListenOptions::default(),
            rx,
        ));
        RunningIdp {
            idp,
            pki,
            _shutdown: tx,
        }
    }
}

/// A simulated client: a software P-256 device key standing in for the
/// Secure Enclave, and an HTTPS client that trusts the deployment's bundle
/// (as an MDM-preset fingerprint would).
pub struct TestClient {
    pub base: String,
    pub key: SigningKey,
    pub http: Client,
    pub idp_http: Client,
    pub session: Option<Session>,
}

pub const REDIRECT_URI: &str = "http://127.0.0.1:53682/callback";

fn location(reply: &Reply) -> String {
    assert_eq!(
        reply.status,
        StatusCode::FOUND,
        "{:?}",
        String::from_utf8_lossy(&reply.body)
    );
    reply.headers["location"].to_str().unwrap().to_owned()
}

fn query_of(url: &str) -> HashMap<String, String> {
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    form_urlencoded::parse(q.as_bytes()).into_owned().collect()
}

impl TestClient {
    pub fn new(base: &str, trust_bundle: &str, idp_ca: &str) -> TestClient {
        TestClient {
            base: base.into(),
            key: SigningKey::generate().unwrap(),
            http: Client::new(Client::roots_from_pem(trust_bundle).unwrap(), None).unwrap(),
            idp_http: Client::new(Client::roots_from_pem(idp_ca).unwrap(), None).unwrap(),
            session: None,
        }
    }

    pub fn bearer(&self) -> String {
        format!("Bearer {}", self.session.as_ref().expect("signed in").token)
    }

    pub async fn get(&self, path: &str) -> Reply {
        let auth = self.session.as_ref().map(|_| self.bearer());
        let headers: Vec<(&str, &str)> =
            auth.iter().map(|a| ("authorization", a.as_str())).collect();
        self.http
            .request(Method::GET, &format!("{}{path}", self.base), &headers, None)
            .await
            .unwrap()
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> Reply {
        let auth = self.bearer();
        self.http
            .request(
                Method::POST,
                &format!("{}{path}", self.base),
                &[
                    ("authorization", auth.as_str()),
                    ("content-type", "application/json"),
                ],
                Some(Bytes::from(body.to_string())),
            )
            .await
            .unwrap()
    }

    /// Runs the whole browser flow and exchanges the code for a session.
    /// Returns the redirect back to the client, for tests of failures.
    pub async fn browser_sign_in(&self) -> HashMap<String, String> {
        self.browser_sign_in_with(&[]).await
    }

    /// Signs in through the browser, adding `extra` to the authorization
    /// request (such as `prompt=login`).
    pub async fn browser_sign_in_with(&self, extra: &[(&str, &str)]) -> HashMap<String, String> {
        let verifier = b64url(&random_bytes::<32>().unwrap());
        let challenge = b64url(&sha256(verifier.as_bytes()));
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("redirect_uri", REDIRECT_URI)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", "client-state-1");
        for (k, v) in extra {
            query.append_pair(k, v);
        }
        let start = format!("{}/v1/auth/authorize?{}", self.base, query.finish());
        let to_idp = location(
            &self
                .http
                .request(Method::GET, &start, &[], None)
                .await
                .unwrap(),
        );
        let to_cp = location(
            &self
                .idp_http
                .request(Method::GET, &to_idp, &[], None)
                .await
                .unwrap(),
        );
        let back = location(
            &self
                .http
                .request(Method::GET, &to_cp, &[], None)
                .await
                .unwrap(),
        );
        assert!(back.starts_with(REDIRECT_URI), "{back}");
        let mut q = query_of(&back);
        assert_eq!(q["state"], "client-state-1");
        q.insert("verifier".into(), verifier);
        q
    }

    pub async fn exchange(&mut self, code: &str, verifier: &str) -> Reply {
        let header = Header {
            alg: "ES256".into(),
            typ: SESSION_REQUEST_TYP.into(),
            kid: None,
            jwk: Some(Jwk::from_key(self.key.public_key())),
            crit: None,
        };
        let request = SessionRequest {
            code: code.into(),
            code_verifier: verifier.into(),
            redirect_uri: REDIRECT_URI.into(),
            iat: clock::now_secs(),
        };
        let jws = jose::sign(&header, &serde_json::to_vec(&request).unwrap(), &self.key).unwrap();
        let reply = self
            .http
            .request(
                Method::POST,
                &format!("{}/v1/auth/token", self.base),
                &[("content-type", "application/jose")],
                Some(Bytes::from(jws)),
            )
            .await
            .unwrap();
        if reply.status == StatusCode::OK {
            self.session = Some(reply.json().unwrap());
        }
        reply
    }

    pub async fn sign_in(&mut self) -> Session {
        let q = self.browser_sign_in().await;
        let reply = self.exchange(&q["code"], &q["verifier"]).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        self.session.clone().unwrap()
    }

    pub fn csr(&self) -> String {
        let spki = cert::p256_spki(self.key.public_key().point());
        STANDARD.encode(join::certificate_request(&spki, |info| self.key.sign_der(info)).unwrap())
    }

    pub async fn enroll(&self) -> (StatusCode, Value) {
        let body = serde_json::to_value(EnrollRequest {
            csr: self.csr(),
            platform: Platform {
                os: "macos".into(),
                os_version: "15.4.1".into(),
                model: "Mac16,1".into(),
                hostname: "test-mac".into(),
            },
            key_storage: "software".into(),
        })
        .unwrap();
        let reply = self.post_json("/v1/devices", &body).await;
        (reply.status, serde_json::from_slice(&reply.body).unwrap())
    }

    pub async fn device(&self) -> DeviceInfo {
        let reply = self.get("/v1/devices/current").await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.json().unwrap()
    }

    pub async fn certificate(&self) -> Result<CertificateResponse, (StatusCode, Value)> {
        let body = serde_json::to_value(CertificateRequest { csr: self.csr() }).unwrap();
        let reply = self.post_json("/v1/certificates", &body).await;
        if reply.status == StatusCode::OK {
            Ok(reply.json().unwrap())
        } else {
            Err((reply.status, serde_json::from_slice(&reply.body).unwrap()))
        }
    }

    pub async fn entitlements(&self) -> Entitlements {
        let reply = self.get("/v1/entitlements").await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        reply.json().unwrap()
    }
}

/// A received line and when it arrived.
#[derive(Debug, Clone)]
pub struct Received {
    pub line: Line,
    pub at: Instant,
    pub at_ms: i64,
}

/// A stub relay or connector.
pub struct StubNode {
    pub base: String,
    /// The node ID the control plane assigned.
    pub id: String,
    /// Its certificate's serial, hex.
    pub serial: String,
    /// The role its certificate names.
    pub role: NodeRole,
    /// Its certificate chain, leaf first, DER.
    pub chain: Vec<Vec<u8>>,
    /// The trust bundle the join returned.
    pub trust: TrustBundle,
    /// The policy-signing key, fetched on link E after joining.
    pub policy_key: Jwk,
    pub http: Client,
}

impl StubNode {
    /// Joins with `token` the way `warren relay` and `warren connector` do,
    /// through warren-masque's node side of the exchange, then talks link E
    /// at `base`.
    pub async fn join(base: &str, token: &str) -> Result<StubNode, String> {
        let token =
            JoinToken::parse(token, clock::now_secs().unsigned_abs()).map_err(|e| e.to_string())?;
        let key = NodeKey::generate().unwrap();
        let joined = warren_masque::join::join(&token, &key)
            .await
            .map_err(|e| e.to_string())?;
        let PrivateKeyDer::Pkcs8(pkcs8) = key.private_key() else {
            unreachable!("node keys are PKCS#8")
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(joined.trust.root.clone()).unwrap();
        let chain: Vec<Vec<u8>> = joined
            .credentials
            .chain
            .iter()
            .map(|c| c.to_vec())
            .collect();
        let http = Client::new(roots, Some((chain.clone(), pkcs8.secret_pkcs8_der()))).unwrap();
        let reply = http
            .request(
                Method::GET,
                &format!("{base}/v1/node/policy-key"),
                &[],
                None,
            )
            .await
            .unwrap();
        assert_eq!(reply.status, StatusCode::OK);
        Ok(StubNode {
            base: base.into(),
            id: joined.identity.id,
            serial: joined.identity.serial,
            role: joined.identity.role,
            chain,
            trust: joined.trust,
            policy_key: reply.json().unwrap(),
            http,
        })
    }

    pub async fn get(&self, path: &str) -> Reply {
        self.http
            .request(Method::GET, &format!("{}{path}", self.base), &[], None)
            .await
            .unwrap()
    }

    pub async fn post(&self, path: &str, content_type: &str, body: Vec<u8>) -> Reply {
        self.http
            .request(
                Method::POST,
                &format!("{}{path}", self.base),
                &[("content-type", content_type)],
                Some(Bytes::from(body)),
            )
            .await
            .unwrap()
    }

    /// Opens the event stream and forwards each line as it arrives.
    pub async fn events(&self, after: Option<u64>) -> mpsc::UnboundedReceiver<Received> {
        let path = match after {
            Some(a) => format!("/v1/node/events?after={a}"),
            None => "/v1/node/events".into(),
        };
        let resp = self
            .http
            .send(Method::GET, &format!("{}{path}", self.base), &[], None)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "application/x-ndjson");
        let (tx, rx) = mpsc::unbounded_channel();
        let mut body = resp.into_body();
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            while let Some(Ok(frame)) = body.frame().await {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buffer.extend_from_slice(&data);
                while let Some(i) = buffer.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = buffer.drain(..=i).collect();
                    let text = String::from_utf8(line).unwrap();
                    let parsed = Line::parse(text.trim()).unwrap();
                    if tx
                        .send(Received {
                            line: parsed,
                            at: Instant::now(),
                            at_ms: clock::now_millis(),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        rx
    }

    pub async fn ack(&self, seq: u64, applied_at_ms: i64, cut: u64) -> Reply {
        let body = AckRequest {
            acks: vec![Ack {
                seq,
                applied_at_ms,
                connections_cut: cut,
            }],
        };
        self.post(
            "/v1/node/events/ack",
            "application/json",
            serde_json::to_vec(&body).unwrap(),
        )
        .await
    }
}

/// Writes a file, creating its directory.
pub fn write(path: &Path, text: &str) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(path, text).unwrap();
}
