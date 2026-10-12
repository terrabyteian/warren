//! A test OpenID Connect provider for end-to-end tests of sign-in:
//! discovery, an authorization endpoint that signs the configured user in
//! at once (no form, so a test's "browser" can follow the redirects), a
//! token endpoint that checks PKCE and, when one is set, the client
//! secret, and a JWKS. ID tokens are ES256. It serves HTTP/1.1 over TLS
//! 1.3, as identity providers do, from a certificate of its own test CA.
//! Never shipped.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use warren_client::signin::{encode, parse_query};
use warren_core::jose::{self, Header, Jwk, b64url};
use warren_core::keys::{SigningKey, random_bytes, sha256};
use warren_core::pki::oid;

use crate::pki::{CertSpec, Issuer, KeyPair, issue, name, pem};

/// The person the IdP signs in.
#[derive(Debug, Clone)]
pub struct IdpUser {
    /// The subject.
    pub sub: String,
    /// The email address.
    pub email: String,
    /// Group names.
    pub groups: Vec<String>,
    /// Authentication methods (`mfa` makes the sign-in count as MFA).
    pub amr: Vec<String>,
}

impl IdpUser {
    /// Parses `SUB,EMAIL,GROUP+GROUP,AMR+AMR`.
    pub fn parse(spec: &str) -> Result<IdpUser, String> {
        let parts: Vec<&str> = spec.split(',').collect();
        let list = |s: &str| -> Vec<String> {
            s.split('+')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        };
        match parts.as_slice() {
            [sub, email, groups, amr] => Ok(IdpUser {
                sub: (*sub).into(),
                email: (*email).into(),
                groups: list(groups),
                amr: list(amr),
            }),
            _ => Err(format!(
                "--user {spec}: expected SUB,EMAIL,GROUP+GROUP,AMR+AMR"
            )),
        }
    }
}

struct Pending {
    nonce: String,
    challenge: String,
    redirect_uri: String,
}

struct State {
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    user: IdpUser,
    key: SigningKey,
    codes: Mutex<HashMap<String, Pending>>,
}

/// A running test IdP.
#[derive(Debug)]
pub struct TestIdp {
    /// The issuer URL.
    pub issuer: String,
    /// Where it listens.
    pub addr: SocketAddr,
    /// Its test CA, PEM: what the control plane and the test browser trust.
    pub ca_pem: String,
}

/// A response: status line, content type, extra headers and body.
struct Reply {
    status: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn json_reply(status: &'static str, v: &Value) -> Reply {
    Reply {
        status,
        headers: vec![("content-type", "application/json".into())],
        body: v.to_string().into_bytes(),
    }
}

impl TestIdp {
    /// Starts the IdP on `listen`, answering as `host`, for `client_id`
    /// (with `client_secret`, or as a public client), signing in `user`.
    pub async fn start(
        listen: SocketAddr,
        host: &str,
        client_id: &str,
        client_secret: Option<&str>,
        user: IdpUser,
    ) -> std::io::Result<TestIdp> {
        let ca_key = KeyPair::generate();
        let ca_cert = issue(&CertSpec::ca("warren test IdP CA"), &ca_key, None);
        let leaf_key = KeyPair::generate();
        let mut spec = CertSpec::leaf(7 * 86_400);
        spec.san_dns = vec![host.to_owned()];
        spec.eku = vec![oid::SERVER_AUTH.to_vec()];
        let leaf = issue(
            &spec,
            &leaf_key,
            Some(&Issuer {
                key: &ca_key,
                name: name(Some("warren test IdP CA")),
            }),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(warren_core::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(std::io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.into(), ca_cert.clone().into()],
                leaf_key.private_key(),
            )
            .map_err(std::io::Error::other)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = warren_masque::tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(listen).await?;
        let addr = listener.local_addr()?;
        let issuer = if addr.port() == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", addr.port())
        };
        let state = Arc::new(State {
            issuer: issuer.clone(),
            client_id: client_id.into(),
            client_secret: client_secret.map(str::to_owned),
            user,
            key: SigningKey::generate().map_err(std::io::Error::other)?,
            codes: Mutex::new(HashMap::new()),
        });
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, state) = (acceptor.clone(), state.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(Ok(Some(req))) =
                        tokio::time::timeout(Duration::from_secs(10), read_request(&mut tls)).await
                    else {
                        return;
                    };
                    let reply = state.handle(&req);
                    let mut out = format!(
                        "HTTP/1.1 {}\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (k, v) in &reply.headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    out.push_str("\r\n");
                    let mut bytes = out.into_bytes();
                    bytes.extend_from_slice(&reply.body);
                    let _ = tls.write_all(&bytes).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Ok(TestIdp {
            issuer,
            addr,
            ca_pem: pem("CERTIFICATE", &ca_cert),
        })
    }
}

/// A parsed request.
struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn read_request<S: AsyncReadExt + Unpin>(s: &mut S) -> std::io::Result<Option<Request>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return Ok(None);
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_owned();
    let target = first.next().unwrap_or("").to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len.min(64 * 1024) {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    Ok(Some(Request {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body,
    }))
}

fn get<'a>(q: &'a [(String, String)], k: &str) -> &'a str {
    q.iter()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

impl State {
    fn handle(&self, req: &Request) -> Reply {
        let bad = |e: &str| json_reply("400 Bad Request", &json!({ "error": e }));
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/.well-known/openid-configuration") => json_reply(
                "200 OK",
                &json!({
                    "issuer": self.issuer,
                    "authorization_endpoint": format!("{}/authorize", self.issuer),
                    "token_endpoint": format!("{}/token", self.issuer),
                    "jwks_uri": format!("{}/jwks", self.issuer),
                    "response_types_supported": ["code"],
                    "id_token_signing_alg_values_supported": ["ES256"],
                }),
            ),
            ("GET", "/jwks") => {
                let mut jwk =
                    serde_json::to_value(Jwk::from_key(self.key.public_key())).unwrap_or_default();
                jwk["use"] = json!("sig");
                jwk["alg"] = json!("ES256");
                json_reply("200 OK", &json!({ "keys": [jwk] }))
            }
            ("GET", "/authorize") => {
                let Some(q) = parse_query(&req.query) else {
                    return bad("invalid_request");
                };
                if get(&q, "response_type") != "code"
                    || get(&q, "client_id") != self.client_id
                    || get(&q, "code_challenge_method") != "S256"
                    || !get(&q, "scope").split(' ').any(|s| s == "openid")
                {
                    return bad("invalid_request");
                }
                let Ok(raw) = random_bytes::<16>() else {
                    return bad("server_error");
                };
                let code = b64url(&raw);
                self.codes.lock().expect("codes lock").insert(
                    code.clone(),
                    Pending {
                        nonce: get(&q, "nonce").into(),
                        challenge: get(&q, "code_challenge").into(),
                        redirect_uri: get(&q, "redirect_uri").into(),
                    },
                );
                let location = format!(
                    "{}?code={}&state={}",
                    get(&q, "redirect_uri"),
                    encode(&code),
                    encode(get(&q, "state"))
                );
                Reply {
                    status: "302 Found",
                    headers: vec![("location", location)],
                    body: Vec::new(),
                }
            }
            ("POST", "/token") => self.token(req),
            _ => json_reply("404 Not Found", &json!({ "error": "not_found" })),
        }
    }

    fn token(&self, req: &Request) -> Reply {
        let bad = |e: &str| json_reply("400 Bad Request", &json!({ "error": e }));
        let Some(form) = parse_query(&String::from_utf8_lossy(&req.body)) else {
            return bad("invalid_request");
        };
        if let Some(secret) = &self.client_secret {
            let expected = format!(
                "Basic {}",
                warren_core::base64::encode(
                    format!("{}:{}", encode(&self.client_id), encode(secret)).as_bytes()
                )
            );
            if req.header("authorization") != Some(expected.as_str()) {
                return json_reply("401 Unauthorized", &json!({ "error": "invalid_client" }));
            }
        } else if get(&form, "client_id") != self.client_id {
            return json_reply("401 Unauthorized", &json!({ "error": "invalid_client" }));
        }
        let Some(pending) = self
            .codes
            .lock()
            .expect("codes lock")
            .remove(get(&form, "code"))
        else {
            return bad("invalid_grant");
        };
        if b64url(&sha256(get(&form, "code_verifier").as_bytes())) != pending.challenge
            || get(&form, "redirect_uri") != pending.redirect_uri
        {
            return bad("invalid_grant");
        }
        let now = warren_core::clock::now_secs();
        let claims = json!({
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": self.user.sub,
            "email": self.user.email,
            "email_verified": true,
            "groups": self.user.groups,
            "amr": self.user.amr,
            "nonce": pending.nonce,
            "iat": now,
            "exp": now + 300,
            "auth_time": now - 5,
        });
        let header = Header {
            alg: "ES256".into(),
            typ: "JWT".into(),
            kid: Jwk::from_key(self.key.public_key()).kid,
            jwk: None,
            crit: None,
        };
        match jose::sign(&header, claims.to_string().as_bytes(), &self.key) {
            Ok(id_token) => json_reply(
                "200 OK",
                &json!({ "id_token": id_token, "access_token": "unused", "token_type": "Bearer" }),
            ),
            Err(_) => bad("server_error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_parse() {
        let u = IdpUser::parse("00u-ada,ada@example.com,eng+ops,pwd+mfa").unwrap();
        assert_eq!(u.groups, ["eng", "ops"]);
        assert_eq!(u.amr, ["pwd", "mfa"]);
        assert!(IdpUser::parse("ada").is_err());
    }
}
