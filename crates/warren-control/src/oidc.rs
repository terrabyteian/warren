//! The control plane as an OpenID Connect relying party: authorization code
//! flow with PKCE (RFC 7636) toward any standard IdP (docs/protocol.md
//! section 11.1).
//!
//! ID tokens are verified here with aws-lc-rs: the algorithm must be on an
//! asymmetric allowlist and match its key, the issuer must match exactly,
//! the audience must include warren, the nonce must be the one sent, and
//! the token must be within its validity with the configured clock skew.
//!
//! The Google preset (`idp.type: google`) skips discovery for its known
//! endpoints, accepts both spellings of Google's issuer, and admits only
//! accounts with a verified email, of the configured Workspace domain or on
//! the allowed list when either is set ([`Provider::admits`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use base64::Engine;
use bytes::Bytes;
use http::Method;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;
use warren_core::clock;
use warren_core::jose::b64url_decode;
use zeroize::Zeroizing;

use crate::Error;
use crate::config::{self, IdpKind};
use crate::web::Client;
use warren_policy::model::LOCAL_PREFIX;

/// What the IdP's discovery document says.
#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// A verified sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignIn {
    /// The IdP's subject identifier.
    pub subject: String,
    /// The email, if the IdP asserted one and marked it verified.
    pub email: String,
    /// Groups from the configured claim.
    pub groups: Vec<String>,
    /// When the user authenticated, Unix seconds, if the IdP said. It is
    /// never inferred from when the token was issued: a silent single
    /// sign-on issues a new token without authenticating anyone.
    pub auth_time: Option<i64>,
    /// When the IdP issued the ID token, Unix seconds.
    pub issued_at: i64,
    /// Whether the authentication used multi-factor authentication.
    pub mfa: bool,
    /// Google: the Workspace domain of the account (the `hd` claim), if any.
    pub hosted_domain: Option<String>,
}

struct Keys {
    keys: Vec<Value>,
    fetched: Option<Instant>,
}

/// The IdP.
pub struct Provider {
    config: config::Idp,
    secret: Option<Zeroizing<String>>,
    http: Client,
    skew: i64,
    metadata: Mutex<Option<Arc<Metadata>>>,
    keys: Mutex<Keys>,
}

/// How often unknown key IDs may trigger a JWKS refetch.
const JWKS_REFRESH: Duration = Duration::from_secs(60);

impl Provider {
    /// A provider for `config`. Discovery happens on first use, so the
    /// control plane starts even while the IdP is unreachable.
    pub fn new(config: &config::Idp, skew: Duration) -> Result<Provider, Error> {
        let roots = match &config.ca_file {
            Some(path) => Client::roots_from_pem(
                &std::fs::read_to_string(path)
                    .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?,
            )?,
            None => Client::native_roots()?,
        };
        let secret = match &config.client_secret_file {
            Some(path) => Some(Zeroizing::new(
                std::fs::read_to_string(path)
                    .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?
                    .trim()
                    .to_owned(),
            )),
            None => None,
        };
        Ok(Provider {
            config: config.clone(),
            secret,
            http: Client::new(roots, None)?,
            skew: skew.as_secs() as i64,
            metadata: Mutex::new(None),
            keys: Mutex::new(Keys {
                keys: Vec::new(),
                fetched: None,
            }),
        })
    }

    /// The provider's configuration.
    pub fn config(&self) -> &config::Idp {
        &self.config
    }

    async fn metadata(&self) -> Result<Arc<Metadata>, Error> {
        let mut slot = self.metadata.lock().await;
        if let Some(m) = slot.as_ref() {
            return Ok(m.clone());
        }
        if let Some(e) = &self.config.endpoints {
            let m = Arc::new(Metadata {
                issuer: self.config.issuer.clone(),
                authorization_endpoint: e.authorization.clone(),
                token_endpoint: e.token.clone(),
                jwks_uri: e.jwks.clone(),
            });
            *slot = Some(m.clone());
            return Ok(m);
        }
        let url = format!("{}/.well-known/openid-configuration", self.config.issuer);
        let reply = self.http.request(Method::GET, &url, &[], None).await?;
        if !reply.status.is_success() {
            return Err(Error::Idp(format!(
                "discovery at {url} returned {}",
                reply.status
            )));
        }
        let m: Metadata = reply
            .json()
            .map_err(|e| Error::Idp(format!("discovery at {url}: {e}")))?;
        if m.issuer.trim_end_matches('/') != self.config.issuer {
            return Err(Error::Idp(format!(
                "discovery names issuer {}, not the configured {}",
                m.issuer, self.config.issuer
            )));
        }
        for endpoint in [&m.authorization_endpoint, &m.token_endpoint, &m.jwks_uri] {
            if !endpoint.starts_with("https://") {
                return Err(Error::Idp(format!("IdP endpoint {endpoint} is not https")));
            }
        }
        let m = Arc::new(m);
        *slot = Some(m.clone());
        Ok(m)
    }

    /// The URL that starts sign-in at the IdP. `max_age` asks the IdP to
    /// authenticate the user again if they last did longer ago than that
    /// many seconds, and `login` to authenticate them again regardless
    /// (OpenID Connect Core section 3.1.2.1); either way the ID token must
    /// then carry `auth_time`. Google supports neither: it is asked to show
    /// its account chooser instead, and its ID tokens report no
    /// authentication time, so freshness rules ask Google users to sign in
    /// again every time. A hosted domain is passed on as Google's `hd`
    /// hint; the `hd` claim is what is enforced.
    pub async fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
        max_age: Option<i64>,
        login: bool,
    ) -> Result<String, Error> {
        let m = self.metadata().await?;
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        match self.config.kind {
            IdpKind::Oidc => {
                if let Some(max_age) = max_age {
                    query.append_pair("max_age", &max_age.to_string());
                }
                if login {
                    query.append_pair("prompt", "login");
                }
            }
            IdpKind::Google => {
                if login {
                    query.append_pair("prompt", "select_account");
                }
                if let Some(hd) = &self.config.hosted_domain {
                    query.append_pair("hd", hd);
                }
            }
        }
        let query = query.finish();
        let sep = if m.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(format!("{}{sep}{query}", m.authorization_endpoint))
    }

    /// Exchanges an authorization code and verifies the ID token.
    pub async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        nonce: &str,
    ) -> Result<SignIn, Error> {
        let m = self.metadata().await?;
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_verifier", verifier)
            .append_pair("client_id", &self.config.client_id)
            .finish();
        let basic = self.secret.as_ref().map(|secret| {
            let enc = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            let pair = format!("{}:{}", enc(&self.config.client_id), enc(secret));
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(pair)
            )
        });
        let mut headers = vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
        ];
        if let Some(b) = &basic {
            headers.push(("authorization", b.as_str()));
        }
        let reply = self
            .http
            .request(
                Method::POST,
                &m.token_endpoint,
                &headers,
                Some(Bytes::from(body)),
            )
            .await?;
        if !reply.status.is_success() {
            let detail: Value = reply.json().unwrap_or_default();
            return Err(Error::Idp(format!(
                "token endpoint returned {}: {}",
                reply.status,
                detail
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("no error code")
            )));
        }
        let tokens: Value = reply.json().map_err(|e| Error::Idp(e.to_string()))?;
        let id_token = tokens
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Idp("the token response has no id_token".into()))?;
        self.verify_id_token(id_token, nonce).await
    }

    async fn key_for(&self, kid: Option<&str>, kty: &str) -> Result<Vec<Value>, Error> {
        let m = self.metadata().await?;
        let mut keys = self.keys.lock().await;
        let matching = |keys: &[Value]| -> Vec<Value> {
            keys.iter()
                .filter(|k| k.get("kty").and_then(Value::as_str) == Some(kty))
                .filter(|k| match kid {
                    Some(kid) => k.get("kid").and_then(Value::as_str) == Some(kid),
                    None => true,
                })
                .cloned()
                .collect()
        };
        let found = matching(&keys.keys);
        let stale = keys.fetched.is_none_or(|t| t.elapsed() >= JWKS_REFRESH);
        if !found.is_empty() || !stale {
            return Ok(found);
        }
        let reply = self
            .http
            .request(Method::GET, &m.jwks_uri, &[], None)
            .await?;
        if !reply.status.is_success() {
            return Err(Error::Idp(format!(
                "JWKS at {} returned {}",
                m.jwks_uri, reply.status
            )));
        }
        let set: Value = reply.json().map_err(|e| Error::Idp(e.to_string()))?;
        keys.keys = set
            .get("keys")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        keys.fetched = Some(Instant::now());
        Ok(matching(&keys.keys))
    }

    /// Verifies an ID token's signature and claims.
    pub async fn verify_id_token(&self, token: &str, nonce: &str) -> Result<SignIn, Error> {
        let bad = |why: &str| Error::Idp(format!("ID token rejected: {why}"));
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("not a compact JWS"));
        };
        let header: Value = serde_json::from_slice(&b64url_decode(h).map_err(|_| bad("header"))?)
            .map_err(|_| bad("header is not JSON"))?;
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
        let kty = match alg {
            "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => "RSA",
            "ES256" | "ES384" => "EC",
            "EdDSA" => "OKP",
            _ => return Err(bad(&format!("algorithm {alg:?} is not accepted"))),
        };
        if header.get("crit").is_some() {
            return Err(bad("critical header parameters are not supported"));
        }
        let kid = header.get("kid").and_then(Value::as_str);
        let signature = b64url_decode(s).map_err(|_| bad("signature encoding"))?;
        let message = format!("{h}.{p}");
        let candidates = self.key_for(kid, kty).await?;
        let verified = candidates.iter().any(|jwk| {
            jwk.get("use")
                .and_then(Value::as_str)
                .is_none_or(|u| u == "sig")
                && jwk
                    .get("alg")
                    .and_then(Value::as_str)
                    .is_none_or(|a| a == alg)
                && verify(alg, jwk, message.as_bytes(), &signature).is_ok()
        });
        if !verified {
            return Err(bad("no IdP key verifies its signature"));
        }
        let claims: Value = serde_json::from_slice(&b64url_decode(p).map_err(|_| bad("payload"))?)
            .map_err(|_| bad("payload is not JSON"))?;
        self.check_claims(&claims, nonce, clock::now_secs())
    }

    fn check_claims(&self, claims: &Value, nonce: &str, now: i64) -> Result<SignIn, Error> {
        let bad = |why: &str| Error::Idp(format!("ID token rejected: {why}"));
        let str_claim = |name: &str| claims.get(name).and_then(Value::as_str);
        let int_claim = |name: &str| claims.get(name).and_then(Value::as_i64);
        if !str_claim("iss").is_some_and(|i| self.config.issued_by(i)) {
            return Err(bad("wrong issuer"));
        }
        let audiences: Vec<&str> = match claims.get("aud") {
            Some(Value::String(a)) => vec![a.as_str()],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        if !audiences.contains(&self.config.client_id.as_str()) {
            return Err(bad("not issued for warren"));
        }
        if audiences.len() > 1 && str_claim("azp") != Some(self.config.client_id.as_str()) {
            return Err(bad(
                "several audiences but warren is not the authorized party",
            ));
        }
        let exp = int_claim("exp").ok_or_else(|| bad("no exp"))?;
        let iat = int_claim("iat").ok_or_else(|| bad("no iat"))?;
        if now >= exp + self.skew {
            return Err(bad("expired"));
        }
        if iat > now + self.skew || int_claim("nbf").is_some_and(|nbf| nbf > now + self.skew) {
            return Err(bad("issued in the future"));
        }
        if str_claim("nonce") != Some(nonce) {
            return Err(bad("wrong nonce"));
        }
        let subject = str_claim("sub")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bad("no subject"))?;
        // `local:` names warren's built-in accounts in policy; no IdP
        // subject may pass for one.
        if subject.starts_with(LOCAL_PREFIX) {
            return Err(bad(
                "the subject uses the prefix reserved for built-in accounts",
            ));
        }
        let auth_time = int_claim("auth_time");
        if auth_time.is_some_and(|t| t > now + self.skew) {
            return Err(bad("authentication time in the future"));
        }
        // An email the IdP did not mark verified may be one the user typed
        // in themselves, so it never identifies anyone.
        let email = match (
            str_claim("email"),
            claims.get("email_verified").and_then(Value::as_bool),
        ) {
            (Some(e), Some(true)) => e.to_ascii_lowercase(),
            _ => String::new(),
        };
        let mut groups: Vec<String> = match claims.get(&self.config.groups_claim) {
            _ if self.config.groups_claim.is_empty() => Vec::new(),
            Some(Value::Array(g)) => g
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            Some(Value::String(g)) => vec![g.clone()],
            _ => Vec::new(),
        };
        // Groups named `local:` are warren's own; the IdP cannot assert
        // membership in them.
        let before = groups.len();
        groups.retain(|g| !g.starts_with(LOCAL_PREFIX));
        if groups.len() != before {
            crate::log::warn(
                "idp",
                "ignored groups the IdP asserted with the prefix reserved for warren's own groups (local:)",
            );
        }
        let amr: Vec<&str> = claims
            .get("amr")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mfa = amr
            .iter()
            .any(|v| self.config.mfa_amr_values.iter().any(|m| m == v))
            || str_claim("acr")
                .is_some_and(|acr| self.config.mfa_acr_values.iter().any(|m| m == acr));
        let hosted_domain = str_claim("hd").map(str::to_ascii_lowercase);
        Ok(SignIn {
            subject: subject.to_owned(),
            email,
            groups,
            auth_time,
            issued_at: iat,
            mfa,
            hosted_domain,
        })
    }

    /// Whether a verified sign-in may proceed, or why not, in words for the
    /// person signing in. Google admits only accounts with a verified email,
    /// and when a hosted domain or allowed emails are configured, only
    /// accounts of that Workspace domain (by the `hd` claim, never the
    /// email's domain) or on that list.
    pub fn admits(&self, signin: &SignIn) -> Result<(), String> {
        if self.config.kind != IdpKind::Google {
            return Ok(());
        }
        if signin.email.is_empty() {
            return Err(
                "Google did not confirm this account's email address, so warren cannot accept it."
                    .into(),
            );
        }
        let restricted =
            self.config.hosted_domain.is_some() || !self.config.allowed_emails.is_empty();
        let in_domain = self
            .config
            .hosted_domain
            .as_ref()
            .is_some_and(|d| signin.hosted_domain.as_ref() == Some(d));
        let listed = self.config.allowed_emails.contains(&signin.email);
        if restricted && !in_domain && !listed {
            return Err(match &self.config.hosted_domain {
                Some(d) => format!(
                    "This Google account is not allowed to sign in to warren. Use your {d} account."
                ),
                None => "This Google account is not allowed to sign in to warren.".into(),
            });
        }
        Ok(())
    }
}

fn coordinate(jwk: &Value, name: &str) -> Result<Vec<u8>, ()> {
    jwk.get(name)
        .and_then(Value::as_str)
        .ok_or(())
        .and_then(|v| b64url_decode(v).map_err(|_| ()))
}

fn verify(alg: &str, jwk: &Value, message: &[u8], sig: &[u8]) -> Result<(), ()> {
    let unsigned = |v: Vec<u8>| -> Vec<u8> {
        let first = v.iter().position(|b| *b != 0).unwrap_or(v.len());
        v[first..].to_vec()
    };
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            let n = unsigned(coordinate(jwk, "n")?);
            let e = unsigned(coordinate(jwk, "e")?);
            let params = match alg {
                "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
                "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
                _ => &signature::RSA_PSS_2048_8192_SHA512,
            };
            RsaPublicKeyComponents { n: &n, e: &e }
                .verify(params, message, sig)
                .map_err(|_| ())
        }
        "ES256" | "ES384" => {
            let (crv, len, algorithm) = if alg == "ES256" {
                ("P-256", 32, &signature::ECDSA_P256_SHA256_FIXED)
            } else {
                ("P-384", 48, &signature::ECDSA_P384_SHA384_FIXED)
            };
            if jwk.get("crv").and_then(Value::as_str) != Some(crv) {
                return Err(());
            }
            let (x, y) = (coordinate(jwk, "x")?, coordinate(jwk, "y")?);
            if x.len() != len || y.len() != len {
                return Err(());
            }
            let mut point = vec![0x04];
            point.extend(x);
            point.extend(y);
            UnparsedPublicKey::new(algorithm, point)
                .verify(message, sig)
                .map_err(|_| ())
        }
        "EdDSA" => {
            if jwk.get("crv").and_then(Value::as_str) != Some("Ed25519") {
                return Err(());
            }
            UnparsedPublicKey::new(&signature::ED25519, coordinate(jwk, "x")?)
                .verify(message, sig)
                .map_err(|_| ())
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn provider() -> Provider {
        Provider {
            config: config::Idp {
                kind: IdpKind::Oidc,
                display_name: "your identity provider".into(),
                issuer: "https://idp.example.com".into(),
                issuer_aliases: vec![],
                endpoints: None,
                hosted_domain: None,
                allowed_emails: vec![],
                client_id: "warren".into(),
                client_secret_file: None,
                scopes: vec!["openid".into()],
                groups_claim: "groups".into(),
                ca_file: None,
                mfa_amr_values: vec!["mfa".into()],
                mfa_acr_values: vec!["urn:example:mfa".into()],
            },
            secret: None,
            http: Client::new(rustls::RootCertStore::empty(), None).unwrap(),
            skew: 120,
            metadata: Mutex::new(None),
            keys: Mutex::new(Keys {
                keys: vec![],
                fetched: None,
            }),
        }
    }

    fn claims() -> Value {
        json!({
            "iss": "https://idp.example.com",
            "aud": "warren",
            "sub": "00u1",
            "exp": 2_000,
            "iat": 1_000,
            "nonce": "n",
            "auth_time": 990,
            "email": "Ada@Example.com",
            "email_verified": true,
            "groups": ["engineering"],
            "amr": ["pwd", "mfa"],
        })
    }

    #[test]
    fn valid_claims() {
        let s = provider().check_claims(&claims(), "n", 1_500).unwrap();
        assert_eq!(s.subject, "00u1");
        assert_eq!(s.email, "ada@example.com");
        assert_eq!(s.groups, ["engineering"]);
        assert_eq!(s.auth_time, Some(990));
        assert_eq!(s.issued_at, 1_000);
        assert!(s.mfa);
    }

    #[test]
    fn a_missing_auth_time_is_unknown_not_the_issue_time() {
        let p = provider();
        let mut c = claims();
        c.as_object_mut().unwrap().remove("auth_time");
        assert_eq!(p.check_claims(&c, "n", 1_500).unwrap().auth_time, None);
        c["auth_time"] = json!(1_500 + 121);
        assert!(p.check_claims(&c, "n", 1_500).is_err());
    }

    #[tokio::test]
    async fn freshness_is_requested_from_the_idp() {
        let p = provider();
        *p.metadata.lock().await = Some(Arc::new(Metadata {
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "https://idp.example.com/authorize".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
        }));
        let params = |url: String| -> Vec<(String, String)> {
            let (_, query) = url.split_once('?').unwrap();
            form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        };
        let get = |params: &[(String, String)], k: &str| {
            params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        };
        let plain = params(
            p.authorize_url("https://cp/cb", "s", "n", "c", None, false)
                .await
                .unwrap(),
        );
        assert_eq!(get(&plain, "max_age"), None);
        assert_eq!(get(&plain, "prompt"), None);
        let fresh = params(
            p.authorize_url("https://cp/cb", "s", "n", "c", Some(3600), true)
                .await
                .unwrap(),
        );
        assert_eq!(get(&fresh, "max_age").as_deref(), Some("3600"));
        assert_eq!(get(&fresh, "prompt").as_deref(), Some("login"));
    }

    #[test]
    fn each_claim_is_checked() {
        let p = provider();
        let reject = |change: &dyn Fn(&mut Value), now: i64| {
            let mut c = claims();
            change(&mut c);
            assert!(p.check_claims(&c, "n", now).is_err(), "{c}");
        };
        reject(&|c| c["iss"] = json!("https://evil.example.com"), 1_500);
        reject(&|c| c["aud"] = json!("other"), 1_500);
        reject(&|c| c["aud"] = json!(["warren", "other"]), 1_500);
        reject(&|c| c["nonce"] = json!("x"), 1_500);
        reject(&|c| c["sub"] = json!(""), 1_500);
        reject(&|_| {}, 2_120);
        reject(&|_| {}, 870);
        reject(
            &|c| {
                c.as_object_mut().unwrap().remove("exp");
            },
            1_500,
        );
        // Within the skew allowance both ways is fine.
        assert!(p.check_claims(&claims(), "n", 2_119).is_ok());
        assert!(p.check_claims(&claims(), "n", 881).is_ok());
        let mut c = claims();
        c["aud"] = json!(["warren", "other"]);
        c["azp"] = json!("warren");
        assert!(p.check_claims(&c, "n", 1_500).is_ok());
    }

    #[test]
    fn unverified_email_and_mfa_sources() {
        let p = provider();
        let mut c = claims();
        c["email_verified"] = json!(false);
        c["amr"] = json!(["pwd"]);
        let s = p.check_claims(&c, "n", 1_500).unwrap();
        assert_eq!(s.email, "");
        // An IdP that lets users set their own email and never says whether
        // it is verified: the email identifies nobody.
        let mut c = claims();
        c.as_object_mut().unwrap().remove("email_verified");
        c["email"] = json!("ceo@example.com");
        assert_eq!(p.check_claims(&c, "n", 1_500).unwrap().email, "");
        c["email_verified"] = json!("true");
        assert_eq!(p.check_claims(&c, "n", 1_500).unwrap().email, "");
        let mut c = claims();
        c["amr"] = json!(["pwd"]);
        let s = p.check_claims(&c, "n", 1_500).unwrap();
        assert!(!s.mfa);
        c["acr"] = json!("urn:example:mfa");
        assert!(p.check_claims(&c, "n", 1_500).unwrap().mfa);
    }

    fn google() -> Provider {
        let mut p = provider();
        p.config.kind = IdpKind::Google;
        p.config.issuer = config::GOOGLE_ISSUER.into();
        p.config.issuer_aliases = vec!["accounts.google.com".into()];
        p.config.groups_claim = String::new();
        p.config.mfa_amr_values = vec![];
        p.config.mfa_acr_values = vec![];
        p.config.endpoints = Some(config::Endpoints {
            authorization: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token: "https://oauth2.googleapis.com/token".into(),
            jwks: "https://www.googleapis.com/oauth2/v3/certs".into(),
        });
        p
    }

    /// Claims as Google issues them: no groups, no amr, no auth_time.
    fn google_claims() -> Value {
        json!({
            "iss": "accounts.google.com",
            "azp": "warren",
            "aud": "warren",
            "sub": "110169484474386276334",
            "hd": "example.com",
            "email": "ada@example.com",
            "email_verified": true,
            "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",
            "nonce": "n",
            "iat": 1_000,
            "exp": 2_000,
            "groups": ["admins"],
        })
    }

    #[test]
    fn google_claims_and_who_may_sign_in() {
        let mut p = google();
        let s = p.check_claims(&google_claims(), "n", 1_500).unwrap();
        assert_eq!(s.subject, "110169484474386276334");
        assert_eq!(s.email, "ada@example.com");
        assert_eq!(s.hosted_domain.as_deref(), Some("example.com"));
        // Google asserts no groups; a claim by that name is not trusted.
        assert!(s.groups.is_empty());
        assert_eq!(s.auth_time, None);
        assert!(!s.mfa);
        let mut c = google_claims();
        c["iss"] = json!("https://accounts.google.com");
        assert!(p.check_claims(&c, "n", 1_500).is_ok());
        c["iss"] = json!("https://accounts.google.com.example.net");
        assert!(p.check_claims(&c, "n", 1_500).is_err());

        // With no restriction, any account with a verified email.
        assert!(p.admits(&s).is_ok());
        let mut unverified = google_claims();
        unverified["email_verified"] = json!(false);
        let u = p.check_claims(&unverified, "n", 1_500).unwrap();
        assert!(p.admits(&u).unwrap_err().contains("email"));

        // A hosted domain admits its accounts by the hd claim alone.
        p.config.hosted_domain = Some("example.com".into());
        assert!(p.admits(&s).is_ok());
        let mut gmail = google_claims();
        gmail.as_object_mut().unwrap().remove("hd");
        gmail["email"] = json!("ada@example.com");
        let g = p.check_claims(&gmail, "n", 1_500).unwrap();
        let refusal = p.admits(&g).unwrap_err();
        assert!(refusal.contains("example.com account"), "{refusal}");
        // Allowed emails add to the domain.
        p.config.allowed_emails = vec!["ada@example.com".into()];
        assert!(p.admits(&g).is_ok());
        p.config.hosted_domain = None;
        let mut other = google_claims();
        other["email"] = json!("eve@example.com");
        let o = p.check_claims(&other, "n", 1_500).unwrap();
        assert!(p.admits(&o).is_err());
        assert!(p.admits(&s).is_ok());
    }

    #[test]
    fn local_principals_cannot_come_from_an_idp() {
        let p = provider();
        let mut c = claims();
        c["sub"] = json!("local:admin");
        assert!(p.check_claims(&c, "n", 1_500).is_err());
        let mut c = claims();
        c["groups"] = json!(["engineering", "local:admins"]);
        assert_eq!(
            p.check_claims(&c, "n", 1_500).unwrap().groups,
            ["engineering"]
        );
    }

    #[tokio::test]
    async fn google_is_asked_for_what_it_supports() {
        let mut p = google();
        p.config.hosted_domain = Some("example.com".into());
        let url = p
            .authorize_url("https://cp/cb", "s", "n", "c", Some(3600), true)
            .await
            .unwrap();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        let (_, query) = url.split_once('?').unwrap();
        let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("prompt"), Some("select_account"));
        assert_eq!(get("max_age"), None);
        assert_eq!(get("hd"), Some("example.com"));
        assert_eq!(get("scope"), Some("openid"));
    }

    #[test]
    fn signatures_by_algorithm() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let point = pair.public_key().as_ref();
        let jwk = json!({
            "kty": "EC", "crv": "P-256",
            "x": warren_core::jose::b64url(&point[1..33]),
            "y": warren_core::jose::b64url(&point[33..]),
        });
        let sig = pair.sign(&SystemRandom::new(), b"msg").unwrap();
        assert!(verify("ES256", &jwk, b"msg", sig.as_ref()).is_ok());
        assert!(verify("ES256", &jwk, b"msG", sig.as_ref()).is_err());
        assert!(verify("ES384", &jwk, b"msg", sig.as_ref()).is_err());
        assert!(verify("HS256", &jwk, b"msg", sig.as_ref()).is_err());
    }
}
