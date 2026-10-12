//! Link D: the client's calls to the control plane (docs/protocol.md
//! section 11.1), over HTTPS with HTTP/2.
//!
//! Before enrollment the client verifies the organization URL with the
//! system's trust store or with a deployment root fingerprint an MDM
//! profile (or the administrator) gave it. Once enrolled it makes every
//! call at the `api_base` enrollment returned and verifies the control
//! plane there against the deployment trust bundle alone, requiring its
//! control-plane certificate, so a certificate the system happens to trust
//! can never stand in for it (docs/protocol.md section 10.1).
//!
//! Every refusal arrives as RFC 9457 problem details with a stable reason
//! code and a sentence written for people, which [`ApiError`] keeps, so
//! the client can always say why something failed (G12).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use warren_core::api::{
    CertificateRequest, CertificateResponse, DeviceInfo, Discovery, Entitlements, Problem,
};
use warren_core::join::sha256_hex;
use warren_core::params::{PROTOCOL_HEADER, PROTOCOL_VERSION};
use warren_core::pki::{self, TrustBundle};
use warren_core::tls::{
    self, DeviceCredentials, ExpectServer, NoRevocations, WarrenServerVerifier,
};
use warren_masque::h2::H2Client;
use warren_masque::http::RequestHead;
use warren_masque::join::PinnedRoot;

use crate::device::DeviceKey;
use crate::state::{CertificateTimes, DeviceState, Profile, Store, StoredCertificate};

/// How long a call may take, connection included.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest response body the client accepts.
const MAX_BODY: usize = 4 << 20;

/// A failed call: the control plane's problem details, or a transport
/// failure with reason `unreachable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status, or 0 when no response arrived.
    pub status: u16,
    /// A stable reason code, such as `device_not_approved`.
    pub reason: String,
    /// What happened, for people.
    pub detail: String,
}

impl ApiError {
    fn unreachable(what: impl std::fmt::Display) -> ApiError {
        ApiError {
            status: 0,
            reason: "unreachable".into(),
            detail: what.to_string(),
        }
    }

    /// Whether signing in again in the browser is the remedy.
    pub fn needs_sign_in(&self) -> bool {
        matches!(
            self.reason.as_str(),
            "reauth_required" | "revoked" | "user_disabled" | "unauthenticated"
        ) || self.status == 401
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ApiError {}

/// How the organization URL is verified before enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgTrust {
    /// The system's trust store (macOS: its trust evaluation, which honors
    /// MDM-installed roots).
    System,
    /// A deployment root, by the lowercase hex SHA-256 of its DER.
    Pinned(String),
}

impl OrgTrust {
    /// Parses a fingerprint as `sha256:HEX`, plain hex, or hex with
    /// colons, as people copy it from different places.
    pub fn pinned(text: &str) -> Result<OrgTrust, String> {
        let hex: String = text
            .trim()
            .trim_start_matches("sha256:")
            .trim_start_matches("SHA256:")
            .chars()
            .filter(|c| *c != ':')
            .collect::<String>()
            .to_ascii_lowercase();
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("a root fingerprint is the 64-digit hex SHA-256 of the root certificate (warren admin deployment shows it)".into());
        }
        Ok(OrgTrust::Pinned(hex))
    }
}

/// An `https` URL split into what a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The host name (no brackets for IPv6 literals).
    pub host: String,
    /// The port.
    pub port: u16,
    /// The path, starting with `/` (no trailing slash unless it is `/`).
    pub path: String,
}

impl Endpoint {
    /// Parses `https://host[:port][/path]`.
    pub fn parse(url: &str) -> Result<Endpoint, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("{url}: only https URLs are accepted"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') || path.contains(['?', '#']) {
            return Err(format!("{url}: not a plain https URL"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6
                .split_once(']')
                .ok_or_else(|| format!("{url}: unclosed IPv6 literal"))?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("{url}: bad port"))?,
                None if after.is_empty() => 443,
                None => return Err(format!("{url}: bad authority")),
            };
            (h.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_owned(),
                    p.parse().map_err(|_| format!("{url}: bad port"))?,
                ),
                None => (authority.to_owned(), 443),
            }
        };
        if host.is_empty() {
            return Err(format!("{url}: no host"));
        }
        let path = path.trim_end_matches('/');
        Ok(Endpoint {
            host: host.to_ascii_lowercase(),
            port,
            path: if path.is_empty() {
                "/".into()
            } else {
                path.into()
            },
        })
    }

    /// `host[:port]` as `:authority` carries it.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The URL again, normalized.
    pub fn url(&self) -> String {
        let path = if self.path == "/" { "" } else { &self.path };
        format!("https://{}{path}", self.authority())
    }

    /// A path under this endpoint's path.
    pub fn join(&self, rest: &str) -> String {
        let base = if self.path == "/" { "" } else { &self.path };
        format!("{base}{rest}")
    }
}

/// Normalizes what a person types as an organization URL: a bare host is
/// taken as `https://host`.
pub fn org_url(input: &str) -> Result<String, String> {
    let input = input.trim();
    let url = if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };
    let e = Endpoint::parse(&url)?;
    if e.path != "/" {
        return Err(format!(
            "{input}: the organization URL is just https://host, without a path"
        ));
    }
    Ok(e.url())
}

/// Verifies the organization URL with the system's trust evaluation.
#[cfg(target_os = "macos")]
#[derive(Debug)]
struct SystemTrust(rustls::crypto::WebPkiSupportedAlgorithms);

#[cfg(target_os = "macos")]
impl ServerCertVerifier for SystemTrust {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let host = match server_name {
            ServerName::DnsName(d) => d.as_ref().to_owned(),
            ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
            _ => return Err(rustls::Error::General("unsupported server name".into())),
        };
        let chain: Vec<&[u8]> = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|c| c.as_ref())
            .collect();
        crate::apple::evaluate_server_trust(&chain, &host)
            .map(|()| rustls::client::danger::ServerCertVerified::assertion())
            .map_err(|e| {
                rustls::Error::General(format!(
                    "this Mac does not trust the certificate of {host}: {e}"
                ))
            })
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

fn tls_config(verifier: Arc<dyn ServerCertVerifier>) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut config = rustls::ClientConfig::builder_with_provider(tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![tls::ALPN_H2.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// The TLS configuration for calls at the organization URL.
pub fn org_tls(
    trust: &OrgTrust,
    trust_domain: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let verifier: Arc<dyn ServerCertVerifier> = match trust {
        OrgTrust::Pinned(pin) => Arc::new(match trust_domain {
            Some(td) => PinnedRoot::new(pin, td),
            None => PinnedRoot::any_trust_domain(pin),
        }),
        #[cfg(target_os = "macos")]
        OrgTrust::System => Arc::new(SystemTrust(
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )),
        #[cfg(not(target_os = "macos"))]
        OrgTrust::System => {
            return Err(
                "verifying the organization URL with the system trust store is implemented on macOS only; pass the deployment root fingerprint".into(),
            );
        }
    };
    tls_config(verifier)
}

/// The TLS configuration for enrolled calls: the control plane's own
/// certificate, verified against the trust bundle.
pub fn api_tls(trust: Arc<TrustBundle>) -> Result<Arc<rustls::ClientConfig>, String> {
    tls_config(Arc::new(WarrenServerVerifier::new(
        trust,
        ExpectServer::ControlPlane,
        Arc::new(NoRevocations),
    )))
}

/// One request: method, URL, bearer token, and a body with its type.
pub struct Call<'a> {
    /// `GET` or `POST`.
    pub method: &'a str,
    /// The full `https` URL.
    pub url: &'a str,
    /// The session token, if any.
    pub token: Option<&'a str>,
    /// The body and its content type.
    pub body: Option<(&'static str, Vec<u8>)>,
}

async fn connect(e: &Endpoint) -> Result<TcpStream, ApiError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((e.host.as_str(), e.port))
        .await
        .map_err(|err| ApiError::unreachable(format!("cannot resolve {}: {err}", e.host)))?
        .collect();
    let mut last = format!("{}: no address", e.host);
    for addr in addrs {
        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(err)) => last = format!("{addr}: {err}"),
            Err(_) => last = format!("{addr}: timed out"),
        }
    }
    Err(ApiError::unreachable(format!(
        "cannot reach the control plane at {}: {last}",
        e.authority()
    )))
}

/// Makes one call and returns the response body, or the refusal as an
/// [`ApiError`].
pub async fn call(tls: &Arc<rustls::ClientConfig>, c: Call<'_>) -> Result<Bytes, ApiError> {
    tokio::time::timeout(CALL_TIMEOUT, call_inner(tls, c))
        .await
        .map_err(|_| ApiError::unreachable("the control plane did not answer in time"))?
}

async fn call_inner(tls: &Arc<rustls::ClientConfig>, c: Call<'_>) -> Result<Bytes, ApiError> {
    let e = Endpoint::parse(c.url).map_err(ApiError::unreachable)?;
    let tcp = connect(&e).await?;
    let name = ServerName::try_from(e.host.clone()).map_err(ApiError::unreachable)?;
    let (mut client, _) = H2Client::connect_with(tcp, tls.clone(), name, false)
        .await
        .map_err(|err| ApiError::unreachable(format!("{}: {err}", e.authority())))?;
    let mut headers = vec![
        ("accept".to_owned(), "application/json".to_owned()),
        (PROTOCOL_HEADER.to_owned(), PROTOCOL_VERSION.to_string()),
    ];
    if let Some(t) = c.token {
        headers.push(("authorization".into(), format!("Bearer {t}")));
    }
    let body = match c.body {
        Some((content_type, body)) => {
            headers.push(("content-type".into(), content_type.into()));
            Bytes::from(body)
        }
        None => Bytes::new(),
    };
    let head = RequestHead {
        method: c.method.into(),
        scheme: Some("https".into()),
        authority: Some(e.authority()),
        path: Some(e.path.clone()),
        protocol: None,
        headers,
    };
    let (resp, body) = client
        .exchange(&head, body, MAX_BODY)
        .await
        .map_err(|err| ApiError::unreachable(format!("{}: {err}", e.authority())))?;
    if (200..300).contains(&resp.status) {
        return Ok(body);
    }
    Err(match serde_json::from_slice::<Problem>(&body) {
        Ok(p) => ApiError {
            status: resp.status,
            reason: p.reason,
            detail: p.detail,
        },
        Err(_) => ApiError {
            status: resp.status,
            reason: format!("http_{}", resp.status),
            detail: format!(
                "the control plane answered {} without an explanation",
                resp.status
            ),
        },
    })
}

/// Decodes a JSON response.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| ApiError {
        status: 200,
        reason: "malformed_response".into(),
        detail: format!("the control plane's answer is malformed: {e}"),
    })
}

/// A JSON body.
pub fn json_body<T: Serialize>(value: &T) -> Option<(&'static str, Vec<u8>)> {
    serde_json::to_vec(value)
        .ok()
        .map(|b| ("application/json", b))
}

/// Fetches discovery from the organization URL and checks its trust
/// bundle: against the pinned root, or as delivered over a connection the
/// system's trust store verified.
pub async fn discover(org: &str, trust: &OrgTrust) -> Result<(Discovery, TrustBundle), ApiError> {
    let url = format!("{org}/.well-known/warren");
    let tls = org_tls(trust, None).map_err(ApiError::unreachable)?;
    let body = call(
        &tls,
        Call {
            method: "GET",
            url: &url,
            token: None,
            body: None,
        },
    )
    .await?;
    let d: Discovery = decode(&body)?;
    if !d.protocol_versions.contains(&PROTOCOL_VERSION) {
        return Err(ApiError {
            status: 200,
            reason: "unsupported_protocol".into(),
            detail: format!(
                "this control plane speaks protocol versions {:?}; this client speaks {PROTOCOL_VERSION}. Update warren.",
                d.protocol_versions
            ),
        });
    }
    let bad = |m: String| ApiError {
        status: 200,
        reason: "malformed_response".into(),
        detail: m,
    };
    let certs =
        pem_certs(&d.trust_bundle).map_err(|e| bad(format!("discovery trust bundle: {e}")))?;
    let [root, client, infra] = <[CertificateDer<'static>; 3]>::try_from(certs).map_err(|_| {
        bad("the discovery trust bundle must hold the root, client and infrastructure CAs".into())
    })?;
    if let OrgTrust::Pinned(pin) = trust
        && sha256_hex(&root) != *pin
    {
        return Err(ApiError {
            status: 200,
            reason: "root_mismatch".into(),
            detail: "the deployment's trust bundle does not have the root you pinned".into(),
        });
    }
    let bundle = TrustBundle::new(&d.trust_domain, root, vec![client], vec![infra])
        .map_err(|e| bad(format!("discovery trust bundle: {e}")))?;
    Ok((d, bundle))
}

fn pem_certs(text: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(text.as_bytes())
        .map(|c| c.map_err(|e| e.to_string()))
        .collect()
}

impl From<&DeviceInfo> for DeviceState {
    fn from(d: &DeviceInfo) -> Self {
        DeviceState {
            id: d.id.clone(),
            status: d.status.clone(),
            tunnel_v4: d.tunnel_v4.clone(),
            tunnel_v6: d.tunnel_v6.clone(),
            trust_class: d.trust_class,
        }
    }
}

/// A signed-in client: its profile, trust bundle and device key, and the
/// calls it makes once enrolled.
#[derive(Clone)]
pub struct Account {
    store: Store,
    /// The profile as last saved.
    pub profile: Profile,
    /// The deployment trust bundle.
    pub trust: Arc<TrustBundle>,
    /// The device key.
    pub key: Arc<DeviceKey>,
    org_tls: Arc<rustls::ClientConfig>,
    api_tls: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("org", &self.profile.org_url)
            .field("user", &self.profile.user.id)
            .finish_non_exhaustive()
    }
}

impl Account {
    /// Loads the signed-in account from `store`.
    pub fn load(store: &Store) -> Result<Account, String> {
        let profile = store
            .profile()?
            .ok_or("not signed in; run `warren login <organization URL>` first")?;
        let trust = Arc::new(store.trust(&profile.trust_domain)?);
        let key = Arc::new(DeviceKey::load(store.dir())?);
        Account::new(store.clone(), profile, trust, key)
    }

    /// An account from its parts.
    pub fn new(
        store: Store,
        profile: Profile,
        trust: Arc<TrustBundle>,
        key: Arc<DeviceKey>,
    ) -> Result<Account, String> {
        let org_trust = match &profile.pin {
            Some(pin) => OrgTrust::Pinned(pin.clone()),
            None => OrgTrust::System,
        };
        let org_tls = org_tls(&org_trust, Some(&profile.trust_domain))?;
        let api_tls = api_tls(trust.clone())?;
        Ok(Account {
            store,
            profile,
            trust,
            key,
            org_tls,
            api_tls,
        })
    }

    /// The store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    fn token(&self) -> &str {
        &self.profile.session.token
    }

    /// Asks the control plane about this device and saves the answer,
    /// learning a new `api_base` if it moved.
    pub async fn refresh_device(&mut self) -> Result<DeviceState, ApiError> {
        let url = format!("{}/devices/current", self.profile.signin_api_base);
        let body = call(
            &self.org_tls,
            Call {
                method: "GET",
                url: &url,
                token: Some(self.token()),
                body: None,
            },
        )
        .await?;
        let info: DeviceInfo = decode(&body)?;
        let device = DeviceState::from(&info);
        self.profile.device = Some(device.clone());
        self.profile.api_base = Some(info.api_base);
        self.save()?;
        Ok(device)
    }

    fn save(&self) -> Result<(), ApiError> {
        self.store
            .save_profile(&self.profile)
            .map_err(|e| ApiError::unreachable(format!("cannot save the profile: {e}")))
    }

    async fn api_call(
        &mut self,
        method: &str,
        path: &str,
        body: Option<(&'static str, Vec<u8>)>,
    ) -> Result<Bytes, ApiError> {
        for attempt in 0..2 {
            let base = match &self.profile.api_base {
                Some(b) => b.clone(),
                None => {
                    self.refresh_device().await?;
                    self.profile.api_base.clone().unwrap_or_default()
                }
            };
            let url = format!("{base}{path}");
            let result = call(
                &self.api_tls,
                Call {
                    method,
                    url: &url,
                    token: Some(self.token()),
                    body: body.clone(),
                },
            )
            .await;
            match result {
                // The control plane moved enrolled calls elsewhere: learn
                // where, then try once more (docs/operating.md).
                Err(e) if e.status == 421 && attempt == 0 => {
                    self.profile.api_base = None;
                }
                other => return other,
            }
        }
        unreachable!("the loop returns on its second attempt")
    }

    /// Requests a certificate for the device key and saves it.
    pub async fn issue_certificate(&mut self) -> Result<StoredCertificate, ApiError> {
        let csr = self
            .key
            .certificate_request()
            .map_err(|e| ApiError::unreachable(format!("the device key cannot sign: {e}")))?;
        let req = CertificateRequest {
            csr: warren_core::base64::encode(&csr),
        };
        let body = self
            .api_call("POST", "/certificates", json_body(&req))
            .await?;
        let resp: CertificateResponse = decode(&body)?;
        let chain = pem_certs(&resp.certificate_chain).map_err(|e| ApiError {
            status: 200,
            reason: "malformed_response".into(),
            detail: format!("the issued certificate is malformed: {e}"),
        })?;
        self.check_issued(&chain)?;
        let cert = StoredCertificate {
            chain,
            serial: resp.serial,
            times: CertificateTimes {
                not_before: resp.not_before,
                not_after: resp.not_after,
                renew_at: resp.renew_at,
            },
        };
        self.store
            .save_certificate(&cert)
            .map_err(|e| ApiError::unreachable(format!("cannot save the certificate: {e}")))?;
        Ok(cert)
    }

    /// Checks that an issued certificate chains to the client CA, has the
    /// user+device profile, and carries this device's key.
    fn check_issued(&self, chain: &[CertificateDer<'static>]) -> Result<(), ApiError> {
        let bad = |m: String| ApiError {
            status: 200,
            reason: "bad_certificate".into(),
            detail: format!("the control plane issued an unusable certificate: {m}"),
        };
        let leaf = chain.first().ok_or_else(|| bad("empty chain".into()))?;
        self.trust
            .verify_chain(leaf, pki::Issuer::Client, false, tls::now())
            .map_err(|e| bad(e.to_string()))?;
        let id = pki::check_client_profile(leaf, &self.trust.trust_domain)
            .map_err(|e| bad(e.to_string()))?;
        if id.user != self.profile.user.id {
            return Err(bad(format!("it names user {}", id.user)));
        }
        if id.spki != self.key.spki() {
            return Err(bad("it is for another key".into()));
        }
        Ok(())
    }

    /// Fetches the user's entitlements and saves them.
    pub async fn entitlements(&mut self) -> Result<Entitlements, ApiError> {
        let body = self.api_call("GET", "/entitlements", None).await?;
        let e: Entitlements = decode(&body)?;
        let _ = self.store.save_entitlements(&e);
        Ok(e)
    }

    /// Device credentials for a certificate: its chain and the device key
    /// as the TLS signer.
    pub fn credentials(&self, cert: &StoredCertificate) -> DeviceCredentials {
        DeviceCredentials::External {
            chain: cert.chain.clone(),
            signer: self.key.tls_signer(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse_and_normalize() {
        let e = Endpoint::parse("https://Warren.Example.com:8443/v1/").unwrap();
        assert_eq!(e.host, "warren.example.com");
        assert_eq!(e.port, 8443);
        assert_eq!(e.path, "/v1");
        assert_eq!(e.authority(), "warren.example.com:8443");
        assert_eq!(e.join("/devices"), "/v1/devices");
        let e = Endpoint::parse("https://[fd00::1]/").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("fd00::1", 443));
        assert_eq!(e.url(), "https://[fd00::1]");
        assert!(Endpoint::parse("http://warren.example.com").is_err());
        assert!(Endpoint::parse("https://user@warren.example.com").is_err());
        assert!(Endpoint::parse("https://warren.example.com/?x=1").is_err());
        assert!(Endpoint::parse("https://:443").is_err());
    }

    #[test]
    fn organization_urls_are_just_hosts() {
        assert_eq!(
            org_url("warren.example.com").unwrap(),
            "https://warren.example.com"
        );
        assert_eq!(
            org_url("https://warren.example.com:8443/").unwrap(),
            "https://warren.example.com:8443"
        );
        assert!(org_url("https://warren.example.com/app").is_err());
        assert!(org_url("ftp://warren.example.com").is_err());
    }

    #[test]
    fn fingerprints_parse_in_common_spellings() {
        let hex = "ab".repeat(32);
        assert_eq!(
            OrgTrust::pinned(&hex).unwrap(),
            OrgTrust::Pinned(hex.clone())
        );
        assert_eq!(
            OrgTrust::pinned(&format!("sha256:{}", hex.to_uppercase())).unwrap(),
            OrgTrust::Pinned(hex.clone())
        );
        let colons: Vec<String> = (0..32).map(|_| "AB".to_owned()).collect();
        assert_eq!(
            OrgTrust::pinned(&colons.join(":")).unwrap(),
            OrgTrust::Pinned(hex)
        );
        assert!(OrgTrust::pinned("abcd").is_err());
        assert!(OrgTrust::pinned(&"zz".repeat(32)).is_err());
    }
}
