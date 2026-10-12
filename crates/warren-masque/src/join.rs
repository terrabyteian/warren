//! The node side of the join exchange (docs/protocol.md section 10.3): a
//! new relay or connector sends its signed certificate request and a join
//! token to the control plane over HTTPS, pinning the deployment root from
//! the token, and receives its first certificate and the trust bundle.

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{Error, SignatureScheme};
use tokio::net::TcpStream;
use warren_core::identity::NodeRole;
use warren_core::join::{
    JOIN_PATH, JoinError, JoinRequest, JoinResponse, JoinToken, NodeKey, sha256_hex,
};
use warren_core::pki::{self, Issuer, NodeIdentity, TrustBundle};
use warren_core::tls::Credentials;
use warren_core::{base64, tls};

use crate::h2::H2Client;
use crate::http::RequestHead;

/// What a successful join produced.
#[derive(Debug)]
pub struct Joined {
    /// The node's certificate chain and its key.
    pub credentials: Credentials,
    /// The deployment trust bundle.
    pub trust: TrustBundle,
    /// The identity the control plane assigned.
    pub identity: NodeIdentity,
}

/// Verifies the control plane's certificate against a pinned deployment
/// root: the root a join token pins, before a node has a trust bundle, or
/// the fingerprint an MDM profile presets for a client signing in
/// (docs/protocol.md section 10.1). The control plane presents the root in
/// its chain, and its certificate must name the control-plane role in the
/// trust domain.
#[derive(Debug)]
pub struct PinnedRoot {
    pin: String,
    trust_domain: Option<String>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedRoot {
    /// Pins the root whose DER has SHA-256 `pin` (lowercase hex), for a
    /// control plane of `trust_domain`.
    pub fn new(pin: &str, trust_domain: &str) -> PinnedRoot {
        PinnedRoot {
            pin: pin.to_ascii_lowercase(),
            trust_domain: Some(trust_domain.to_owned()),
            algorithms: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }

    /// Pins a root without knowing the trust domain yet, as a client does
    /// before discovery: the certificate must still name the control-plane
    /// role, in whichever trust domain it names.
    pub fn any_trust_domain(pin: &str) -> PinnedRoot {
        PinnedRoot {
            trust_domain: None,
            ..PinnedRoot::new(pin, "")
        }
    }
}

/// The trust domain a node certificate's warren URI names.
fn named_trust_domain(leaf: &[u8]) -> Option<String> {
    let names = pki::parse_cert(leaf).ok()?.subject_alt_names().ok()?;
    names.uris.iter().find_map(|u| {
        u.strip_prefix("warren://")
            .and_then(|rest| rest.split('/').next())
            .map(str::to_owned)
    })
}

impl ServerCertVerifier for PinnedRoot {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fail = |m: &str| Error::General(m.to_owned());
        let root = intermediates
            .iter()
            .find(|c| sha256_hex(c) == self.pin)
            .ok_or_else(|| fail("the control plane did not present the pinned deployment root"))?;
        let anchor = webpki::anchor_from_trusted_cert(root).map_err(|e| fail(&e.to_string()))?;
        let others: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .filter(|c| *c != root)
            .cloned()
            .collect();
        let ee = webpki::EndEntityCert::try_from(end_entity).map_err(|e| fail(&e.to_string()))?;
        ee.verify_for_usage(
            self.algorithms.all,
            &[anchor],
            &others,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| fail(&format!("control plane certificate: {e}")))?;
        ee.verify_is_valid_for_subject_name(server_name)
            .map_err(|e| fail(&format!("control plane name: {e}")))?;
        let trust_domain = match &self.trust_domain {
            Some(td) => td.clone(),
            None => named_trust_domain(end_entity)
                .ok_or_else(|| fail("the control plane certificate names no trust domain"))?,
        };
        let id = pki::check_infra_profile(end_entity, &trust_domain)
            .map_err(|e| fail(&e.to_string()))?;
        if id.role != NodeRole::ControlPlane {
            return Err(fail("the join endpoint is not the control plane"));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn der(field: &str, b64: &str) -> Result<CertificateDer<'static>, JoinError> {
    base64::decode(b64)
        .map(CertificateDer::from)
        .ok_or_else(|| JoinError(format!("{field} is not base64")))
}

/// Joins the deployment named by `token` with `key`.
pub async fn join(token: &JoinToken, key: &NodeKey) -> Result<Joined, JoinError> {
    let fail = |e: &dyn std::fmt::Display| JoinError(e.to_string());
    let host = token
        .cp
        .rsplit_once(':')
        .map_or(token.cp.as_str(), |(h, _)| h)
        .to_owned();
    let addrs: Vec<std::net::SocketAddr> = token
        .cp
        .to_socket_addrs()
        .map_err(|e| JoinError(format!("{}: {e}", token.cp)))?
        .collect();
    let verifier = Arc::new(PinnedRoot::new(&token.root, &token.td));
    let mut config = rustls::ClientConfig::builder_with_provider(tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| fail(&e))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![tls::ALPN_H2.to_vec()];
    let mut tcp = None;
    let mut last = format!("{}: no address", token.cp);
    for addr in addrs {
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last = format!("{addr}: {e}"),
            Err(_) => last = format!("{addr}: timed out"),
        }
    }
    let tcp = tcp.ok_or(JoinError(last))?;
    let name = ServerName::try_from(host.clone()).map_err(|e| fail(&e))?;
    let (mut client, _) = H2Client::connect_with(tcp, Arc::new(config), name, false)
        .await
        .map_err(|e| fail(&e))?;
    let body = serde_json::to_vec(&JoinRequest {
        token: token.encode(),
        csr: base64::encode(&key.certificate_request()?),
    })
    .map_err(|e| fail(&e))?;
    let head = RequestHead {
        method: "POST".into(),
        scheme: Some("https".into()),
        authority: Some(host),
        path: Some(JOIN_PATH.into()),
        protocol: None,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            (
                crate::connect::WARREN_PROTOCOL.into(),
                crate::connect::PROTOCOL_VERSION.to_string(),
            ),
        ],
    };
    let (resp, body) = client
        .exchange(&head, Bytes::from(body), 1 << 20)
        .await
        .map_err(|e| fail(&e))?;
    if resp.status != 200 {
        return Err(JoinError(format!(
            "the control plane refused the join ({}): {}",
            resp.status,
            String::from_utf8_lossy(&body)
        )));
    }
    let r: JoinResponse =
        serde_json::from_slice(&body).map_err(|e| JoinError(format!("malformed response: {e}")))?;

    // The response must stay inside what the token pinned and promised.
    let root = der("root", &r.trust_bundle.root)?;
    if sha256_hex(&root) != token.root.to_ascii_lowercase() {
        return Err(JoinError(
            "the returned trust bundle has a different root".into(),
        ));
    }
    let collect =
        |v: &[String], f: &str| v.iter().map(|c| der(f, c)).collect::<Result<Vec<_>, _>>();
    let trust = TrustBundle::new(
        &token.td,
        root,
        collect(&r.trust_bundle.client_cas, "clientCas")?,
        collect(&r.trust_bundle.infra_cas, "infraCas")?,
    )
    .map_err(|e| fail(&e))?;
    let chain = collect(&r.chain, "chain")?;
    let leaf = chain
        .first()
        .ok_or_else(|| JoinError("empty certificate chain".into()))?;
    // Relays serve clients; connectors are TLS clients of relays.
    let role = token.node_role();
    let server_use = matches!(role, NodeRole::Relay);
    trust
        .verify_chain(leaf, Issuer::Infrastructure, server_use, tls::now())
        .map_err(|e| fail(&e))?;
    let identity = pki::check_infra_profile(leaf, &token.td).map_err(|e| fail(&e))?;
    if identity.role != role {
        return Err(JoinError(format!(
            "the certificate names {}, the token {role}",
            identity.role
        )));
    }
    let leaf_spki = pki::parse_cert(leaf).map_err(|e| fail(&e))?.spki.to_vec();
    if leaf_spki != key.spki() {
        return Err(JoinError(
            "the certificate is not for this node's key".into(),
        ));
    }
    Ok(Joined {
        credentials: Credentials {
            chain,
            key: key.private_key(),
        },
        trust,
        identity,
    })
}
