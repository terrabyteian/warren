//! TLS for every warren link (docs/protocol.md section 3): rustls on
//! aws-lc-rs only, TLS 1.3 only, no 0-RTT, no session resumption, and
//! certificate verification against the deployment trust bundle with
//! warren's profiles and pushed revocation state.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DistinguishedName, Error, SignatureScheme};

use crate::identity::NodeRole;
use crate::pki::{
    self, CertError, ClientIdentity, Issuer, NodeIdentity, PeerIdentity, TrustBundle,
};

/// ALPN for QUIC links.
pub const ALPN_H3: &[u8] = b"h3";
/// ALPN for the HTTP/2 fallback.
pub const ALPN_H2: &[u8] = b"h2";

/// warren's crypto provider: aws-lc-rs with the profile's TLS 1.3 cipher
/// suites and key exchange groups, hybrid post-quantum first.
pub fn provider() -> Arc<CryptoProvider> {
    let base = aws_lc_rs::default_provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![
            aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
        ],
        ..base
    })
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    aws_lc_rs::default_provider().signature_verification_algorithms
}

/// Live revocation and enablement state, as pushed by the control plane
/// (docs/protocol.md section 12). Verifiers consult it on every handshake.
pub trait RevocationCheck: Send + Sync + fmt::Debug {
    /// Fails if the client's certificate, user, device or session is revoked
    /// or disabled.
    fn check_client(&self, id: &ClientIdentity) -> Result<(), CertError>;
    /// Fails if the node or its certificate is revoked, or a connector's
    /// group is disabled.
    fn check_node(&self, id: &NodeIdentity) -> Result<(), CertError>;
}

/// A revocation check that revokes nothing, for tests and tools.
#[derive(Debug, Default)]
pub struct NoRevocations;

impl RevocationCheck for NoRevocations {
    fn check_client(&self, _: &ClientIdentity) -> Result<(), CertError> {
        Ok(())
    }
    fn check_node(&self, _: &NodeIdentity) -> Result<(), CertError> {
        Ok(())
    }
}

fn to_tls_error(e: CertError) -> Error {
    match e {
        CertError::Revoked(_) => Error::InvalidCertificate(CertificateError::Revoked),
        CertError::Chain(msg) | CertError::Profile(msg) => Error::InvalidCertificate(
            CertificateError::Other(rustls::OtherError(Arc::new(CertError::Profile(msg)))),
        ),
    }
}

/// Which client certificates a server accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptClients {
    /// User+device certificates from the client CA.
    pub users: bool,
    /// Infrastructure certificates with one of these roles; `None` matches
    /// any connector group.
    pub nodes: Vec<NodeRoleMatch>,
}

/// A node role a server accepts as a TLS client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRoleMatch {
    /// Any connector.
    AnyConnector,
    /// The control plane.
    ControlPlane,
}

/// Verifies client certificates: user+device certificates through the
/// client CA and/or infrastructure certificates through the infrastructure
/// CA, each against its profile and the revocation state.
#[derive(Debug)]
pub struct WarrenClientVerifier {
    bundle: Arc<TrustBundle>,
    accept: AcceptClients,
    revocation: Arc<dyn RevocationCheck>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl WarrenClientVerifier {
    /// Creates a verifier.
    pub fn new(
        bundle: Arc<TrustBundle>,
        accept: AcceptClients,
        revocation: Arc<dyn RevocationCheck>,
    ) -> Self {
        Self {
            bundle,
            accept,
            revocation,
            algorithms: algorithms(),
        }
    }
}

/// Classifies and checks a verified client certificate, exactly as the
/// verifier did during the handshake. Applications call this on the peer
/// certificate after the handshake to learn who the peer is.
pub fn verify_client(
    bundle: &TrustBundle,
    accept: &AcceptClients,
    revocation: &dyn RevocationCheck,
    leaf: &CertificateDer<'_>,
    now: UnixTime,
) -> Result<PeerIdentity, CertError> {
    let mut last = CertError::Chain("no acceptable issuer".into());
    if accept.users {
        match bundle.verify_chain(leaf, Issuer::Client, false, now) {
            Ok(()) => {
                let id = pki::check_client_profile(leaf, &bundle.trust_domain)?;
                revocation.check_client(&id)?;
                return Ok(PeerIdentity::Client(id));
            }
            Err(e) => last = e,
        }
    }
    if !accept.nodes.is_empty() {
        bundle.verify_chain(leaf, Issuer::Infrastructure, false, now)?;
        let id = pki::check_infra_profile(leaf, &bundle.trust_domain)?;
        let allowed = accept.nodes.iter().any(|m| {
            matches!(
                (m, &id.role),
                (NodeRoleMatch::AnyConnector, NodeRole::Connector { .. })
                    | (NodeRoleMatch::ControlPlane, NodeRole::ControlPlane)
            )
        });
        if !allowed {
            return Err(CertError::Profile(format!(
                "role {} may not connect here",
                id.role
            )));
        }
        revocation.check_node(&id)?;
        return Ok(PeerIdentity::Node(id));
    }
    Err(last)
}

impl ClientCertVerifier for WarrenClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        verify_client(
            &self.bundle,
            &self.accept,
            self.revocation.as_ref(),
            end_entity,
            now,
        )
        .map(|_| ClientCertVerified::assertion())
        .map_err(to_tls_error)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
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

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// What a client expects of the server it dials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectServer {
    /// A relay whose certificate names the dialled DNS name.
    Relay,
    /// A connector in this group (the inner session's server).
    Connector {
        /// Connector group.
        group: String,
    },
}

/// Verifies server certificates through the infrastructure CA: relays by
/// DNS name and role, connectors by group (docs/protocol.md section 5).
#[derive(Debug)]
pub struct WarrenServerVerifier {
    bundle: Arc<TrustBundle>,
    expect: ExpectServer,
    revocation: Arc<dyn RevocationCheck>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl WarrenServerVerifier {
    /// Creates a verifier.
    pub fn new(
        bundle: Arc<TrustBundle>,
        expect: ExpectServer,
        revocation: Arc<dyn RevocationCheck>,
    ) -> Self {
        Self {
            bundle,
            expect,
            revocation,
            algorithms: algorithms(),
        }
    }
}

/// Checks a server certificate, exactly as the verifier did.
pub fn verify_server(
    bundle: &TrustBundle,
    expect: &ExpectServer,
    revocation: &dyn RevocationCheck,
    leaf: &CertificateDer<'_>,
    server_name: &ServerName<'_>,
    now: UnixTime,
) -> Result<NodeIdentity, CertError> {
    bundle.verify_chain(leaf, Issuer::Infrastructure, true, now)?;
    let id = pki::check_infra_profile(leaf, &bundle.trust_domain)?;
    match (expect, &id.role) {
        (ExpectServer::Relay, NodeRole::Relay) => {
            let ee = webpki::EndEntityCert::try_from(leaf)
                .map_err(|e| CertError::Chain(e.to_string()))?;
            ee.verify_is_valid_for_subject_name(server_name)
                .map_err(|e| CertError::Chain(format!("relay name: {e}")))?;
        }
        (ExpectServer::Connector { group }, NodeRole::Connector { group: g }) if g == group => {}
        _ => {
            return Err(CertError::Profile(format!(
                "expected {expect:?}, the certificate names {}",
                id.role
            )));
        }
    }
    revocation.check_node(&id)?;
    Ok(id)
}

impl ServerCertVerifier for WarrenServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        verify_server(
            &self.bundle,
            &self.expect,
            self.revocation.as_ref(),
            end_entity,
            server_name,
            now,
        )
        .map(|_| ServerCertVerified::assertion())
        .map_err(to_tls_error)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
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

/// A certificate chain and its private key.
#[derive(Debug)]
pub struct Credentials {
    /// Chain, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// Private key.
    pub key: PrivateKeyDer<'static>,
}

impl Clone for Credentials {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl Credentials {
    /// Loads a PEM chain and a PEM private key.
    pub fn load(chain: &std::path::Path, key: &std::path::Path) -> Result<Credentials, String> {
        use rustls::pki_types::pem::PemObject;
        let chain = pki::load_chain(chain).map_err(|e| e.to_string())?;
        let key =
            PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
        Ok(Credentials { chain, key })
    }
}

/// Builds a client configuration for one link.
pub fn client_config(
    creds: &Credentials,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: &[u8],
) -> Result<rustls::ClientConfig, Error> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(creds.chain.clone(), creds.key.clone_key())?;
    config.alpn_protocols = vec![alpn.to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// Builds a server configuration for one link.
pub fn server_config(
    creds: &Credentials,
    verifier: Arc<dyn ClientCertVerifier>,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, Error> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(creds.chain.clone(), creds.key.clone_key())?;
    config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(config)
}

/// The current time for verification.
pub fn now() -> UnixTime {
    pki::unix_time(SystemTime::now())
}
