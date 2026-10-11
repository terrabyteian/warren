//! Request and response bodies of the control-plane APIs: link D, used by
//! clients, and link E, used by relays and connectors (docs/protocol.md
//! section 11). Every body is JSON. Binary values (DER) are standard base64;
//! certificates travel as PEM.

use serde::{Deserialize, Serialize};

use crate::jose::Jwk;

/// `GET /.well-known/warren`: what a client needs to start, given only the
/// organization URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    /// The deployment's trust domain.
    pub trust_domain: String,
    /// The base URL of the versioned API, for example
    /// `https://warren.example.com/v1`.
    pub api_base: String,
    /// Where the client sends the system browser to sign in.
    pub authorize_endpoint: String,
    /// Where the client exchanges the sign-in code for a session.
    pub token_endpoint: String,
    /// The deployment trust bundle: the root CA, then the client CA, then
    /// the infrastructure CA, as PEM.
    pub trust_bundle: String,
    /// Protocol versions this control plane accepts.
    pub protocol_versions: Vec<u32>,
}

/// The JWS `typ` of a session request.
pub const SESSION_REQUEST_TYP: &str = "warren-session-request+jws";

/// The payload of a session request: the client exchanges the one-time
/// sign-in code, with its PKCE verifier, for a session bound to the device
/// key. The request is a JWS signed by the device key with that key in the
/// header's `jwk` member, so the session is bound to a key the client has
/// proven it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    /// The one-time code from the sign-in redirect.
    pub code: String,
    /// The PKCE code verifier (RFC 7636) whose S256 challenge the client
    /// sent when sign-in started.
    pub code_verifier: String,
    /// The redirect URI sign-in used.
    pub redirect_uri: String,
    /// When the client made the request, Unix seconds.
    pub iat: i64,
}

/// A user as the APIs show them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// The warren user ID.
    pub id: String,
    /// The verified email address, if the IdP asserted one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// IdP groups.
    pub groups: Vec<String>,
}

/// A sign-in session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The session ID, also carried in certificates.
    pub session_id: String,
    /// The bearer token for link D calls. Treat as a secret.
    pub token: String,
    /// When the session ends and the user must sign in again, Unix
    /// seconds.
    pub expires_at: i64,
    /// The signed-in user.
    pub user: UserInfo,
    /// When the user authenticated at the IdP, Unix seconds, or 0 when the
    /// IdP did not say (`x509::AUTH_TIME_UNKNOWN`).
    pub auth_time: i64,
    /// Whether that authentication used multi-factor authentication.
    pub mfa: bool,
}

/// Device facts the client reports at enrollment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// Operating system, for example `macos`.
    pub os: String,
    /// Operating system version, for example `15.4.1`.
    #[serde(default)]
    pub os_version: String,
    /// Hardware model.
    #[serde(default)]
    pub model: String,
    /// Host name, for display only.
    #[serde(default)]
    pub hostname: String,
}

/// `POST /v1/devices`: enroll the session's device key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// A PKCS#10 request signed by the device key, DER, base64.
    pub csr: String,
    /// Platform facts.
    pub platform: Platform,
    /// Where the key lives: `secure-enclave` or `software`. Without a
    /// hardware attestation this is the client's claim, recorded as trust
    /// class 1 (device-reported).
    pub key_storage: String,
}

/// A device as the APIs show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// The device ID.
    pub id: String,
    /// `pending`, `approved`, `disabled` or `revoked`.
    pub status: String,
    /// The IPv4 tunnel address.
    pub tunnel_v4: String,
    /// The IPv6 tunnel address.
    pub tunnel_v6: String,
    /// The enrollment trust class, 1 to 3.
    pub trust_class: u8,
}

/// `POST /v1/certificates` and `POST /v1/node/certificate`: issue or renew a
/// certificate for the key that signed `csr`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// A PKCS#10 request, DER, base64.
    pub csr: String,
}

/// An issued certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateResponse {
    /// The certificate followed by its issuing CA, PEM.
    pub certificate_chain: String,
    /// The serial number, lowercase hex.
    pub serial: String,
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// When to renew, Unix seconds: half-life.
    pub renew_at: i64,
}

/// `GET /v1/entitlements`: the apps the user may reach or request. It never
/// names apps the user may neither reach nor request, and nothing in it is
/// secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlements {
    /// The bundle version the entitlements were computed from.
    pub version: u64,
    /// The apps.
    pub apps: Vec<EntitledApp>,
    /// DNS suffixes and names the client claims for split DNS.
    pub dns_suffixes: Vec<String>,
    /// The relays the client may use.
    pub relays: Vec<Relay>,
}

/// One app in a user's entitlements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitledApp {
    /// The app's name.
    pub name: String,
    /// `allowed` when a rule may admit the user (subject to its conditions,
    /// which the connector checks per flow), `requestable` when the user
    /// may only request access.
    pub access: String,
    /// The connector group to reach it through.
    pub connector_group: String,
    /// Client-facing destinations. Connector-side targets are not included.
    pub destinations: Vec<EntitledDestination>,
}

/// One client-facing destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitledDestination {
    /// The client-facing host name, exact or `*.`-wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// An address or CIDR range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// `tcp`, `udp`, `icmp` or `any`.
    pub protocol: String,
    /// Port ranges; empty means every port.
    pub ports: Vec<crate::policy_bundle::PortRange>,
}

/// A relay a client may dial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    /// The relay's node ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// The DNS names it listens on.
    pub dns_names: Vec<String>,
}

/// `POST /v1/join`: a relay or connector exchanges a single-use join token
/// for its first infrastructure certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The join token.
    pub token: String,
    /// A PKCS#10 request signed by the node's key, DER, base64.
    pub csr: String,
    /// The node's name, unique within its role.
    pub name: String,
    /// DNS names the node listens on (relays).
    #[serde(default)]
    pub dns_names: Vec<String>,
}

/// The answer to a join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    /// The node's ID.
    pub node_id: String,
    /// `relay` or `connector`.
    pub role: String,
    /// The connector group, for connectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The deployment's trust domain.
    pub trust_domain: String,
    /// The node's certificate.
    pub certificate: CertificateResponse,
    /// The deployment trust bundle, PEM (root, client CA, infrastructure
    /// CA).
    pub trust_bundle: String,
    /// The key that signs policy bundles.
    pub policy_key: Jwk,
}

/// An error, as RFC 9457 problem details. `reason` is a stable code the
/// client maps to its own message; `detail` is already human-readable, so
/// nothing fails without saying why (G12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// The HTTP status.
    pub status: u16,
    /// A stable reason code, for example `device_not_approved`.
    pub reason: String,
    /// A short summary.
    pub title: String,
    /// A human-readable explanation of what happened and what to do.
    pub detail: String,
}
