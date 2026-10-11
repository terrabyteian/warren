//! Policy bundles: what the control plane publishes to relays and connectors
//! on link E (docs/protocol.md section 11.2).
//!
//! A bundle is a JSON document signed by the policy-signing key as a JWS
//! (ES256, `typ` [`BUNDLE_TYP`]). Nodes learn the policy-signing key when
//! they join, verify every bundle before use, reject any bundle older than
//! the one they hold, and persist the last verified bundle so they can
//! restart during a control-plane outage (G10).
//!
//! The control plane publishes two views of each version. Connectors get
//! everything they enforce with. Relays get only what admission needs (the
//! nodes and connector groups they serve and the revocation state), never
//! the policy or the user and app catalog, so a relay learns no more about
//! the deployment than its job requires.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::jose::{self, Header, JoseError, Jwk};
use crate::keys::{PublicKey, SigningKey};

/// The JWS `typ` of a policy bundle.
pub const BUNDLE_TYP: &str = "warren-bundle+jws";

/// The bundle format this build reads and writes.
pub const BUNDLE_FORMAT: &str = "warren.bundle.v1";

/// Which nodes a bundle is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum View {
    /// The full bundle, for connectors.
    Connector,
    /// The admission subset, for relays.
    Relay,
}

/// A policy bundle's contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    /// Always [`BUNDLE_FORMAT`].
    pub format: String,
    /// The deployment's trust domain.
    pub trust_domain: String,
    /// The bundle version. Versions only increase across the deployment.
    pub version: u64,
    /// When the control plane signed it, Unix seconds.
    pub issued_at: i64,
    /// Which view this is.
    pub view: View,
    /// The compiled policy. Connector view only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySet>,
    /// The Cedar entity snapshot (users with their groups and email, apps
    /// with their labels), in Cedar's JSON entity format. Connector view
    /// only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entities: Option<serde_json::Value>,
    /// Apps and their destinations. Connector view only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<App>,
    /// Connector groups and their scopes.
    #[serde(default)]
    pub connector_groups: Vec<ConnectorGroup>,
    /// Approved, enabled devices and the users bound to them. Connector view
    /// only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
    /// Enabled relays and connectors.
    #[serde(default)]
    pub nodes: Vec<Node>,
    /// The current revocation state.
    pub revocations: Revocations,
    /// Public keys nodes verify other control-plane statements with.
    #[serde(default)]
    pub keys: BTreeMap<String, Jwk>,
}

/// The compiled Cedar policy set and what the explainer needs to turn a
/// failing condition into a reason (docs/policy.md sections 8 and 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySet {
    /// `sha256:<hex>` over `schema` and `policies`, identifying the policy
    /// version decisions are recorded under.
    pub digest: String,
    /// The generated Cedar schema, in Cedar's human-readable syntax.
    pub schema: String,
    /// The compiled Cedar policies.
    pub policies: String,
    /// One entry per compiled policy, in the order they were compiled.
    pub rules: Vec<RuleInfo>,
    /// The time zones schedules use, by the `context.time` field that holds
    /// the minute of the week in each.
    #[serde(default)]
    pub timezones: BTreeMap<String, String>,
}

/// One compiled Cedar policy and the conditions it checks, kept separately
/// so the explainer can evaluate them one at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInfo {
    /// The Cedar policy ID, `<policy>/<rule>`.
    pub id: String,
    /// `permit` or `forbid`.
    pub effect: String,
    /// The Cedar action: `connect`, `request` or `approve`.
    pub action: String,
    /// Where the rule was written: `file:line` or a CRD reference.
    pub source: String,
    /// The `when` conditions, in the order they are checked.
    pub conditions: Vec<Condition>,
}

/// One condition of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// What kind of condition: `who`, `what`, `via`, `posture`,
    /// `auth.maxAge`, `auth.mfa`, `schedule`, `network`, `grant` or
    /// `not-requester`.
    pub kind: String,
    /// A Cedar expression that is true when the condition holds, evaluable
    /// on its own against the same request.
    pub expression: String,
    /// The reason code a failure maps to (docs/protocol.md section 7).
    pub reason: String,
    /// The message the user sees when this condition is the one that
    /// failed. `{app}` stands for the app's name.
    pub message: String,
}

/// An app as connectors see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct App {
    /// The app's name.
    pub name: String,
    /// The connector group that serves it.
    pub connector_group: String,
    /// Its labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Its destinations.
    pub destinations: Vec<Destination>,
    /// Whether servers may open flows toward clients.
    #[serde(default)]
    pub server_initiated_flows: bool,
    /// Whether users who may request it can see it.
    #[serde(default)]
    pub discoverable: bool,
}

/// One destination of an app: a host name or an address range, with ports
/// and a protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// The client-facing host name, exact or `*.`-wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// What the connector reaches for an exact host, when it differs from
    /// the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// An address or CIDR range, for address apps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// `tcp`, `udp`, `icmp` or `any`.
    pub protocol: String,
    /// Port ranges; empty means every port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
}

/// An inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    /// First port.
    pub from: u16,
    /// Last port, inclusive.
    pub to: u16,
}

/// A connector group's scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorGroup {
    /// The group's name.
    pub name: String,
    /// Domains (exact or `*.`-wildcard) its apps may target.
    #[serde(default)]
    pub destination_domains: Vec<String>,
    /// Address ranges its apps may target.
    #[serde(default)]
    pub destination_cidrs: Vec<String>,
    /// Names clients may use for its apps.
    #[serde(default)]
    pub client_names: Vec<String>,
    /// The relays its connectors attach to; `None` means every relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,
}

/// An approved device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// The device ID.
    pub id: String,
    /// The users the device is bound to.
    pub users: Vec<String>,
    /// Its IPv4 tunnel address.
    pub tunnel_v4: String,
    /// Its IPv6 tunnel address.
    pub tunnel_v6: String,
    /// Its enrollment trust class, 1 to 3.
    pub trust_class: u8,
}

/// An enabled infrastructure node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// The node ID.
    pub id: String,
    /// `relay` or `connector`.
    pub role: String,
    /// The connector group, for connectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The node's name.
    pub name: String,
    /// DNS names a relay is reachable at.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
}

/// Revocation state: everything that must not be admitted even if it
/// presents an otherwise valid certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocations {
    /// Disabled users.
    #[serde(default)]
    pub users: Vec<String>,
    /// Disabled or revoked devices.
    #[serde(default)]
    pub devices: Vec<String>,
    /// Revoked sign-in sessions.
    #[serde(default)]
    pub sessions: Vec<String>,
    /// Revoked certificates, kept until they expire.
    #[serde(default)]
    pub certificates: Vec<RevokedCertificate>,
    /// Revoked relays and connectors.
    #[serde(default)]
    pub nodes: Vec<String>,
}

/// A revoked certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedCertificate {
    /// The serial number, lowercase hex without leading zeros.
    pub serial: String,
    /// When the certificate expires anyway, Unix seconds.
    pub not_after: i64,
}

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The JWS is malformed or its signature does not verify.
    Signature(JoseError),
    /// The payload is not a bundle this build understands.
    Format(String),
    /// The bundle is for another deployment or another kind of node.
    Mismatch(String),
    /// The bundle is older than the one the node holds.
    Stale {
        /// The version received.
        received: u64,
        /// The version held.
        held: u64,
    },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Signature(e) => write!(f, "bundle signature: {e}"),
            BundleError::Format(e) => write!(f, "bundle format: {e}"),
            BundleError::Mismatch(e) => write!(f, "bundle mismatch: {e}"),
            BundleError::Stale { received, held } => {
                write!(f, "bundle version {received} is older than {held}")
            }
        }
    }
}

impl std::error::Error for BundleError {}

impl Bundle {
    /// Signs the bundle with the policy-signing key.
    pub fn sign(&self, key: &SigningKey) -> Result<String, JoseError> {
        let payload = serde_json::to_vec(self).map_err(|e| JoseError(e.to_string()))?;
        let header = Header {
            alg: "ES256".into(),
            typ: BUNDLE_TYP.into(),
            kid: Some(jose::thumbprint(key.public_key())),
            jwk: None,
            crit: None,
        };
        jose::sign(&header, &payload, key)
    }

    /// Verifies a signed bundle and checks that it is for this deployment
    /// and this kind of node, and not older than `held` (the version the
    /// node holds, if any). A bundle with the same version as the one held
    /// is accepted, so a node may re-fetch its current bundle.
    pub fn verify(
        jws: &str,
        policy_key: &PublicKey,
        trust_domain: &str,
        view: View,
        held: Option<u64>,
    ) -> Result<Bundle, BundleError> {
        let payload = jose::Unverified::parse(jws, BUNDLE_TYP)
            .and_then(|u| u.verify(policy_key))
            .map_err(BundleError::Signature)?;
        let bundle: Bundle =
            serde_json::from_slice(&payload).map_err(|e| BundleError::Format(e.to_string()))?;
        if bundle.format != BUNDLE_FORMAT {
            return Err(BundleError::Format(format!(
                "unsupported format {}",
                bundle.format
            )));
        }
        if bundle.trust_domain != trust_domain {
            return Err(BundleError::Mismatch(format!(
                "bundle is for trust domain {}",
                bundle.trust_domain
            )));
        }
        if bundle.view != view {
            return Err(BundleError::Mismatch("bundle is for another role".into()));
        }
        if let Some(held) = held
            && bundle.version < held
        {
            return Err(BundleError::Stale {
                received: bundle.version,
                held,
            });
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(version: u64, view: View) -> Bundle {
        Bundle {
            format: BUNDLE_FORMAT.into(),
            trust_domain: "example.com".into(),
            version,
            issued_at: 1_791_715_800,
            view,
            policy: None,
            entities: None,
            apps: vec![],
            connector_groups: vec![],
            devices: vec![],
            nodes: vec![],
            revocations: Revocations {
                users: vec!["u-1".into()],
                ..Revocations::default()
            },
            keys: BTreeMap::new(),
        }
    }

    #[test]
    fn verify_checks_signature_domain_view_and_version() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let jws = bundle(5, View::Relay).sign(&key).unwrap();
        let pk = key.public_key();
        let got = Bundle::verify(&jws, pk, "example.com", View::Relay, Some(4)).unwrap();
        assert_eq!(got, bundle(5, View::Relay));
        assert!(Bundle::verify(&jws, pk, "example.com", View::Relay, Some(5)).is_ok());
        assert!(matches!(
            Bundle::verify(&jws, pk, "example.com", View::Relay, Some(6)),
            Err(BundleError::Stale { .. })
        ));
        assert!(matches!(
            Bundle::verify(&jws, pk, "example.org", View::Relay, None),
            Err(BundleError::Mismatch(_))
        ));
        assert!(matches!(
            Bundle::verify(&jws, pk, "example.com", View::Connector, None),
            Err(BundleError::Mismatch(_))
        ));
        assert!(matches!(
            Bundle::verify(&jws, other.public_key(), "example.com", View::Relay, None),
            Err(BundleError::Signature(_))
        ));
    }
}
