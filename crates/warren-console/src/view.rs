//! What each page shows, as plain data the control plane fills in. Nothing
//! here reads state; the pages only render it.

/// Who is looking, and what they may do.
#[derive(Debug, Clone, Default)]
pub struct Viewer {
    /// The warren user ID.
    pub user_id: String,
    /// The user's email, or their IdP subject when the IdP gave no email.
    pub name: String,
    /// Whether the admin pages are open to them.
    pub admin: bool,
    /// Whether their sign-in is recent enough for admin changes.
    pub can_change: bool,
    /// The form token every POST must carry.
    pub csrf: String,
    /// Now, Unix seconds: what relative times are measured from.
    pub now: i64,
}

/// A notice shown at the top of a page after an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flash {
    /// Whether it reports success.
    pub ok: bool,
    /// What happened.
    pub text: String,
}

/// The overview page.
#[derive(Debug, Clone, Default)]
pub struct Overview {
    /// The deployment's trust domain.
    pub trust_domain: String,
    /// The organization URL clients sign in to.
    pub public_url: String,
    /// Users known to warren.
    pub users: usize,
    /// Users disabled by an admin.
    pub users_disabled: usize,
    /// Devices by status.
    pub devices: DeviceCounts,
    /// Devices holding a current user+device certificate.
    pub devices_certified: usize,
    /// Devices that reached an app in the last 15 minutes.
    pub devices_recent: usize,
    /// Relays and connectors that have not been revoked.
    pub nodes: Vec<NodeRow>,
    /// The policy in force.
    pub policy: PolicySummary,
    /// The most recent denied decisions.
    pub recent_denies: Vec<DecisionRow>,
    /// Commit-to-cut revocation latency.
    pub revocation: Option<Latency>,
}

/// Devices by status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceCounts {
    /// Approved.
    pub approved: usize,
    /// Waiting for an admin.
    pub pending: usize,
    /// Disabled.
    pub disabled: usize,
    /// Revoked.
    pub revoked: usize,
}

/// Revocation latency from node acknowledgements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Latency {
    /// How many acknowledgements were counted.
    pub count: u64,
    /// Median, milliseconds.
    pub p50_ms: i64,
    /// 99th percentile, milliseconds.
    pub p99_ms: i64,
    /// The deadline, milliseconds.
    pub deadline_ms: i64,
    /// Acknowledgements over the deadline.
    pub over_deadline: u64,
}

/// A relay or connector.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeRow {
    /// Node ID.
    pub id: String,
    /// `relay` or `connector`.
    pub role: String,
    /// Its name.
    pub name: String,
    /// The connector group, for connectors.
    pub group: Option<String>,
    /// DNS names a relay listens on.
    pub dns_names: Vec<String>,
    /// When it joined, Unix seconds.
    pub joined_at: i64,
    /// Whether its revocation event stream is open now.
    pub connected: bool,
    /// When the open stream started, Unix seconds.
    pub connected_since: Option<i64>,
    /// When it was last heard from, Unix seconds.
    pub last_seen: Option<i64>,
    /// When its newest certificate expires, Unix seconds.
    pub cert_not_after: Option<i64>,
}

/// The policy in force, in brief.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySummary {
    /// Whether any policy is in force.
    pub loaded: bool,
    /// Its digest.
    pub digest: String,
    /// Compiled rules.
    pub rules: usize,
    /// Apps.
    pub apps: usize,
    /// When it was loaded, Unix seconds.
    pub loaded_at: i64,
    /// Errors from the last load attempt; the previous policy stays.
    pub errors: Vec<String>,
    /// Warnings.
    pub warnings: Vec<String>,
    /// The newest bundle version.
    pub bundle_version: Option<u64>,
}

/// A user on the users page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserRow {
    /// User ID.
    pub id: String,
    /// Verified email, or empty.
    pub email: String,
    /// IdP subject.
    pub subject: String,
    /// IdP issuer.
    pub issuer: String,
    /// IdP groups.
    pub groups: Vec<String>,
    /// Disabled by an admin.
    pub disabled: bool,
    /// Last sign-in, Unix seconds.
    pub last_auth_at: i64,
    /// Devices bound to the user.
    pub devices: usize,
    /// Whether the user is a console admin.
    pub admin: bool,
}

/// A group on the users page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupRow {
    /// Group name.
    pub name: String,
    /// Members, by display name.
    pub members: Vec<String>,
    /// Policy rules that name it.
    pub rules: Vec<String>,
}

/// A device on the devices page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRow {
    /// Device ID.
    pub id: String,
    /// `pending`, `approved`, `disabled` or `revoked`.
    pub status: String,
    /// Bound users, by display name.
    pub users: Vec<String>,
    /// Host name the device reported.
    pub hostname: String,
    /// Operating system and version.
    pub os: String,
    /// Hardware model.
    pub model: String,
    /// `secure-enclave` or `software`.
    pub key_storage: String,
    /// Enrollment trust class.
    pub trust_class: u8,
    /// Tunnel addresses.
    pub tunnel: String,
    /// When it enrolled, Unix seconds.
    pub created_at: i64,
    /// When its newest current certificate expires, if it holds one.
    pub certified_until: Option<i64>,
}

/// An app on the apps page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppRow {
    /// App name.
    pub name: String,
    /// Labels, as `key=value`.
    pub labels: Vec<String>,
    /// The connector group serving it.
    pub connector_group: String,
    /// Destinations.
    pub destinations: Vec<DestinationRow>,
    /// Whether users who may request it can see it.
    pub discoverable: bool,
    /// Whether servers may open flows toward clients.
    pub server_initiated: bool,
    /// Where it is defined.
    pub source: String,
    /// Rules that grant or deny it.
    pub rules: Vec<String>,
}

/// One destination of an app.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationRow {
    /// Host name or address range.
    pub target: String,
    /// `tcp`, `udp`, `icmp` or `any`.
    pub protocol: String,
    /// Ports, such as `443` or `8000-8100`; empty for every port.
    pub ports: String,
}

/// A connector group on the apps page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupScope {
    /// Group name.
    pub name: String,
    /// Domains its connectors may reach.
    pub domains: Vec<String>,
    /// Address ranges its connectors may reach.
    pub cidrs: Vec<String>,
    /// Names its apps may give clients.
    pub client_names: Vec<String>,
    /// Its connectors.
    pub connectors: Vec<NodeRow>,
    /// Where it is defined.
    pub source: String,
}

/// The policies page.
#[derive(Debug, Clone, Default)]
pub struct PolicyPage {
    /// The policy directory.
    pub dir: String,
    /// The policy in force.
    pub summary: PolicySummary,
    /// When loading was last attempted, Unix seconds.
    pub attempted_at: i64,
    /// Access policies, in file order.
    pub policies: Vec<PolicyDoc>,
    /// The compiled Cedar policy set.
    pub cedar: String,
}

/// One access policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyDoc {
    /// Policy name.
    pub name: String,
    /// Where it is defined.
    pub source: String,
    /// Its rules.
    pub rules: Vec<RuleRow>,
}

/// One rule of an access policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleRow {
    /// `<policy>/<rule>`.
    pub id: String,
    /// The rule's name.
    pub name: String,
    /// A deny rule.
    pub deny: bool,
    /// Who: users and `group:` entries.
    pub who: Vec<String>,
    /// What: apps and `label:` selectors.
    pub what: Vec<String>,
    /// Conditions, in words.
    pub when: Vec<String>,
    /// Where it is defined.
    pub source: String,
}

/// One access decision a connector reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionRow {
    /// The decision ID.
    pub id: String,
    /// When, Unix milliseconds.
    pub time_ms: i64,
    /// Allowed or denied.
    pub allowed: bool,
    /// The user, by display name.
    pub user: String,
    /// The user ID.
    pub user_id: String,
    /// The device ID.
    pub device: String,
    /// The app, if one was identified.
    pub app: String,
    /// What the client addressed: name or address, and port.
    pub destination: String,
    /// IP protocol name.
    pub protocol: String,
    /// The reason code for denies.
    pub reason: String,
    /// The message the user saw.
    pub message: String,
    /// The connector that decided.
    pub connector: String,
}

/// The "why was this decided?" page.
#[derive(Debug, Clone, Default)]
pub struct Explanation {
    /// The decision.
    pub decision: DecisionRow,
    /// The reason code, in words.
    pub reason_text: String,
    /// The condition that failed first, if one did.
    pub failed_condition: Option<String>,
    /// The bundle version it was decided under.
    pub policy_version: Option<u64>,
    /// The bundle version now.
    pub current_version: Option<u64>,
    /// The rules that determined it.
    pub rules: Vec<RuleExplanation>,
    /// Source and translated addresses.
    pub source: String,
    /// The real destination, after name translation.
    pub translated: Option<String>,
    /// The record as received, pretty-printed.
    pub record: String,
}

/// A rule behind a decision, as the policy in force defines it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleExplanation {
    /// `<policy>/<rule>`.
    pub id: String,
    /// Whether the policy in force still has it.
    pub found: bool,
    /// `permit` or `forbid`.
    pub effect: String,
    /// Where it is defined.
    pub source: String,
    /// Its conditions, in the order they are checked.
    pub conditions: Vec<ConditionRow>,
}

/// One condition of a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConditionRow {
    /// The kind, such as `auth.mfa`.
    pub kind: String,
    /// What the user is told when it fails.
    pub message: String,
    /// The Cedar expression.
    pub expression: String,
    /// Whether this is the condition that failed.
    pub failed: bool,
}

/// An app on the end-user page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortalApp {
    /// App name.
    pub name: String,
    /// Whether the user may reach it now or may request it.
    pub requestable: bool,
    /// Destinations, as the client reaches them.
    pub destinations: Vec<DestinationRow>,
}

/// The end-user page.
#[derive(Debug, Clone, Default)]
pub struct Portal {
    /// Apps the user may reach or request.
    pub apps: Vec<PortalApp>,
    /// The user's devices.
    pub devices: Vec<DeviceRow>,
    /// The organization URL to give the warren app.
    pub public_url: String,
    /// Whether policy is loaded.
    pub policy_loaded: bool,
}
