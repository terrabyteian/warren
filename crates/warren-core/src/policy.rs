//! The policy enforcement interface the connector admits flows through
//! (G1, G7). The connector checks the invariants no rule can override, then
//! asks a [`PolicyDecisionPoint`]. This milestone ships a decision point
//! over the static bundle; the control plane's compiled Cedar policy plugs
//! in behind the same trait.

use std::net::SocketAddr;
use std::time::SystemTime;

use crate::bundle::{CompiledApp, CompiledBundle};
use crate::pki::ClientIdentity;

/// Reason codes (docs/protocol.md section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// No rule allows it.
    NoRule,
    /// The app can be requested.
    RequestAccess,
    /// A posture check failed.
    PostureFailed,
    /// The sign-in is too old.
    ReauthRequired,
    /// MFA is required.
    MfaRequired,
    /// Outside the allowed schedule.
    OutsideSchedule,
    /// Not allowed from this network.
    NetworkNotAllowed,
    /// The device is not approved.
    DeviceNotApproved,
    /// The user, device, session or certificate is revoked.
    Revoked,
    /// A just-in-time grant expired.
    GrantExpired,
    /// The destination is outside every app or the group's scope.
    OutOfScope,
    /// A name was bound to an app that does not own it.
    NameNotInApp,
    /// A server tried to open a flow toward a client.
    ServerInitiatedBlocked,
}

impl Reason {
    /// The wire code.
    pub fn code(self) -> &'static str {
        match self {
            Reason::NoRule => "no_rule",
            Reason::RequestAccess => "request_access",
            Reason::PostureFailed => "posture_failed",
            Reason::ReauthRequired => "reauth_required",
            Reason::MfaRequired => "mfa_required",
            Reason::OutsideSchedule => "outside_schedule",
            Reason::NetworkNotAllowed => "network_not_allowed",
            Reason::DeviceNotApproved => "device_not_approved",
            Reason::Revoked => "revoked",
            Reason::GrantExpired => "grant_expired",
            Reason::OutOfScope => "out_of_scope",
            Reason::NameNotInApp => "name_not_in_app",
            Reason::ServerInitiatedBlocked => "server_initiated_blocked",
        }
    }
}

/// How the user reaches the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Through the device tunnel.
    Client,
}

/// One access question: may this client reach this app's destination now?
#[derive(Debug, Clone)]
pub struct FlowRequest<'a> {
    /// The verified user and device.
    pub client: &'a ClientIdentity,
    /// The app the destination belongs to.
    pub app: &'a CompiledApp,
    /// IP protocol.
    pub protocol: u8,
    /// The real destination.
    pub dst: SocketAddr,
    /// Tunnel or browser.
    pub via: Via,
    /// Evaluation time.
    pub now: SystemTime,
}

/// A decision, with what determined it (G12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Allowed or not.
    pub allowed: bool,
    /// The deny reason.
    pub reason: Option<Reason>,
    /// The rules that determined the decision.
    pub rules: Vec<String>,
    /// The first failed condition of the closest candidate rule.
    pub failed_condition: Option<String>,
    /// The message the user sees.
    pub message: String,
    /// What the user can do.
    pub remediation: String,
    /// The policy version it was made under.
    pub policy_version: u64,
}

impl Decision {
    /// A deny with a reason and message.
    pub fn deny(reason: Reason, message: impl Into<String>, version: u64) -> Decision {
        Decision {
            allowed: false,
            reason: Some(reason),
            rules: Vec::new(),
            failed_condition: None,
            message: message.into(),
            remediation: String::new(),
            policy_version: version,
        }
    }
}

/// Decides whether a flow is allowed. Implementations never see flows that
/// fail the invariants; they evaluate rules only.
pub trait PolicyDecisionPoint: Send + Sync + std::fmt::Debug {
    /// Evaluates a request.
    fn decide(&self, req: &FlowRequest<'_>) -> Decision;
}

/// The decision point over the node bundle's rules.
#[derive(Debug, Clone)]
pub struct StaticPolicy {
    state: std::sync::Arc<crate::bundle::NodeState>,
}

impl StaticPolicy {
    /// Evaluates the rules of whatever bundle `state` currently holds.
    pub fn new(state: std::sync::Arc<crate::bundle::NodeState>) -> StaticPolicy {
        StaticPolicy { state }
    }
}

impl PolicyDecisionPoint for StaticPolicy {
    fn decide(&self, req: &FlowRequest<'_>) -> Decision {
        evaluate(&self.state.get(), req)
    }
}

/// Evaluates the static bundle's rules: deny rules win, then the first
/// allow rule whose conditions hold; otherwise a default deny explained by
/// the closest candidate rule.
pub fn evaluate(bundle: &CompiledBundle, req: &FlowRequest<'_>) -> Decision {
    let user = &req.client.user;
    let groups = bundle.user_groups(user);
    let app = req.app;
    let candidates: Vec<_> = bundle
        .rules
        .iter()
        .filter(|r| r.users.contains(user) || groups.iter().any(|g| r.groups.contains(g)))
        .filter(|r| {
            r.apps.contains(&app.name)
                || r.labels
                    .as_ref()
                    .is_some_and(|l| l.iter().all(|(k, v)| app.labels.get(k) == Some(v)))
        })
        .collect();
    if let Some(deny) = candidates.iter().find(|r| r.deny) {
        return Decision {
            allowed: false,
            reason: Some(Reason::NoRule),
            rules: vec![deny.id.clone()],
            failed_condition: None,
            message: format!("Access to {} is blocked by policy.", app.name),
            remediation: String::new(),
            policy_version: bundle.version,
        };
    }
    let age = req
        .now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(req.client.identity.auth_time);
    let mut first_failure: Option<(&str, Reason, String, String)> = None;
    for rule in candidates.iter().filter(|r| !r.deny) {
        if rule.mfa && !req.client.identity.mfa {
            first_failure.get_or_insert((
                &rule.id,
                Reason::MfaRequired,
                "auth.mfa".into(),
                format!(
                    "Sign in again with multi-factor authentication to reach {}.",
                    app.name
                ),
            ));
            continue;
        }
        if let Some(max) = rule.auth_max_age
            && age > max.as_secs()
        {
            first_failure.get_or_insert((
                &rule.id,
                Reason::ReauthRequired,
                "auth.maxAge".into(),
                format!(
                    "Sign in again to reach {} (last sign-in {} ago; policy requires {}).",
                    app.name,
                    human(age),
                    human(max.as_secs())
                ),
            ));
            continue;
        }
        return Decision {
            allowed: true,
            reason: None,
            rules: vec![rule.id.clone()],
            failed_condition: None,
            message: String::new(),
            remediation: String::new(),
            policy_version: bundle.version,
        };
    }
    match first_failure {
        Some((rule, reason, condition, message)) => Decision {
            allowed: false,
            reason: Some(reason),
            rules: vec![rule.to_owned()],
            failed_condition: Some(condition),
            message,
            remediation: "Sign in again from the warren menu.".into(),
            policy_version: bundle.version,
        },
        None if app.discoverable => Decision {
            allowed: false,
            reason: Some(Reason::RequestAccess),
            rules: Vec::new(),
            failed_condition: None,
            message: format!("You don't have access to {}. Request access.", app.name),
            remediation: "Request access from the warren menu.".into(),
            policy_version: bundle.version,
        },
        None => Decision::deny(
            Reason::NoRule,
            format!("No policy allows you to reach {}.", app.name),
            bundle.version,
        ),
    }
}

fn human(secs: u64) -> String {
    match secs {
        s if s >= 3600 => format!("{} h", s / 3600),
        s if s >= 60 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}
