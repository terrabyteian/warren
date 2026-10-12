//! Compiling the policy surface to Cedar (docs/policy.md section 8).
//!
//! The compiler checks everything the policy documents promise before any
//! policy ships: references, connector-group scopes, name claims and
//! reserved names. It then turns each rule into exactly one Cedar policy,
//! generates the schema those policies need, and validates the set in
//! Cedar's strict mode. Each rule's conditions are also kept as separate
//! Cedar expressions, so an explainer can find the first one that failed.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{Policy, PolicyId, Schema, ValidationMode, Validator};
use warren_core::keys::{hex, sha256};
use warren_core::policy_bundle::{self, Condition, RuleInfo};

use crate::model::{
    AccessRequestPolicy, App, Check, DestinationKind, Diagnostic, Objects, Rule, Severity, Signal,
    Source, Target, Via, When, Who,
};
use crate::names::DomainPattern;

/// The result of a successful compilation.
#[derive(Debug, Clone)]
pub struct Compiled {
    /// The compiled, validated Cedar policy set with its explanation data.
    pub policy: policy_bundle::PolicySet,
    /// Apps as connectors see them.
    pub apps: Vec<policy_bundle::App>,
    /// Connector groups and their scopes.
    pub groups: Vec<policy_bundle::ConnectorGroup>,
    /// The source objects, for computing entitlements.
    pub objects: Objects,
    /// Warnings. A compilation with errors fails instead.
    pub warnings: Vec<Diagnostic>,
}

/// A user as policy sees them, for entities and entitlements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntity {
    /// The warren user ID.
    pub id: String,
    /// The verified email, or empty.
    pub email: String,
    /// The IdP subject identifier.
    pub subject: String,
    /// IdP groups.
    pub groups: Vec<String>,
}

/// Compiles objects read from a policy directory. `reserved` lists warren's
/// own names (the control plane, the relays, the IdP sign-in hosts), which
/// no app may claim. `diagnostics` holds what reading the files reported;
/// any error among them, or found here, fails the compilation.
pub fn compile(
    objects: Objects,
    mut diagnostics: Vec<Diagnostic>,
    reserved: &[String],
) -> Result<Compiled, Vec<Diagnostic>> {
    check(&objects, reserved, &mut diagnostics);
    let mut out = Output::default();
    if !diagnostics.iter().any(|d| d.severity == Severity::Error) {
        generate(&objects, &mut out);
    }
    let schema_text = schema(&out.timezones.keys().cloned().collect());
    if !diagnostics.iter().any(|d| d.severity == Severity::Error) {
        validate(&schema_text, &out, &mut diagnostics);
    }
    if diagnostics.iter().any(|d| d.severity == Severity::Error) {
        diagnostics.sort_by_key(|d| d.severity);
        return Err(diagnostics);
    }
    let policies: String = out.policies.iter().map(|p| p.text.as_str()).collect();
    let digest = format!(
        "sha256:{}",
        hex(&sha256(format!("{schema_text}\n{policies}").as_bytes()))
    );
    Ok(Compiled {
        policy: policy_bundle::PolicySet {
            digest,
            schema: schema_text,
            policies,
            rules: out.policies.into_iter().map(|p| p.info).collect(),
            timezones: out.timezones,
        },
        apps: objects.apps.iter().map(bundle_app).collect(),
        groups: objects
            .groups
            .iter()
            .map(|g| policy_bundle::ConnectorGroup {
                name: g.meta.name.clone(),
                destination_domains: g
                    .destination_domains
                    .iter()
                    .map(|d| d.to_string())
                    .collect(),
                destination_cidrs: g.destination_cidrs.iter().map(|c| c.to_string()).collect(),
                client_names: g.client_names.iter().map(|d| d.to_string()).collect(),
                relays: g.relays.clone(),
            })
            .collect(),
        objects,
        warnings: diagnostics,
    })
}

fn error(diags: &mut Vec<Diagnostic>, source: &Source, line: usize, message: String) {
    diags.push(Diagnostic {
        severity: Severity::Error,
        file: source.file.clone(),
        line,
        message,
    });
}

fn warning(diags: &mut Vec<Diagnostic>, source: &Source, line: usize, message: String) {
    diags.push(Diagnostic {
        severity: Severity::Warning,
        file: source.file.clone(),
        line,
        message,
    });
}

fn duplicates<'a>(
    names: impl Iterator<Item = (&'a str, &'a Source)>,
    kind: &str,
    diags: &mut Vec<Diagnostic>,
) {
    let mut seen: BTreeMap<&str, &Source> = BTreeMap::new();
    for (name, source) in names {
        if let Some(first) = seen.get(name) {
            error(
                diags,
                source,
                source.line,
                format!("{kind} {name} is already defined at {first}"),
            );
        } else {
            seen.insert(name, source);
        }
    }
}

fn check(objects: &Objects, reserved: &[String], diags: &mut Vec<Diagnostic>) {
    duplicates(
        objects
            .groups
            .iter()
            .map(|g| (g.meta.name.as_str(), &g.meta.source)),
        "ConnectorGroup",
        diags,
    );
    duplicates(
        objects
            .apps
            .iter()
            .map(|a| (a.meta.name.as_str(), &a.meta.source)),
        "App",
        diags,
    );
    duplicates(
        objects
            .profiles
            .iter()
            .map(|p| (p.meta.name.as_str(), &p.meta.source)),
        "PostureProfile",
        diags,
    );
    duplicates(
        objects
            .policies
            .iter()
            .map(|p| (p.meta.name.as_str(), &p.meta.source))
            .chain(
                objects
                    .request_policies
                    .iter()
                    .map(|p| (p.meta.name.as_str(), &p.meta.source)),
            ),
        "AccessPolicy or AccessRequestPolicy",
        diags,
    );
    duplicates(
        objects
            .local_users
            .iter()
            .map(|u| (u.meta.name.as_str(), &u.meta.source)),
        "LocalUser",
        diags,
    );
    duplicates(
        objects
            .local_groups
            .iter()
            .map(|g| (g.meta.name.as_str(), &g.meta.source)),
        "LocalGroup",
        diags,
    );

    // Every schedule's time zone gets its own context field.
    let mut fields: BTreeMap<String, (String, Source, usize)> = BTreeMap::new();
    let schedules = objects
        .policies
        .iter()
        .flat_map(|p| p.rules.iter().map(move |r| (&p.meta.source, &r.when)))
        .chain(objects.request_policies.iter().flat_map(|p| {
            std::iter::once((&p.meta.source, &p.when))
                .chain(p.automatic.iter().map(move |a| (&p.meta.source, a)))
        }));
    for (src, when) in schedules {
        let Some(s) = &when.schedule else { continue };
        let field = timezone_field(&s.timezone);
        match fields.get(&field) {
            Some((tz, first, line)) if *tz != s.timezone => error(
                diags,
                src,
                when.line,
                format!(
                    "time zones {:?} and {:?} (at {}:{line}) cannot both be used; their names are too alike",
                    s.timezone, tz, first.file
                ),
            ),
            Some(_) => {}
            None => {
                fields.insert(field, (s.timezone.clone(), src.clone(), when.line));
            }
        }
    }

    let reserved: Vec<String> = reserved.iter().map(|r| r.to_ascii_lowercase()).collect();
    // Every client-facing name claimed so far, with its app.
    let mut claims: Vec<(DomainPattern, &str, &Source, usize)> = Vec::new();
    for app in &objects.apps {
        let src = &app.meta.source;
        let Some(group) = objects
            .groups
            .iter()
            .find(|g| g.meta.name == app.connector_group)
        else {
            error(
                diags,
                src,
                src.line,
                format!(
                    "app {} uses connector group {}, which is not defined",
                    app.meta.name, app.connector_group
                ),
            );
            continue;
        };
        let mut app_claims: Vec<(DomainPattern, usize)> = Vec::new();
        for dest in &app.destinations {
            match &dest.kind {
                DestinationKind::Host { host, target } => {
                    app_claims.push((host.clone(), dest.line));
                    match target {
                        None => {
                            if !group.destination_domains.iter().any(|d| d.covers(host)) {
                                error(
                                    diags,
                                    src,
                                    dest.line,
                                    format!(
                                        "{host} is outside connector group {}'s destinations; \
                                     add it there or set a target inside them",
                                        group.meta.name
                                    ),
                                );
                            }
                        }
                        Some(Target::Name(name)) => {
                            if !group.destination_domains.iter().any(|d| d.matches(name)) {
                                error(
                                    diags,
                                    src,
                                    dest.line,
                                    format!(
                                        "target {name} is outside connector group {}'s destinations",
                                        group.meta.name
                                    ),
                                );
                            }
                        }
                        Some(Target::Addr(addr)) => {
                            if !group.destination_cidrs.iter().any(|c| c.contains(*addr)) {
                                error(
                                    diags,
                                    src,
                                    dest.line,
                                    format!(
                                        "target {addr} is outside connector group {}'s destinations",
                                        group.meta.name
                                    ),
                                );
                            }
                        }
                    }
                }
                DestinationKind::Cidr(cidr) => {
                    if !group.destination_cidrs.iter().any(|c| c.covers(cidr)) {
                        error(
                            diags,
                            src,
                            dest.line,
                            format!(
                                "{cidr} is outside connector group {}'s destinations",
                                group.meta.name
                            ),
                        );
                    }
                }
            }
        }
        if let Some(c) = &app.clientless {
            app_claims.push((c.url_host.clone(), c.line));
            let targets: Vec<String> = app
                .destinations
                .iter()
                .filter_map(|d| match &d.kind {
                    DestinationKind::Host {
                        host: DomainPattern::Exact(h),
                        target: None,
                    } => Some(h.clone()),
                    DestinationKind::Host {
                        target: Some(t), ..
                    } => Some(t.to_string()),
                    _ => None,
                })
                .collect();
            let port_declared = app.destinations.iter().any(|d| {
                let target = match &d.kind {
                    DestinationKind::Host {
                        host: DomainPattern::Exact(h),
                        target: None,
                    } => h.clone(),
                    DestinationKind::Host {
                        target: Some(t), ..
                    } => t.to_string(),
                    _ => return false,
                };
                target == c.upstream_host
                    && matches!(
                        d.protocol,
                        crate::model::Protocol::Tcp | crate::model::Protocol::Any
                    )
                    && (d.ports.is_empty()
                        || d.ports
                            .iter()
                            .any(|r| (r.from..=r.to).contains(&c.upstream_port)))
            });
            if targets.contains(&c.upstream_host) && !port_declared {
                error(
                    diags,
                    src,
                    c.line,
                    format!(
                        "clientless.upstream port {} is not one of the app's TCP ports for {}",
                        c.upstream_port, c.upstream_host
                    ),
                );
            }
            if !targets.contains(&c.upstream_host) {
                error(
                    diags,
                    src,
                    c.line,
                    format!(
                        "clientless.upstream host {} must be one of the app's destination targets",
                        c.upstream_host
                    ),
                );
            }
        }
        for (pattern, line) in &app_claims {
            if !group.client_names.iter().any(|n| n.covers(pattern)) {
                error(
                    diags,
                    src,
                    *line,
                    format!(
                        "{pattern} is outside connector group {}'s client names",
                        group.meta.name
                    ),
                );
            }
            if let Some(r) = reserved.iter().find(|r| pattern.matches(r)) {
                error(
                    diags,
                    src,
                    *line,
                    format!("{pattern} claims {r}, which is reserved for warren itself"),
                );
            }
            for (other, owner, other_src, other_line) in &claims {
                if *owner != app.meta.name && other == pattern {
                    error(
                        diags,
                        src,
                        *line,
                        format!(
                            "{pattern} is already claimed by app {owner} at {}:{other_line}",
                            other_src.file
                        ),
                    );
                }
            }
        }
        for (pattern, line) in app_claims {
            if !claims
                .iter()
                .any(|(p, owner, _, _)| *p == pattern && *owner == app.meta.name)
            {
                claims.push((pattern, &app.meta.name, src, line));
            }
        }
    }

    let app_names: BTreeSet<&str> = objects.apps.iter().map(|a| a.meta.name.as_str()).collect();
    let profile_names: BTreeSet<&str> = objects
        .profiles
        .iter()
        .map(|p| p.meta.name.as_str())
        .collect();
    let check_refs = |what: &crate::model::What,
                      when: &When,
                      deny: bool,
                      src: &Source,
                      diags: &mut Vec<Diagnostic>| {
        for app in &what.apps {
            if !app_names.contains(app.as_str()) {
                error(diags, src, what.line, format!("app {app} is not defined"));
            }
        }
        if !what.match_labels.is_empty()
            && !objects
                .apps
                .iter()
                .any(|a| labels_match(&what.match_labels, &a.meta.labels))
        {
            if deny {
                // A misspelt label would quietly switch the deny off.
                error(diags, src, what.line, "appSelector selects no app".into());
            } else {
                warning(diags, src, what.line, "appSelector selects no app".into());
            }
        }
        for profile in &when.posture {
            if !profile_names.contains(profile.as_str()) {
                error(
                    diags,
                    src,
                    when.line,
                    format!("posture profile {profile} is not defined"),
                );
            }
        }
    };
    for policy in &objects.policies {
        for rule in &policy.rules {
            check_refs(
                &rule.what,
                &rule.when,
                rule.deny,
                &policy.meta.source,
                diags,
            );
            let via = rule_via(rule);
            if !rule.when.posture.is_empty() && via.contains(&Via::Browser) {
                let message = if via.contains(&Via::Client) {
                    "posture conditions never hold for browser sessions, so this rule \
                     admits only client sessions"
                } else {
                    "posture conditions never hold for browser sessions, so this rule \
                     can never match"
                };
                warning(diags, &policy.meta.source, rule.line, message.into());
            }
        }
    }
    for policy in &objects.request_policies {
        check_refs(
            &policy.what,
            &policy.when,
            false,
            &policy.meta.source,
            diags,
        );
        if let Some(auto) = &policy.automatic {
            check_refs(&policy.what, auto, false, &policy.meta.source, diags);
        }
    }
}

/// Warnings for groups that policy names but the IdP has not asserted for
/// any user in `known`, which is how a misspelt group shows up. The IdP
/// owns group names and a correctly named group may have no members yet,
/// so these are warnings rather than errors.
pub fn unknown_groups(objects: &Objects, known: &BTreeSet<String>) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let mut check = |who: &Who, deny: bool, source: &Source, line: usize| {
        for group in who.groups.iter().filter(|g| !known.contains(*g)) {
            let has = match group.strip_prefix(crate::model::LOCAL_PREFIX) {
                Some(name) => format!("no user is in local group {name}"),
                None => format!("no user has group {group} at the IdP"),
            };
            let message = if deny {
                format!("{has} yet, so this deny rule blocks nobody; check its spelling")
            } else {
                format!("{has} yet; check its spelling")
            };
            warning(&mut diags, source, line, message);
        }
    };
    for policy in &objects.policies {
        for rule in &policy.rules {
            check(&rule.who, rule.deny, &policy.meta.source, rule.line);
        }
    }
    for policy in &objects.request_policies {
        let source = &policy.meta.source;
        check(&policy.who, false, source, source.line);
        check(&policy.approvers, false, source, source.line);
    }
    diags
}

fn labels_match(selector: &BTreeMap<String, String>, labels: &BTreeMap<String, String>) -> bool {
    selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

fn rule_via(rule: &Rule) -> Vec<Via> {
    match &rule.when.via {
        Some(v) => v.clone(),
        // Allow rules admit the tunnel unless they say otherwise; deny
        // rules apply to every kind of session unless they say otherwise.
        None if rule.deny => vec![Via::Client, Via::Browser],
        None => vec![Via::Client],
    }
}

fn bundle_app(app: &App) -> policy_bundle::App {
    policy_bundle::App {
        name: app.meta.name.clone(),
        connector_group: app.connector_group.clone(),
        labels: app.meta.labels.clone(),
        destinations: app
            .destinations
            .iter()
            .map(|d| {
                let (host, target, cidr) = match &d.kind {
                    DestinationKind::Host { host, target } => (
                        Some(host.to_string()),
                        target.as_ref().map(|t| t.to_string()),
                        None,
                    ),
                    DestinationKind::Cidr(c) => (None, None, Some(c.to_string())),
                };
                policy_bundle::Destination {
                    host,
                    target,
                    cidr,
                    protocol: d.protocol.as_str().into(),
                    ports: d.ports.clone(),
                }
            })
            .collect(),
        server_initiated_flows: app.server_initiated_flows,
        discoverable: app.discoverable,
    }
}

/// A Cedar string literal.
pub fn cedar_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn uid(kind: &str, id: &str) -> String {
    format!("Warren::{kind}::{}", cedar_str(id))
}

/// The context field holding the minute of the week in `timezone`.
pub fn timezone_field(timezone: &str) -> String {
    if matches!(timezone, "UTC" | "Etc/UTC") {
        return "utcMinuteOfWeek".into();
    }
    let mut field = String::new();
    for c in timezone.chars() {
        match c {
            c if c.is_ascii_alphanumeric() => field.push(c.to_ascii_lowercase()),
            // Keep offsets apart: Etc/GMT+5 and Etc/GMT-5 are ten hours apart.
            '+' => field.push_str("_plus_"),
            _ => field.push('_'),
        }
    }
    field
}

struct CompiledPolicy {
    text: String,
    info: RuleInfo,
    source: Source,
}

#[derive(Default)]
struct Output {
    policies: Vec<CompiledPolicy>,
    /// Context field name to time zone.
    timezones: BTreeMap<String, String>,
}

struct Scope {
    principal: String,
    resource: String,
    conditions: Vec<Condition>,
}

fn condition(
    kind: &str,
    expression: String,
    reason: &str,
    message: impl Into<String>,
) -> Condition {
    Condition {
        kind: kind.into(),
        expression,
        reason: reason.into(),
        message: message.into(),
    }
}

/// `who` as an expression over the user `var`.
fn who_expression(who: &Who, var: &str) -> String {
    let mut terms: Vec<String> = who
        .groups
        .iter()
        .map(|g| format!("{var} in {}", uid("Group", g)))
        .collect();
    terms.extend(who.users.iter().map(|u| {
        if u.contains('@') {
            format!("{var}.email == {}", cedar_str(&u.to_ascii_lowercase()))
        } else {
            format!("{var}.subject == {}", cedar_str(u))
        }
    }));
    paren_or(terms)
}

fn who_scope(who: &Who) -> (String, Option<Condition>) {
    if who.users.is_empty() && who.groups.len() == 1 {
        return (
            format!("principal in {}", uid("Group", &who.groups[0])),
            None,
        );
    }
    (
        "principal is Warren::User".into(),
        Some(condition(
            "who",
            who_expression(who, "principal"),
            "no_rule",
            "No policy allows you to reach {app}.",
        )),
    )
}

fn what_scope(what: &crate::model::What) -> (String, Option<Condition>) {
    if what.match_labels.is_empty() && what.apps.len() == 1 {
        return (format!("resource == {}", uid("App", &what.apps[0])), None);
    }
    if what.apps.is_empty()
        && what.match_labels.len() == 1
        && let Some((k, v)) = what.match_labels.first_key_value()
    {
        return (
            format!("resource in {}", uid("AppLabel", &format!("{k}={v}"))),
            None,
        );
    }
    let mut terms: Vec<String> = what
        .apps
        .iter()
        .map(|a| format!("resource == {}", uid("App", a)))
        .collect();
    if !what.match_labels.is_empty() {
        terms.push(
            what.match_labels
                .iter()
                .map(|(k, v)| format!("resource in {}", uid("AppLabel", &format!("{k}={v}"))))
                .collect::<Vec<_>>()
                .join(" && "),
        );
    }
    (
        "resource".into(),
        Some(condition(
            "what",
            paren_or(terms),
            "no_rule",
            "No policy allows you to reach {app}.",
        )),
    )
}

fn paren_or(terms: Vec<String>) -> String {
    if terms.len() == 1 {
        terms.into_iter().next().unwrap_or_default()
    } else {
        format!("({})", terms.join(" || "))
    }
}

fn scope(who: &Who, what: &crate::model::What) -> Scope {
    let (principal, who_cond) = who_scope(who);
    let (resource, what_cond) = what_scope(what);
    Scope {
        principal,
        resource,
        conditions: who_cond.into_iter().chain(what_cond).collect(),
    }
}

/// A posture check. With `absent_matches` (deny rules) a missing device or
/// signal satisfies the check, so a deny never lapses for want of data.
fn posture_conditions(check: &Check, prefix: &str, absent_matches: bool) -> Condition {
    let signals = format!("{prefix}.device.signals");
    let name = check.signal.name();
    let present = format!("{prefix} has device && {signals} has {name}");
    let mut terms = Vec::new();
    let field = format!("{signals}.{name}");
    let (problem, fix) = match &check.signal {
        Signal::DiskEncryption => {
            terms.push(format!("{field}.ok"));
            (
                "FileVault is off.".to_owned(),
                "Turn on FileVault in System Settings to reach {app}.".to_owned(),
            )
        }
        Signal::Firewall => {
            terms.push(format!("{field}.ok"));
            (
                "The firewall is off.".to_owned(),
                "Turn on the firewall in System Settings to reach {app}.".to_owned(),
            )
        }
        Signal::OsVersion(min) => {
            terms.push(format!("{field}.value >= {min}"));
            let (major, minor, patch) = (min / 10_000, min / 100 % 100, min % 100);
            let version = match (minor, patch) {
                (0, 0) => format!("{major}"),
                (_, 0) => format!("{major}.{minor}"),
                _ => format!("{major}.{minor}.{patch}"),
            };
            (
                format!("macOS {version} or later is required."),
                "Update macOS in System Settings to reach {app}.".to_owned(),
            )
        }
        Signal::ScreenLock(max_idle) => {
            terms.push(format!("{field}.ok"));
            if let Some(secs) = max_idle {
                terms.push(format!("{field}.maxIdleSeconds <= {secs}"));
            }
            (
                "Screen lock is off or allows too long an idle time.".to_owned(),
                "Require a password soon after the screen saver starts to reach {app}.".to_owned(),
            )
        }
        Signal::MdmEnrolled => {
            terms.push(format!("{field}.ok"));
            (
                "This Mac is not enrolled in device management.".to_owned(),
                "Ask your administrator to enroll it to reach {app}.".to_owned(),
            )
        }
        Signal::SecurityAgent(agent) => {
            terms.push(format!("{field}.names.contains({})", cedar_str(agent)));
            (
                format!("The {agent} security agent is not running."),
                "Start it to reach {app}.".to_owned(),
            )
        }
    };
    if check.min_trust > 1 {
        terms.push(format!("{field}.trust >= {}", check.min_trust));
    }
    let fix = check.remediation.clone().unwrap_or(fix);
    let expression = if absent_matches {
        format!("(if {present} then {} else true)", terms.join(" && "))
    } else {
        format!("{present} && {}", terms.join(" && "))
    };
    condition(
        "posture",
        expression,
        "posture_failed",
        format!("{problem} {fix}"),
    )
}

fn format_age(secs: i64) -> String {
    if secs % 3600 == 0 {
        format!("{} h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// The `when` conditions, in the order the explainer reports them. Deny
/// rules pass `absent_matches`, so context the request lacks (a device, a
/// signal, a source address) never lets it escape the deny.
fn when_conditions(
    when: &When,
    via: Option<&[Via]>,
    prefix: &str,
    absent_matches: bool,
    objects: &Objects,
    timezones: &mut BTreeMap<String, String>,
) -> Vec<Condition> {
    let mut out = Vec::new();
    if let Some(via) = via
        && via.len() == 1
    {
        let (value, message) = match via[0] {
            Via::Client => ("client", "{app} is available only through the warren app."),
            Via::Browser => ("browser", "{app} is available only in a browser."),
        };
        out.push(condition(
            "via",
            format!("{prefix}.via == {}", cedar_str(value)),
            "no_rule",
            message,
        ));
    }
    for name in &when.posture {
        if let Some(profile) = objects.profiles.iter().find(|p| &p.meta.name == name) {
            out.extend(
                profile
                    .checks
                    .iter()
                    .map(|c| posture_conditions(c, prefix, absent_matches)),
            );
        }
    }
    if let Some(max_age) = when.auth.max_age {
        out.push(condition(
            "auth.maxAge",
            format!("{prefix}.auth.ageSeconds <= {max_age}"),
            "reauth_required",
            format!(
                "Sign in again to reach {{app}}; policy requires a sign-in within the last {}.",
                format_age(max_age)
            ),
        ));
    }
    if when.auth.mfa {
        out.push(condition(
            "auth.mfa",
            format!("{prefix}.auth.mfa"),
            "mfa_required",
            "Sign in again with multi-factor authentication to reach {app}.",
        ));
    }
    if let Some(schedule) = &when.schedule {
        let field = timezone_field(&schedule.timezone);
        timezones.insert(field.clone(), schedule.timezone.clone());
        let terms: Vec<String> = schedule
            .ranges
            .iter()
            .map(|r| {
                format!(
                    "({prefix}.time.{field} >= {} && {prefix}.time.{field} < {})",
                    r.from, r.to
                )
            })
            .collect();
        out.push(condition(
            "schedule",
            paren_or(terms),
            "outside_schedule",
            format!("{{app}} is available {}.", schedule.text),
        ));
    }
    if !when.network.is_empty() {
        let terms: Vec<String> = when
            .network
            .iter()
            .map(|c| {
                format!(
                    "{prefix}.network.source.isInRange(ip({}))",
                    cedar_str(&c.to_string())
                )
            })
            .collect();
        let ranges = paren_or(terms);
        out.push(condition(
            "network",
            if absent_matches {
                format!("(if {prefix} has network then {ranges} else true)")
            } else {
                format!("{prefix} has network && {ranges}")
            },
            "network_not_allowed",
            "{app} isn't available from this network.",
        ));
    }
    out
}

struct Draft {
    id: String,
    effect: &'static str,
    action: &'static str,
    line: usize,
    principal: String,
    resource: String,
    conditions: Vec<Condition>,
}

fn render(out: &mut Output, source: &Source, d: Draft) {
    let source_text = format!("{}:{}", source.file, d.line);
    let mut text = format!(
        "@id({})\n@source({})\n{} (\n  {},\n  action == Warren::Action::{},\n  {}\n)",
        cedar_str(&d.id),
        cedar_str(&source_text),
        d.effect,
        d.principal,
        cedar_str(d.action),
        d.resource,
    );
    if !d.conditions.is_empty() {
        let body: Vec<&str> = d.conditions.iter().map(|c| c.expression.as_str()).collect();
        text.push_str(&format!("\nwhen {{\n  {}\n}}", body.join(" &&\n  ")));
    }
    text.push_str(";\n\n");
    out.policies.push(CompiledPolicy {
        text,
        info: RuleInfo {
            id: d.id,
            effect: d.effect.into(),
            action: d.action.into(),
            source: source_text,
            conditions: d.conditions,
        },
        source: Source {
            file: source.file.clone(),
            line: d.line,
        },
    });
}

fn generate(objects: &Objects, out: &mut Output) {
    for policy in &objects.policies {
        for rule in &policy.rules {
            let s = scope(&rule.who, &rule.what);
            let via = rule_via(rule);
            let mut conditions = s.conditions;
            let via_filter = if via.len() == 2 {
                None
            } else {
                Some(via.as_slice())
            };
            conditions.extend(when_conditions(
                &rule.when,
                via_filter,
                "context",
                rule.deny,
                objects,
                &mut out.timezones,
            ));
            render(
                out,
                &policy.meta.source,
                Draft {
                    id: format!("{}/{}", policy.meta.name, rule.name),
                    effect: if rule.deny { "forbid" } else { "permit" },
                    action: "connect",
                    line: rule.line,
                    principal: s.principal,
                    resource: s.resource,
                    conditions,
                },
            );
        }
    }
    for policy in &objects.request_policies {
        generate_request_policy(policy, objects, out);
    }
}

fn generate_request_policy(policy: &AccessRequestPolicy, objects: &Objects, out: &mut Output) {
    let name = &policy.meta.name;
    let src = &policy.meta.source;
    let client = [Via::Client];

    // Requesting.
    let s = scope(&policy.who, &policy.what);
    let mut conditions = s.conditions;
    conditions.extend(when_conditions(
        &policy.when,
        Some(&client),
        "context",
        false,
        objects,
        &mut out.timezones,
    ));
    render(
        out,
        src,
        Draft {
            id: format!("{name}/request"),
            effect: "permit",
            action: "request",
            line: src.line,
            principal: s.principal,
            resource: s.resource,
            conditions,
        },
    );

    // Approving: only requests this policy lets the requester make, and
    // never your own.
    let s = scope(&policy.approvers, &policy.what);
    let mut conditions = s.conditions;
    conditions.push(requester_condition(policy));
    conditions.push(condition(
        "not-requester",
        "context.requester != principal".into(),
        "no_rule",
        "You cannot approve your own request.",
    ));
    render(
        out,
        src,
        Draft {
            id: format!("{name}/approve"),
            effect: "permit",
            action: "approve",
            line: src.line,
            principal: s.principal,
            resource: s.resource,
            conditions,
        },
    );

    // Connecting under a grant.
    let s = scope(&policy.who, &policy.what);
    let mut conditions = s.conditions;
    conditions.push(condition(
        "grant",
        format!(
            "context.grants.contains({{ app: resource, policy: {} }})",
            cedar_str(name)
        ),
        "request_access",
        "You don't have access to {app}. Request access.",
    ));
    conditions.extend(when_conditions(
        &policy.when,
        Some(&client),
        "context",
        false,
        objects,
        &mut out.timezones,
    ));
    render(
        out,
        src,
        Draft {
            id: format!("{name}/connect"),
            effect: "permit",
            action: "connect",
            line: src.line,
            principal: s.principal,
            resource: s.resource,
            conditions,
        },
    );

    // Automatic approval, judged on the request's own context.
    if let Some(auto) = &policy.automatic {
        let (resource, what_cond) = what_scope(&policy.what);
        let mut conditions: Vec<Condition> = what_cond.into_iter().collect();
        conditions.push(requester_condition(policy));
        conditions.extend(when_conditions(
            auto,
            None,
            "context.request",
            false,
            objects,
            &mut out.timezones,
        ));
        render(
            out,
            src,
            Draft {
                id: format!("{name}/approve-automatic"),
                effect: "permit",
                action: "approve",
                line: auto.line,
                principal: "principal == Warren::AutoApprover::\"automatic\"".into(),
                resource,
                conditions,
            },
        );
    }
}

/// An approval's requester must be someone the policy lets request.
fn requester_condition(policy: &AccessRequestPolicy) -> Condition {
    condition(
        "requester",
        who_expression(&policy.who, "context.requester"),
        "no_rule",
        "The requester cannot request {app} under this policy.",
    )
}

/// The Cedar schema for a policy set that uses schedules in `timezones`
/// (field names from [`timezone_field`]).
pub fn schema(timezones: &BTreeSet<String>) -> String {
    let mut time_fields = vec!["utcMinuteOfWeek: Long".to_owned()];
    time_fields.extend(
        timezones
            .iter()
            .filter(|t| t.as_str() != "utcMinuteOfWeek")
            .map(|t| format!("{t}: Long")),
    );
    format!(
        r#"namespace Warren {{
  entity Group;
  entity User in [Group] {{ email: String, subject: String }};
  entity AutoApprover;
  entity AppLabel;
  entity App in [AppLabel] {{ connectorGroup: String }};

  type Signal = {{ ok: Bool, trust: Long }};
  type Grant = {{ app: App, policy: String }};
  type Device = {{
    id: String,
    signals: {{
      diskEncryption?: Signal,
      firewall?: Signal,
      osVersion?: {{ value: Long, trust: Long }},
      screenLock?: {{ ok: Bool, trust: Long, maxIdleSeconds: Long }},
      mdmEnrolled?: Signal,
      securityAgent?: {{ names: Set<String>, trust: Long }},
    }},
  }};
  type Context = {{
    via: String,
    device?: Device,
    auth: {{ ageSeconds: Long, mfa: Bool }},
    network?: {{ source: ipaddr }},
    time: {{ {} }},
    grants: Set<Grant>,
  }};

  action connect appliesTo {{ principal: [User], resource: [App], context: Context }};
  action request appliesTo {{ principal: [User], resource: [App], context: Context }};
  action approve appliesTo {{
    principal: [User, AutoApprover],
    resource: [App],
    context: {{ requester: User, request: Context }},
  }};
}}
"#,
        time_fields.join(", ")
    )
}

fn validate(schema_text: &str, out: &Output, diags: &mut Vec<Diagnostic>) {
    let internal = |diags: &mut Vec<Diagnostic>, source: &Source, msg: String| {
        error(
            diags,
            source,
            source.line,
            format!("internal compiler error, please report it: {msg}"),
        );
    };
    let schema = match Schema::from_cedarschema_str(schema_text) {
        Ok((schema, _warnings)) => schema,
        Err(e) => {
            let src = Source {
                file: "<schema>".into(),
                line: 0,
            };
            internal(diags, &src, format!("generated schema is invalid: {e}"));
            return;
        }
    };
    let mut set = cedar_policy::PolicySet::new();
    for p in &out.policies {
        let parsed = Policy::parse(Some(PolicyId::new(&p.info.id)), &p.text)
            .map_err(|e| e.to_string())
            .and_then(|policy| set.add(policy).map_err(|e| e.to_string()));
        if let Err(e) = parsed {
            internal(diags, &p.source, format!("{}: {e}", p.info.id));
        }
    }
    let result = Validator::new(schema).validate(&set, ValidationMode::Strict);
    for e in result.validation_errors() {
        let id = e.policy_id().to_string();
        let source = out
            .policies
            .iter()
            .find(|p| p.info.id == id)
            .map(|p| p.source.clone())
            .unwrap_or(Source {
                file: "<policy>".into(),
                line: 0,
            });
        internal(diags, &source, format!("{id}: {e}"));
    }
}

/// Parses a compiled policy set so that each policy's Cedar ID is its rule
/// path, taken from its `@id` annotation. Cedar itself numbers policies when
/// it parses a set, so enforcement points re-key them this way to report
/// the IDs the explainer and the audit records use.
pub fn policy_set(policy: &policy_bundle::PolicySet) -> Result<cedar_policy::PolicySet, String> {
    let parsed = cedar_policy::PolicySet::from_str(&policy.policies).map_err(|e| e.to_string())?;
    let mut set = cedar_policy::PolicySet::new();
    for p in parsed.policies() {
        let id = p
            .annotation("id")
            .ok_or("compiled policy without an @id")?
            .to_owned();
        set.add(p.new_id(PolicyId::new(id)))
            .map_err(|e| e.to_string())?;
    }
    Ok(set)
}

/// The Cedar entity snapshot for these users and the compiled apps, in
/// Cedar's JSON entity format.
pub fn entities(users: &[UserEntity], apps: &[policy_bundle::App]) -> serde_json::Value {
    use serde_json::json;
    let entity_ref = |kind: &str, id: &str| json!({ "type": format!("Warren::{kind}"), "id": id });
    let mut out = Vec::new();
    let mut groups = BTreeSet::new();
    for user in users {
        groups.extend(user.groups.iter().cloned());
        out.push(json!({
            "uid": entity_ref("User", &user.id),
            "attrs": { "email": user.email, "subject": user.subject },
            "parents": user.groups.iter().map(|g| entity_ref("Group", g)).collect::<Vec<_>>(),
        }));
    }
    for group in groups {
        out.push(json!({ "uid": entity_ref("Group", &group), "attrs": {}, "parents": [] }));
    }
    let mut labels = BTreeSet::new();
    for app in apps {
        let parents: Vec<String> = app.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        labels.extend(parents.iter().cloned());
        out.push(json!({
            "uid": entity_ref("App", &app.name),
            "attrs": { "connectorGroup": app.connector_group },
            "parents": parents.iter().map(|l| entity_ref("AppLabel", l)).collect::<Vec<_>>(),
        }));
    }
    for label in labels {
        out.push(json!({ "uid": entity_ref("AppLabel", &label), "attrs": {}, "parents": [] }));
    }
    out.push(json!({ "uid": entity_ref("AutoApprover", "automatic"), "attrs": {}, "parents": [] }));
    serde_json::Value::Array(out)
}

/// How a user relates to an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Some allow rule names the user and the app; its conditions are
    /// checked per flow at the connector.
    Allowed,
    /// The user may request access to this discoverable app.
    Requestable,
}

fn who_matches(who: &Who, user: &UserEntity) -> bool {
    who.groups.iter().any(|g| user.groups.contains(g))
        || who.users.iter().any(|u| {
            if u.contains('@') {
                !user.email.is_empty() && u.eq_ignore_ascii_case(&user.email)
            } else {
                *u == user.subject
            }
        })
}

/// Whether a rule's `what` names `app`, by name or by its labels: the
/// matching [`Compiled::entitlements`] uses.
pub fn what_matches(what: &crate::model::What, app: &App) -> bool {
    what.apps.contains(&app.meta.name)
        || (!what.match_labels.is_empty() && labels_match(&what.match_labels, &app.meta.labels))
}

impl Compiled {
    /// The shortest `auth.maxAge` any rule or request policy sets, in
    /// seconds: how recently a sign-in must have authenticated the user for
    /// every freshness condition to hold.
    pub fn shortest_max_age(&self) -> Option<i64> {
        let rules = self.objects.policies.iter().flat_map(|p| &p.rules);
        rules
            .map(|r| &r.when)
            .chain(
                self.objects
                    .request_policies
                    .iter()
                    .flat_map(|p| std::iter::once(&p.when).chain(&p.automatic)),
            )
            .filter_map(|w| w.auth.max_age)
            .min()
    }

    /// The apps `user` may reach or request, by name. Apps the user may
    /// neither reach nor request are absent, so entitlement data never
    /// names them (docs/protocol.md section 11.1).
    pub fn entitlements(&self, user: &UserEntity) -> BTreeMap<String, Access> {
        let mut out = BTreeMap::new();
        for app in &self.objects.apps {
            let rules = self.objects.policies.iter().flat_map(|p| &p.rules);
            let mut allowed = false;
            let mut blocked = false;
            for rule in rules {
                if !who_matches(&rule.who, user) || !what_matches(&rule.what, app) {
                    continue;
                }
                if rule.deny {
                    // A deny rule with no conditions blocks the app outright.
                    let w = &rule.when;
                    if w.posture.is_empty()
                        && w.auth == Default::default()
                        && w.schedule.is_none()
                        && w.network.is_empty()
                        && rule_via(rule).contains(&Via::Client)
                    {
                        blocked = true;
                    }
                } else if rule_via(rule).contains(&Via::Client) {
                    allowed = true;
                }
            }
            if blocked {
                continue;
            }
            if allowed {
                out.insert(app.meta.name.clone(), Access::Allowed);
            } else if app.discoverable
                && self
                    .objects
                    .request_policies
                    .iter()
                    .any(|p| who_matches(&p.who, user) && what_matches(&p.what, app))
            {
                out.insert(app.meta.name.clone(), Access::Requestable);
            }
        }
        out
    }
}
