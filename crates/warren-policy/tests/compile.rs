//! The examples in docs/policy.md compile, validate in strict mode, and make
//! the decisions the document describes.

#![cfg(feature = "compiler")]

use std::collections::BTreeSet;
use std::path::Path;
use std::str::FromStr;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, Request, Schema};
use serde_json::json;
use warren_policy::compile::{self, Access, Compiled, UserEntity};
use warren_policy::model::{self, Objects, Severity};

fn docs_examples() -> Compiled {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples/policy");
    let (objects, diags) = model::load_dir(&dir).unwrap();
    compile::compile(objects, diags, &["warren.example.com".to_owned()]).unwrap_or_else(|d| {
        panic!(
            "{}",
            d.iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        )
    })
}

fn compile_text(text: &str) -> Result<Compiled, Vec<String>> {
    let mut objects = Objects::default();
    let mut diags = Vec::new();
    model::parse_file("test.yaml", text, &mut objects, &mut diags);
    compile::compile(objects, diags, &["warren.example.com".to_owned()])
        .map_err(|d| d.iter().map(|d| d.to_string()).collect())
}

fn user(id: &str, groups: &[&str]) -> UserEntity {
    UserEntity {
        id: id.into(),
        email: format!("{id}@example.com"),
        subject: format!("sub-{id}"),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
    }
}

struct Engine {
    schema: Schema,
    policies: cedar_policy::PolicySet,
    entities: Entities,
}

impl Engine {
    fn new(compiled: &Compiled, users: &[UserEntity]) -> Engine {
        let (schema, _) = Schema::from_cedarschema_str(&compiled.policy.schema).unwrap();
        let policies = compile::policy_set(&compiled.policy).unwrap();
        let entities =
            Entities::from_json_value(compile::entities(users, &compiled.apps), Some(&schema))
                .unwrap();
        Engine {
            schema,
            policies,
            entities,
        }
    }

    fn decide(&self, user: &str, app: &str, context: serde_json::Value) -> (Decision, Vec<String>) {
        self.decide_as(
            &format!("Warren::User::\"{user}\""),
            "connect",
            app,
            context,
        )
    }

    /// Decides any action for any principal (a user or the automatic
    /// approver).
    fn decide_as(
        &self,
        principal: &str,
        action: &str,
        app: &str,
        context: serde_json::Value,
    ) -> (Decision, Vec<String>) {
        let principal = EntityUid::from_str(principal).unwrap();
        let action = EntityUid::from_str(&format!("Warren::Action::\"{action}\"")).unwrap();
        let resource = EntityUid::from_str(&format!("Warren::App::\"{app}\"")).unwrap();
        let context = Context::from_json_value(context, Some((&self.schema, &action))).unwrap();
        let request =
            Request::new(principal, action, resource, context, Some(&self.schema)).unwrap();
        let response = Authorizer::new().is_authorized(&request, &self.policies, &self.entities);
        let reasons = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        (response.decision(), reasons)
    }
}

fn good_device() -> serde_json::Value {
    json!({
        "id": "d-1",
        "signals": {
            "diskEncryption": { "ok": true, "trust": 1 },
            "firewall": { "ok": true, "trust": 1 },
            "osVersion": { "value": 150_401, "trust": 1 },
            "screenLock": { "ok": true, "trust": 1, "maxIdleSeconds": 120 },
            "mdmEnrolled": { "ok": true, "trust": 2 },
            "securityAgent": { "names": ["corp-agent"], "trust": 2 },
        }
    })
}

/// A tunnel request's context. `berlin` is the minute of the week in
/// Europe/Berlin, for policy sets whose schema has that field.
fn context(
    device: Option<serde_json::Value>,
    age: i64,
    mfa: bool,
    berlin: Option<i64>,
) -> serde_json::Value {
    let mut time = json!({ "utcMinuteOfWeek": 0 });
    if let Some(minute) = berlin {
        time["europe_berlin"] = json!(minute);
    }
    let mut c = json!({
        "via": "client",
        "auth": { "ageSeconds": age, "mfa": mfa },
        "time": time,
        "grants": [],
        "network": { "source": { "__extn": { "fn": "ip", "arg": "203.0.113.9" } } },
    });
    if let Some(d) = device {
        c["device"] = d;
    }
    c
}

#[test]
fn the_documented_examples_compile() {
    let compiled = docs_examples();
    assert!(compiled.policy.digest.starts_with("sha256:"));
    let ids: Vec<&str> = compiled
        .policy
        .rules
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "observability/engineers-view-grafana",
            "observability/contractors-office-hours",
            "observability/no-contractors-on-prod",
            "prod-db-break-glass/request",
            "prod-db-break-glass/approve",
            "prod-db-break-glass/connect",
            "prod-db-break-glass/approve-automatic",
        ]
    );
    let text = &compiled.policy.policies;
    for expected in [
        "@id(\"observability/engineers-view-grafana\")",
        "@source(\"observability.yaml:7\")",
        "principal in Warren::Group::\"engineering\"",
        "resource == Warren::App::\"grafana\"",
        "context.device.signals.osVersion.value >= 150400",
        "context.device.signals.screenLock.maxIdleSeconds <= 300",
        "context.device.signals.mdmEnrolled.trust >= 2",
        "context.device.signals.securityAgent.names.contains(\"corp-agent\")",
        "context.auth.ageSeconds <= 43200",
        "forbid (\n  principal in Warren::Group::\"contractors\"",
        "resource in Warren::AppLabel::\"env=prod\"",
        "context.network.source.isInRange(ip(\"203.0.113.0/24\"))",
        "(context.time.europe_berlin >= 1920 && context.time.europe_berlin < 2580)",
        "context.requester != principal",
        "context.grants.contains(resource)",
        "principal == Warren::AutoApprover::\"automatic\"",
        "context.request.time.utcMinuteOfWeek >= 1800",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
    // Both via values listed means no via condition at all.
    assert!(!text.contains("context.via == \"client\" || context.via == \"browser\""));
    assert!(compiled.policy.schema.contains("europe_berlin: Long"));
    // The rule lists posture with browser, which the compiler flags.
    assert!(
        compiled
            .warnings
            .iter()
            .any(|w| w.severity == Severity::Warning && w.message.contains("browser"))
    );
}

#[test]
fn every_condition_is_explained() {
    let compiled = docs_examples();
    let rule = &compiled.policy.rules[0];
    let kinds: Vec<&str> = rule.conditions.iter().map(|c| c.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "posture",
            "posture",
            "posture",
            "posture",
            "posture",
            "posture",
            "auth.maxAge",
            "auth.mfa"
        ]
    );
    assert_eq!(rule.conditions[0].reason, "posture_failed");
    assert_eq!(
        rule.conditions[0].message,
        "FileVault is off. Turn on FileVault in System Settings > Privacy & Security."
    );
    assert_eq!(
        rule.conditions[6].message,
        "Sign in again to reach {app}; policy requires a sign-in within the last 12 h."
    );
    let schedule = &compiled.policy.rules[1]
        .conditions
        .iter()
        .find(|c| c.kind == "schedule")
        .unwrap()
        .message;
    assert_eq!(
        schedule,
        "{app} is available Mon-Fri 08:00-19:00 Europe/Berlin."
    );
}

#[test]
fn decisions_match_the_documentation() {
    let compiled = docs_examples();
    let users = [
        user("ada", &["engineering"]),
        user("cy", &["contractors"]),
        user("sam", &["sre"]),
        user("lee", &["sre-leads"]),
    ];
    let engine = Engine::new(&compiled, &users);
    let monday_9 = Some(1440 + 9 * 60);

    // An engineer on a compliant Mac with a fresh MFA sign-in.
    let (d, why) = engine.decide(
        "ada",
        "grafana",
        context(Some(good_device()), 600, true, monday_9),
    );
    assert_eq!(d, Decision::Allow);
    assert_eq!(why, ["observability/engineers-view-grafana"]);

    // Stale sign-in, no MFA, no posture: each one denies.
    assert_eq!(
        engine
            .decide(
                "ada",
                "grafana",
                context(Some(good_device()), 50_000, true, monday_9)
            )
            .0,
        Decision::Deny
    );
    assert_eq!(
        engine
            .decide(
                "ada",
                "grafana",
                context(Some(good_device()), 600, false, monday_9)
            )
            .0,
        Decision::Deny
    );
    assert_eq!(
        engine
            .decide("ada", "grafana", context(None, 600, true, monday_9))
            .0,
        Decision::Deny
    );
    let mut weak = good_device();
    weak["signals"]["mdmEnrolled"]["trust"] = json!(1);
    assert_eq!(
        engine
            .decide("ada", "grafana", context(Some(weak), 600, true, monday_9))
            .0,
        Decision::Deny
    );

    // Nothing else is allowed by default.
    assert_eq!(
        engine
            .decide(
                "ada",
                "lab-network",
                context(Some(good_device()), 600, true, monday_9)
            )
            .0,
        Decision::Deny
    );

    // Contractors: the office-hours rule would allow grafana, but it is
    // labeled env=prod and the deny rule wins.
    let (d, why) = engine.decide(
        "cy",
        "grafana",
        context(Some(good_device()), 600, true, monday_9),
    );
    assert_eq!(d, Decision::Deny);
    assert_eq!(why, ["observability/no-contractors-on-prod"]);

    // An SRE reaches prod-db only with a grant.
    assert_eq!(
        engine
            .decide(
                "sam",
                "prod-db",
                context(Some(good_device()), 60, true, monday_9)
            )
            .0,
        Decision::Deny
    );
    let mut granted = context(Some(good_device()), 60, true, monday_9);
    granted["grants"] = json!([{ "type": "Warren::App", "id": "prod-db" }]);
    let (d, why) = engine.decide("sam", "prod-db", granted);
    assert_eq!(d, Decision::Allow);
    assert_eq!(why, ["prod-db-break-glass/connect"]);
}

#[test]
fn entitlements_never_name_other_apps() {
    let compiled = docs_examples();
    let ada = compiled.entitlements(&user("ada", &["engineering"]));
    assert_eq!(
        ada.into_iter().collect::<Vec<_>>(),
        [("grafana".to_owned(), Access::Allowed)]
    );
    // Contractors would match grafana but an unconditional deny blocks it.
    assert!(
        compiled
            .entitlements(&user("cy", &["contractors"]))
            .is_empty()
    );
    let sam = compiled.entitlements(&user("sam", &["sre"]));
    assert_eq!(
        sam.into_iter().collect::<Vec<_>>(),
        [("prod-db".to_owned(), Access::Requestable)]
    );
    assert!(compiled.entitlements(&user("eve", &["finance"])).is_empty());
}

const GROUP: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: ConnectorGroup
metadata: { name: lab }
spec:
  destinations:
    domains: ["*.lab.example.com"]
    cidrs: ["10.0.0.0/16"]
  clientNames: ["*.lab.example.com", "*.example.com"]
"#;

fn app(name: &str, host: &str, extra: &str) -> String {
    format!(
        "---\napiVersion: warren.dev/v1alpha1\nkind: App\nmetadata: {{ name: {name} }}\nspec:\n  connectorGroup: lab\n  destinations:\n    - host: \"{host}\"\n      ports: [443]\n      protocol: tcp\n{extra}"
    )
}

fn errors_of(text: &str) -> Vec<String> {
    compile_text(text).err().unwrap_or_default()
}

#[test]
fn scopes_are_enforced_at_compile_time() {
    let errors = errors_of(&format!("{GROUP}{}", app("a", "a.other.com", "")));
    assert!(
        errors.iter().any(|e| e.contains("client names")),
        "{errors:?}"
    );
    let errors = errors_of(&format!("{GROUP}{}", app("a", "a.example.com", "")));
    assert!(
        errors.iter().any(|e| e.contains("destinations")),
        "{errors:?}"
    );
    let target = "      target: 10.9.0.1\n";
    let text = format!(
        "{GROUP}---\napiVersion: warren.dev/v1alpha1\nkind: App\nmetadata: {{ name: a }}\nspec:\n  connectorGroup: lab\n  destinations:\n    - host: a.example.com\n{target}      ports: [443]\n      protocol: tcp\n"
    );
    let errors = errors_of(&text);
    assert!(
        errors.iter().any(|e| e.contains("target 10.9.0.1")),
        "{errors:?}"
    );
    let errors = errors_of(&format!(
        "{GROUP}---\napiVersion: warren.dev/v1alpha1\nkind: App\nmetadata: {{ name: n }}\nspec:\n  connectorGroup: lab\n  destinations:\n    - cidr: 10.0.1.0/24\n      protocol: icmp\n    - cidr: 10.0.0.0/8\n      protocol: icmp\n"
    ));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("10.0.0.0/8"));
    assert!(compile_text(&format!("{GROUP}{}", app("a", "a.lab.example.com", ""))).is_ok());
}

#[test]
fn names_are_claimed_once_and_reserved_names_are_refused() {
    let text = format!(
        "{GROUP}{}{}",
        app("a", "x.lab.example.com", ""),
        app("b", "x.lab.example.com", "")
    );
    let errors = errors_of(&text);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("already claimed by app a"));

    let text = format!(
        "{GROUP}{}{}",
        app("a", "*.lab.example.com", ""),
        app("b", "x.lab.example.com", "")
    );
    assert!(
        compile_text(&text).is_ok(),
        "a more specific name under a wildcard is fine"
    );

    // A wildcard that would cover warren's own name is refused.
    let group = GROUP.replace(
        r#"domains: ["*.lab.example.com"]"#,
        r#"domains: ["*.example.com"]"#,
    );
    let errors = errors_of(&format!("{group}{}", app("a", "*.example.com", "")));
    assert!(errors.iter().any(|e| e.contains("reserved")), "{errors:?}");
}

#[test]
fn references_must_resolve() {
    let text = format!(
        "{GROUP}{}---\napiVersion: warren.dev/v1alpha1\nkind: AccessPolicy\nmetadata: {{ name: p }}\nspec:\n  rules:\n    - name: r\n      who: {{ groups: [g] }}\n      what: {{ apps: [nope] }}\n      when: {{ posture: [missing] }}\n",
        app("a", "a.lab.example.com", "")
    );
    let errors = errors_of(&text);
    assert!(
        errors.iter().any(|e| e.contains("app nope is not defined")),
        "{errors:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("posture profile missing")),
        "{errors:?}"
    );
    assert!(
        errors.iter().all(|e| e.starts_with("test.yaml:")),
        "{errors:?}"
    );
}

#[test]
fn awkward_names_are_escaped() {
    let text = format!(
        "{GROUP}{}---\napiVersion: warren.dev/v1alpha1\nkind: AccessPolicy\nmetadata: {{ name: p }}\nspec:\n  rules:\n    - name: r\n      who:\n        groups: [\"a\\\"b\\\\c\", \"x\\ny\"]\n        users: [\"Ada@Example.com\", \"00u\\\"1\"]\n      what: {{ apps: [a] }}\n",
        app("a", "a.lab.example.com", "")
    );
    let compiled = compile_text(&text).unwrap();
    let weird = UserEntity {
        id: "u-1".into(),
        email: String::new(),
        subject: "none".into(),
        groups: vec!["x\ny".into()],
    };
    let by_email = UserEntity {
        id: "u-2".into(),
        email: "ada@example.com".into(),
        subject: "s".into(),
        groups: vec![],
    };
    let by_subject = UserEntity {
        id: "u-3".into(),
        email: String::new(),
        subject: "00u\"1".into(),
        groups: vec![],
    };
    let engine = Engine::new(
        &compiled,
        &[weird.clone(), by_email.clone(), by_subject.clone()],
    );
    for u in [&weird, &by_email, &by_subject] {
        let (d, _) = engine.decide(&u.id, "a", context(None, 0, false, None));
        assert_eq!(d, Decision::Allow, "{u:?}");
        assert!(compiled.entitlements(u).contains_key("a"));
    }
    let stranger = UserEntity {
        id: "u-4".into(),
        email: "eve@example.com".into(),
        subject: "a\"b\\c-not".into(),
        groups: vec!["a\"b".into()],
    };
    let engine = Engine::new(&compiled, std::slice::from_ref(&stranger));
    assert_eq!(
        engine.decide("u-4", "a", context(None, 0, false, None)).0,
        Decision::Deny
    );
}

#[test]
fn timezone_fields() {
    assert_eq!(compile::timezone_field("UTC"), "utcMinuteOfWeek");
    assert_eq!(compile::timezone_field("Europe/Berlin"), "europe_berlin");
    assert_eq!(
        compile::timezone_field("America/Port-au-Prince"),
        "america_port_au_prince"
    );
    assert_ne!(
        compile::timezone_field("Etc/GMT+5"),
        compile::timezone_field("Etc/GMT-5")
    );
    let schema = compile::schema(&BTreeSet::from(["europe_berlin".to_owned()]));
    assert!(Schema::from_cedarschema_str(&schema).is_ok());
    // The bundle carries which zone each field stands for.
    let compiled = docs_examples();
    assert_eq!(
        compiled
            .policy
            .timezones
            .get("europe_berlin")
            .map(String::as_str),
        Some("Europe/Berlin")
    );
}

fn schedule_policy(rule_zone: &str, other_zone: &str) -> String {
    format!(
        "{GROUP}{}---\napiVersion: warren.dev/v1alpha1\nkind: AccessPolicy\nmetadata: {{ name: p }}\nspec:\n  rules:\n    - name: r1\n      who: {{ groups: [g] }}\n      what: {{ apps: [a] }}\n      when:\n        schedule: {{ timezone: \"{rule_zone}\", windows: [{{ days: [mon], from: \"08:00\", to: \"09:00\" }}] }}\n    - name: r2\n      who: {{ groups: [g] }}\n      what: {{ apps: [a] }}\n      when:\n        schedule: {{ timezone: \"{other_zone}\", windows: [{{ days: [mon], from: \"08:00\", to: \"09:00\" }}] }}\n",
        app("a", "a.lab.example.com", "")
    )
}

#[test]
fn time_zones_that_would_share_a_field_are_refused() {
    assert!(compile_text(&schedule_policy("Etc/GMT+5", "Etc/GMT-5")).is_ok());
    let errors = errors_of(&schedule_policy("Etc/GMT-5", "Etc_GMT-5"));
    assert!(
        errors.iter().any(|e| e.contains("cannot both be used")),
        "{errors:?}"
    );
    let errors = errors_of(&schedule_policy("1Zone/X", "UTC"));
    assert!(
        errors.iter().any(|e| e.contains("cannot be used")),
        "{errors:?}"
    );
}

#[test]
fn schedule_and_network_conditions_decide() {
    // contractors-office-hours, without the deny rule that would hide it.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples/policy");
    let mut objects = Objects::default();
    let mut diags = Vec::new();
    for file in [
        "connector-groups.yaml",
        "apps.yaml",
        "posture.yaml",
        "observability.yaml",
    ] {
        let text = std::fs::read_to_string(dir.join(file)).unwrap();
        model::parse_file(file, &text, &mut objects, &mut diags);
    }
    objects.policies[0]
        .rules
        .retain(|r| r.name == "contractors-office-hours");
    let compiled = compile::compile(objects, diags, &[]).unwrap();
    let engine = Engine::new(&compiled, &[user("cy", &["contractors"])]);
    let monday = |minute: i64| context(Some(good_device()), 60, false, Some(1440 + minute));
    assert_eq!(
        engine.decide("cy", "grafana", monday(9 * 60)).0,
        Decision::Allow
    );
    assert_eq!(
        engine.decide("cy", "grafana", monday(7 * 60 + 59)).0,
        Decision::Deny
    );
    assert_eq!(
        engine.decide("cy", "grafana", monday(19 * 60)).0,
        Decision::Deny
    );
    let saturday = context(Some(good_device()), 60, false, Some(6 * 1440 + 9 * 60));
    assert_eq!(engine.decide("cy", "grafana", saturday).0, Decision::Deny);
    let mut elsewhere = monday(9 * 60);
    elsewhere["network"] = json!({ "source": { "__extn": { "fn": "ip", "arg": "198.51.100.7" } } });
    assert_eq!(engine.decide("cy", "grafana", elsewhere).0, Decision::Deny);
    let mut unknown = monday(9 * 60);
    unknown.as_object_mut().unwrap().remove("network");
    assert_eq!(engine.decide("cy", "grafana", unknown).0, Decision::Deny);
}

#[test]
fn request_and_approval_policies_decide() {
    let compiled = docs_examples();
    let users = [
        user("sam", &["sre"]),
        user("lee", &["sre-leads"]),
        user("cy", &["contractors"]),
    ];
    let engine = Engine::new(&compiled, &users);
    let fresh = context(Some(good_device()), 60, true, Some(0));
    let (d, why) = engine.decide_as("Warren::User::\"sam\"", "request", "prod-db", fresh.clone());
    assert_eq!(
        (d, why),
        (
            Decision::Allow,
            vec!["prod-db-break-glass/request".to_owned()]
        )
    );
    let stale = context(Some(good_device()), 7200, true, Some(0));
    assert_eq!(
        engine
            .decide_as("Warren::User::\"sam\"", "request", "prod-db", stale)
            .0,
        Decision::Deny
    );
    assert_eq!(
        engine
            .decide_as("Warren::User::\"cy\"", "request", "prod-db", fresh.clone())
            .0,
        Decision::Deny
    );

    let approval = |requester: &str, utc_minute: i64| {
        let mut request = fresh.clone();
        request["time"]["utcMinuteOfWeek"] = json!(utc_minute);
        json!({ "requester": { "type": "Warren::User", "id": requester }, "request": request })
    };
    // A lead approves an SRE's request; nobody approves their own.
    let (d, why) = engine.decide_as(
        "Warren::User::\"lee\"",
        "approve",
        "prod-db",
        approval("sam", 0),
    );
    assert_eq!(
        (d, why),
        (
            Decision::Allow,
            vec!["prod-db-break-glass/approve".to_owned()]
        )
    );
    assert_eq!(
        engine
            .decide_as(
                "Warren::User::\"lee\"",
                "approve",
                "prod-db",
                approval("lee", 0)
            )
            .0,
        Decision::Deny
    );
    assert_eq!(
        engine
            .decide_as(
                "Warren::User::\"sam\"",
                "approve",
                "prod-db",
                approval("sam", 0)
            )
            .0,
        Decision::Deny
    );
    // Automatic approval holds on weekdays 06:00-18:00 UTC only.
    let auto = "Warren::AutoApprover::\"automatic\"";
    assert_eq!(
        engine
            .decide_as(auto, "approve", "prod-db", approval("sam", 1440 + 7 * 60))
            .0,
        Decision::Allow
    );
    assert_eq!(
        engine
            .decide_as(auto, "approve", "prod-db", approval("sam", 1440 + 19 * 60))
            .0,
        Decision::Deny
    );
    assert_eq!(
        engine
            .decide_as(auto, "approve", "prod-db", approval("sam", 7 * 60))
            .0,
        Decision::Deny
    );
}

#[test]
fn users_can_be_approvers() {
    let text = format!(
        "{GROUP}{}---\napiVersion: warren.dev/v1alpha1\nkind: AccessRequestPolicy\nmetadata: {{ name: jit }}\nspec:\n  who: {{ groups: [g] }}\n  what: {{ apps: [a] }}\n  approval:\n    approvers: {{ users: [lead@example.com] }}\n  maxDuration: 1h\n",
        app("a", "a.lab.example.com", "")
    );
    let compiled = compile_text(&text).unwrap();
    let lead = UserEntity {
        id: "u-lead".into(),
        email: "lead@example.com".into(),
        subject: "s".into(),
        groups: vec![],
    };
    let engine = Engine::new(&compiled, &[lead, user("sam", &["g"])]);
    let request = context(None, 0, false, None);
    let ctx = json!({ "requester": { "type": "Warren::User", "id": "sam" }, "request": request });
    assert_eq!(
        engine
            .decide_as("Warren::User::\"u-lead\"", "approve", "a", ctx.clone())
            .0,
        Decision::Allow
    );
    assert_eq!(
        engine
            .decide_as("Warren::AutoApprover::\"automatic\"", "approve", "a", ctx)
            .0,
        Decision::Deny
    );
}

#[test]
fn a_clientless_upstream_needs_a_declared_port() {
    let clientless = |upstream: &str| {
        format!(
            "{GROUP}{}",
            app(
                "a",
                "a.lab.example.com",
                &format!(
                    "  clientless:\n    url: https://web.example.com\n    upstream: {upstream}\n"
                ),
            )
        )
    };
    assert!(compile_text(&clientless("https://a.lab.example.com")).is_ok());
    let errors = errors_of(&clientless("http://a.lab.example.com:8080/"));
    assert!(errors.iter().any(|e| e.contains("port 8080")), "{errors:?}");
}
