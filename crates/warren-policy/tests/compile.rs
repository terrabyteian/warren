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
        let principal = EntityUid::from_str(&format!("Warren::User::\"{user}\"")).unwrap();
        let action = EntityUid::from_str("Warren::Action::\"connect\"").unwrap();
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
    let schema = compile::schema(&BTreeSet::from(["europe_berlin".to_owned()]));
    assert!(Schema::from_cedarschema_str(&schema).is_ok());
}
