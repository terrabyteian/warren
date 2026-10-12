//! The console's pages. Each function renders one whole page from the data
//! the control plane gathered; nothing here reads state.

use crate::html;
use crate::html::Html;
use crate::view::*;

/// Where the console lives.
pub const BASE: &str = "/console";

/// Which navigation entry a page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    /// The overview.
    Overview,
    /// Users and groups.
    Users,
    /// Devices.
    Devices,
    /// Apps and connector groups.
    Apps,
    /// Policies.
    Policies,
    /// Access decisions.
    Decisions,
    /// The signed-in user's own apps.
    Mine,
    /// None.
    None,
}

const ADMIN_NAV: &[(Nav, &str, &str, &str)] = &[
    (Nav::Overview, "/console/", "Overview", ICON_OVERVIEW),
    (Nav::Users, "/console/users", "Users & groups", ICON_USERS),
    (Nav::Devices, "/console/devices", "Devices", ICON_DEVICE),
    (Nav::Apps, "/console/apps", "Apps", ICON_APPS),
    (Nav::Policies, "/console/policies", "Policies", ICON_POLICY),
    (
        Nav::Decisions,
        "/console/decisions",
        "Decisions",
        ICON_DECISION,
    ),
];

const ICON_OVERVIEW: &str = "<svg viewBox=\"0 0 20 20\" aria-hidden=\"true\"><path d=\"M3 3h6v6H3zM11 3h6v4h-6zM11 9h6v8h-6zM3 11h6v6H3z\"/></svg>";
const ICON_USERS: &str = "<svg viewBox=\"0 0 20 20\" aria-hidden=\"true\"><circle cx=\"7.5\" cy=\"7\" r=\"3\"/><path d=\"M2 17c0-3 2.5-5 5.5-5s5.5 2 5.5 5\"/><circle cx=\"14.5\" cy=\"6\" r=\"2.2\"/><path d=\"M14 11c2.4 0 4 1.6 4 4\"/></svg>";
const ICON_DEVICE: &str = "<svg viewBox=\"0 0 20 20\" aria-hidden=\"true\"><rect x=\"3\" y=\"4\" width=\"14\" height=\"9\" rx=\"1.5\"/><path d=\"M1.5 16h17\"/></svg>";
const ICON_APPS: &str = "<svg viewBox=\"0 0 20 20\" aria-hidden=\"true\"><rect x=\"3\" y=\"3\" width=\"6\" height=\"6\" rx=\"1.5\"/><rect x=\"11\" y=\"3\" width=\"6\" height=\"6\" rx=\"1.5\"/><rect x=\"3\" y=\"11\" width=\"6\" height=\"6\" rx=\"1.5\"/><rect x=\"11\" y=\"11\" width=\"6\" height=\"6\" rx=\"1.5\"/></svg>";
const ICON_POLICY: &str = "<svg viewBox=\"0 0 20 20\" aria-hidden=\"true\"><path d=\"M10 2l6 2.5v5c0 4-2.7 6.7-6 8.5-3.3-1.8-6-4.5-6-8.5v-5z\"/><path d=\"M7 10l2 2 4-4\"/></svg>";
const ICON_DECISION: &str = "<svg viewBox=\"0 0 20 20\" aria-hidden=\"true\"><path d=\"M4 4h12M4 8h12M4 12h8M4 16h6\"/></svg>";
const ICON_MINE: &str = "<svg viewBox=\"0 0 20 20\" aria-hidden=\"true\"><path d=\"M3 9l7-6 7 6v8H3z\"/><path d=\"M8 17v-5h4v5\"/></svg>";
const LOGO: &str = "<svg class=\"logo\" viewBox=\"0 0 32 32\" aria-hidden=\"true\"><rect width=\"32\" height=\"32\" rx=\"8\"/><path d=\"M6 24v-5a10 10 0 0 1 20 0v5\"/><path d=\"M11 24v-4a5 5 0 0 1 10 0v4\"/></svg>";
const FAVICON: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%232f6f4f'/%3E%3Cpath d='M6 24v-5a10 10 0 0 1 20 0v5M11 24v-4a5 5 0 0 1 10 0v4' fill='none' stroke='white' stroke-width='2.5' stroke-linecap='round'/%3E%3C/svg%3E";

/// The asset version, so browsers fetch new styles and scripts after an
/// upgrade.
fn asset_version() -> String {
    format!("{:016x}", crate::ASSET_VERSION)
}

fn head(title: &str) -> Html {
    html!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"referrer\" content=\"same-origin\"><title>{} · warren</title><link rel=\"icon\" href=\"{}\"><link rel=\"stylesheet\" href=\"/console/assets/console.css?v={}\"><script src=\"/console/assets/console.js?v={}\" defer></script></head>",
        title,
        FAVICON,
        asset_version(),
        asset_version()
    )
}

/// A whole page for a signed-in viewer.
pub fn layout(viewer: &Viewer, nav: Nav, title: &str, flash: Option<&Flash>, body: Html) -> Html {
    let link = |(n, href, label, icon): &(Nav, &str, &str, &str)| {
        let current = if *n == nav {
            html!(" aria-current=\"page\"")
        } else {
            Html::new()
        };
        html!(
            "<a href=\"{}\"{}>{}<span>{}</span></a>",
            *href,
            current,
            Html::__from_template((*icon).to_owned()),
            *label
        )
    };
    let admin_nav = if viewer.admin {
        html!(
            "<p class=\"nav-head\">Administration</p>{}",
            ADMIN_NAV.iter().map(link).collect::<Html>()
        )
    } else {
        Html::new()
    };
    let mine = link(&(Nav::Mine, "/console/me", "My apps", ICON_MINE));
    let role = if viewer.admin {
        html!("<span class=\"badge info\">admin</span>")
    } else {
        Html::new()
    };
    let flash = match flash {
        Some(f) => html!(
            "<div class=\"flash {}\" role=\"status\">{}</div>",
            if f.ok { "ok" } else { "bad" },
            f.text
        ),
        None => Html::new(),
    };
    html!(
        "{}<body><div class=\"shell\"><aside class=\"side\"><a class=\"brand\" href=\"/console/\">{}<span>warren</span></a><nav aria-label=\"Console\">{}<p class=\"nav-head\">You</p>{}</nav></aside><div class=\"main-col\"><header class=\"top\"><h1>{}</h1><div class=\"who\"><span class=\"who-name\" title=\"{}\">{}</span>{}<form method=\"post\" action=\"/console/logout\">{}<button class=\"btn ghost small\" type=\"submit\">Sign out</button></form></div></header><main id=\"main\">{}{}</main></div></div></body></html>",
        head(title),
        Html::__from_template(LOGO.to_owned()),
        admin_nav,
        mine,
        title,
        viewer.user_id,
        viewer.name,
        role,
        csrf_field(viewer),
        flash,
        body
    )
}

fn csrf_field(viewer: &Viewer) -> Html {
    html!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        viewer.csrf
    )
}

/// The sign-in page: a button for the IdP, a username and password form
/// for built-in accounts, or both.
pub fn sign_in(page: &SignIn) -> Html {
    let notice = match &page.message {
        Some(m) => html!(
            "<div class=\"flash bad\" role=\"alert\">{}</div>",
            m.as_str()
        ),
        None => Html::new(),
    };
    let start = start_url(&page.next, page.reauth);
    let body = match (&page.idp, &page.local) {
        (Some(_), None) => html!(
            "<p class=\"muted\">Use your organization's account. You return here once your identity provider has signed you in.</p>{}<a class=\"btn primary wide\" href=\"{}\">Continue to sign in</a>",
            notice,
            start
        ),
        (idp, Some(form)) => {
            let idp = match idp {
                Some(name) => html!(
                    "<a class=\"btn primary wide\" href=\"{}\">Sign in with {}</a><p class=\"or\">or with a warren account</p>",
                    start,
                    name.as_str()
                ),
                None => Html::new(),
            };
            let (focus, kind) = if page.idp.is_none() {
                (html!(" autofocus"), html!(" primary"))
            } else {
                (Html::new(), Html::new())
            };
            html!(
                "{}{}<form method=\"post\" action=\"/console/login\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"next\" value=\"{}\"><label for=\"username\">Username</label><input id=\"username\" name=\"username\" value=\"{}\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" required{}><label for=\"password\">Password</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required><button class=\"btn wide{}\" type=\"submit\">Continue</button></form><p class=\"muted small\">Next, you enter the code from your authenticator app.</p>",
                notice,
                idp,
                form.csrf.as_str(),
                page.next.as_str(),
                form.username.as_str(),
                focus,
                kind
            )
        }
        (None, None) => notice,
    };
    html!(
        "{}<body class=\"center\"><main class=\"signin card\">{}<h1>Sign in to warren</h1>{}</main></body></html>",
        head("Sign in"),
        Html::__from_template(LOGO.to_owned()),
        body
    )
}

/// `next` for a query string, keeping only characters that need no
/// escaping.
fn next_param(next: &str) -> String {
    let mut q = String::new();
    for b in next.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.') {
            q.push(char::from(b));
        } else {
            q.push_str(&format!("%{b:02X}"));
        }
    }
    q
}

/// Where the IdP sign-in button points.
pub fn start_url(next: &str, reauth: bool) -> String {
    let mut q = format!("/console/login/start?next={}", next_param(next));
    if reauth {
        q.push_str("&reauth=1");
    }
    q
}

/// Where **Sign in again** points for `viewer`: the IdP for an IdP sign-in,
/// the sign-in page's form for a built-in account.
pub fn again_url(viewer: &Viewer, next: &str) -> String {
    if viewer.local {
        format!("/console/login?next={}&reauth=1", next_param(next))
    } else {
        start_url(next, true)
    }
}

/// A page that only says something went wrong, or was refused.
pub fn message(viewer: Option<&Viewer>, title: &str, text: &str, action: Option<Html>) -> Html {
    let body = html!(
        "<section class=\"card narrow\"><p>{}</p>{}<p><a href=\"/console/\">Back to the console</a></p></section>",
        text,
        action
    );
    match viewer {
        Some(v) => layout(v, Nav::None, title, None, body),
        None => html!(
            "{}<body class=\"center\"><main class=\"signin card\">{}<h1>{}</h1><p>{}</p><p><a class=\"btn primary\" href=\"/console/login\">Sign in</a></p></main></body></html>",
            head(title),
            Html::__from_template(LOGO.to_owned()),
            title,
            text
        ),
    }
}

// Pieces.

/// Year, month, day, hour and minute of a Unix time, in UTC.
fn civil(secs: i64) -> (i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, rem / 3600, rem % 3600 / 60)
}

/// A Unix time as `2026-10-12 14:03 UTC`.
pub fn absolute(secs: i64) -> String {
    let (y, m, d, h, min) = civil(secs);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02} UTC")
}

fn iso(secs: i64) -> String {
    let (y, m, d, h, min) = civil(secs);
    format!(
        "{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{:02}Z",
        secs.rem_euclid(60)
    )
}

/// How long ago, or how far ahead, `secs` is from `now`, in words.
pub fn relative(now: i64, secs: i64) -> String {
    let delta = now - secs;
    let span = delta.unsigned_abs();
    let amount = match span {
        0..45 => {
            return if delta >= 0 {
                "just now".into()
            } else {
                "in a moment".into()
            };
        }
        45..5_400 => format!("{} min", (span + 30) / 60),
        5_400..129_600 => format!("{} h", (span + 1800) / 3600),
        _ => format!("{} d", (span + 43_200) / 86_400),
    };
    if delta >= 0 {
        format!("{amount} ago")
    } else {
        format!("in {amount}")
    }
}

fn when(now: i64, secs: i64) -> Html {
    if secs <= 0 {
        return html!("<span class=\"muted\">never</span>");
    }
    html!(
        "<time datetime=\"{}\" title=\"{}\" data-rel>{}</time>",
        iso(secs),
        absolute(secs),
        relative(now, secs)
    )
}

fn badge(kind: &str, text: &str) -> Html {
    html!("<span class=\"badge {}\">{}</span>", kind, text)
}

fn status_badge(status: &str) -> Html {
    let kind = match status {
        "approved" => "ok",
        "pending" => "warn",
        "revoked" => "bad",
        _ => "muted",
    };
    badge(kind, status)
}

fn dot(up: bool, label: &str) -> Html {
    html!(
        "<span class=\"health {}\"><span class=\"dot\"></span>{}</span>",
        if up { "up" } else { "down" },
        label
    )
}

fn chips(items: &[String]) -> Html {
    if items.is_empty() {
        return html!("<span class=\"muted\">none</span>");
    }
    items
        .iter()
        .map(|i| html!("<span class=\"chip\">{}</span>", i))
        .collect()
}

fn mono(s: &str) -> Html {
    html!("<code>{}</code>", s)
}

fn empty(text: &str) -> Html {
    html!("<p class=\"empty\">{}</p>", text)
}

fn filter(table: &str, placeholder: &str) -> Html {
    html!(
        "<input class=\"filter\" type=\"search\" data-filter=\"{}\" placeholder=\"{}\" aria-label=\"{}\">",
        table,
        placeholder,
        placeholder
    )
}

/// A button that posts to `action`, or a disabled one explaining why the
/// viewer cannot make changes yet.
fn action(viewer: &Viewer, path: &str, label: &str, kind: &str, confirm: Option<&str>) -> Html {
    let why = match viewer.changes {
        Changes::Allowed => None,
        Changes::NeedMfa => Some("Changes need a multi-factor sign-in"),
        Changes::NeedRecentSignIn | Changes::NotAdmin => Some("Sign in again to make changes"),
    };
    if let Some(why) = why {
        return html!(
            "<button class=\"btn small {}\" type=\"button\" disabled title=\"{}\">{}</button>",
            kind,
            why,
            label
        );
    }
    let confirm = match confirm {
        Some(c) => html!(" data-confirm=\"{}\"", c),
        None => Html::new(),
    };
    html!(
        "<form class=\"inline\" method=\"post\" action=\"{}\"{}>{}<button class=\"btn small {}\" type=\"submit\">{}</button></form>",
        path,
        confirm,
        csrf_field(viewer),
        kind,
        label
    )
}

/// A note above admin pages when the viewer's sign-in cannot make
/// changes.
fn reauth_note(viewer: &Viewer, here: &str) -> Html {
    match viewer.changes {
        Changes::Allowed | Changes::NotAdmin => Html::new(),
        Changes::NeedMfa => html!(
            "<div class=\"flash warn\" role=\"note\">{} <a href=\"{}\">Sign in again</a> with a second factor to approve, revoke, disable or enable.</div>",
            NEED_MFA,
            again_url(viewer, here)
        ),
        Changes::NeedRecentSignIn => html!(
            "<div class=\"flash warn\" role=\"note\">Changes need a recent sign-in. <a href=\"{}\">Sign in again</a> to approve, revoke, disable or enable.</div>",
            again_url(viewer, here)
        ),
    }
}

/// Why a sign-in without multi-factor authentication cannot make changes.
pub const NEED_MFA: &str = "Changes need a multi-factor sign-in, and your identity provider did not report one for this sign-in. For identity providers that never report it, a step-up with a warren authenticator-app code is coming.";

fn stat(label: &str, value: Html, detail: Html, href: Option<&str>) -> Html {
    let inner = html!(
        "<span class=\"stat-label\">{}</span><span class=\"stat-value\">{}</span><span class=\"stat-detail\">{}</span>",
        label,
        value,
        detail
    );
    match href {
        Some(h) => html!("<a class=\"stat card\" href=\"{}\">{}</a>", h, inner),
        None => html!("<div class=\"stat card\">{}</div>", inner),
    }
}

fn short_digest(d: &str) -> String {
    let hex = d.strip_prefix("sha256:").unwrap_or(d);
    hex.chars().take(12).collect()
}

fn node_health(now: i64, n: &NodeRow) -> Html {
    if n.connected {
        let since = n
            .connected_since
            .map(|s| html!(" <span class=\"muted\">since {}</span>", when(now, s)))
            .unwrap_or_default();
        html!("{}{}", dot(true, "connected"), since)
    } else {
        let seen = match n.last_seen {
            Some(s) => html!(" <span class=\"muted\">last seen {}</span>", when(now, s)),
            None => html!(" <span class=\"muted\">not seen since the control plane started</span>"),
        };
        html!("{}{}", dot(false, "disconnected"), seen)
    }
}

fn nodes_table(now: i64, nodes: &[NodeRow]) -> Html {
    if nodes.is_empty() {
        return empty(
            "No relays or connectors have joined yet. Create a join token with `warren admin join-token` and start one.",
        );
    }
    let rows: Html = nodes
        .iter()
        .map(|n| {
            let detail = match (&n.group, n.dns_names.is_empty()) {
                (Some(g), _) => html!("group {}", mono(g)),
                (None, false) => chips(&n.dns_names),
                (None, true) => Html::new(),
            };
            let cert = match n.cert_not_after {
                Some(t) if t > now => html!("valid, expires {}", when(now, t)),
                Some(t) => html!("<span class=\"warn-text\">expired {}</span>", when(now, t)),
                None => html!("<span class=\"muted\">none issued</span>"),
            };
            html!(
                "<tr><td><strong>{}</strong><br><span class=\"id\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                n.name,
                n.id,
                n.role,
                detail,
                node_health(now, n),
                cert,
                when(now, n.joined_at)
            )
        })
        .collect();
    html!(
        "<div class=\"table-wrap\"><table><thead><tr><th>Node</th><th>Role</th><th>Serves</th><th>Health</th><th>Certificate</th><th>Joined</th></tr></thead><tbody>{}</tbody></table></div>",
        rows
    )
}

fn decisions_table(now: i64, rows: &[DecisionRow], id: &str) -> Html {
    let body: Html = rows
        .iter()
        .map(|d| {
            let verdict = if d.allowed {
                badge("ok", "allowed")
            } else {
                badge("bad", "denied")
            };
            let reason = if d.allowed {
                Html::new()
            } else {
                html!("<code>{}</code>", d.reason)
            };
            html!(
                "<tr><td>{}</td><td>{}</td><td>{}<br><span class=\"id\">{}</span></td><td>{}</td><td>{} <span class=\"muted\">{}</span></td><td>{}</td><td>{}</td><td><a href=\"/console/decisions/{}\">Why?</a></td></tr>",
                when(now, d.time_ms / 1000),
                verdict,
                d.user,
                d.device,
                if d.app.is_empty() { "—" } else { d.app.as_str() },
                d.destination,
                d.protocol,
                reason,
                d.connector,
                d.id
            )
        })
        .collect();
    html!(
        "<div class=\"table-wrap\"><table id=\"{}\"><thead><tr><th>When</th><th>Decision</th><th>User and device</th><th>App</th><th>Destination</th><th>Reason</th><th>Connector</th><th></th></tr></thead><tbody>{}</tbody></table></div>",
        id,
        body
    )
}

// Pages.

/// The overview.
pub fn overview(viewer: &Viewer, o: &Overview) -> Html {
    let now = viewer.now;
    let relays: Vec<&NodeRow> = o.nodes.iter().filter(|n| n.role == "relay").collect();
    let connectors: Vec<&NodeRow> = o.nodes.iter().filter(|n| n.role == "connector").collect();
    let up = |v: &[&NodeRow]| v.iter().filter(|n| n.connected).count();
    let fraction = |a: usize, b: usize| html!("{}<small>/{}</small>", a, b);
    let pending = if o.devices.pending > 0 {
        html!(
            "<span class=\"warn-text\">{} waiting for approval</span>",
            o.devices.pending
        )
    } else {
        html!("none waiting for approval")
    };
    let stats = html!(
        "<div class=\"stats\">{}{}{}{}{}{}</div>",
        stat(
            "Users",
            html!("{}", o.users),
            html!("{} disabled", o.users_disabled),
            Some("/console/users")
        ),
        stat(
            "Approved devices",
            html!("{}", o.devices.approved),
            pending,
            Some("/console/devices")
        ),
        stat(
            "Signed-in devices",
            html!("{}", o.devices_certified),
            html!("holding a current certificate"),
            Some("/console/devices")
        ),
        stat(
            "Connected recently",
            html!("{}", o.devices_recent),
            html!("devices that reached an app in 15 min"),
            Some("/console/decisions")
        ),
        stat(
            "Relays",
            fraction(up(&relays), relays.len()),
            html!("connected to the control plane"),
            None
        ),
        stat(
            "Connectors",
            fraction(up(&connectors), connectors.len()),
            html!("connected to the control plane"),
            Some("/console/apps")
        ),
    );
    let policy = if o.policy.loaded {
        let errors = if o.policy.errors.is_empty() {
            Html::new()
        } else {
            html!(
                "<div class=\"flash bad\">The last change did not compile, so the policy below stays in force. <a href=\"/console/policies\">See the errors</a>.</div>"
            )
        };
        html!(
            "{}<dl class=\"facts\"><dt>Version</dt><dd>{} <span class=\"muted\">bundle {}</span></dd><dt>Rules</dt><dd>{}</dd><dt>Apps</dt><dd>{}</dd><dt>Loaded</dt><dd>{}</dd><dt>Warnings</dt><dd>{}</dd></dl>",
            errors,
            mono(&short_digest(&o.policy.digest)),
            o.policy
                .bundle_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".into()),
            o.policy.rules,
            o.policy.apps,
            when(now, o.policy.loaded_at),
            o.policy.warnings.len()
        )
    } else {
        empty("No policy is loaded.")
    };
    let latency = match &o.revocation {
        Some(l) if l.count > 0 => html!(
            "<dl class=\"facts\"><dt>Median</dt><dd>{} ms</dd><dt>99th percentile</dt><dd>{} ms</dd><dt>Over the {} s deadline</dt><dd>{}</dd><dt>Measured</dt><dd>{} acknowledgements</dd></dl>",
            l.p50_ms,
            l.p99_ms,
            l.deadline_ms / 1000,
            if l.over_deadline > 0 {
                html!("<span class=\"bad-text\">{}</span>", l.over_deadline)
            } else {
                html!("0")
            },
            l.count
        ),
        _ => empty("No revocation has been acknowledged by a node yet."),
    };
    let denies = if o.recent_denies.is_empty() {
        empty("No denied decisions since the control plane started.")
    } else {
        decisions_table(now, &o.recent_denies, "recent-denies")
    };
    let body = html!(
        "<div data-refresh=\"15\">{}<section class=\"card\"><h2>Relays and connectors</h2>{}</section><div class=\"grid2\"><section class=\"card\"><h2>Policy</h2>{}<p><a href=\"/console/policies\">View policies</a></p></section><section class=\"card\"><h2>Revocation latency</h2><p class=\"muted\">From a change committing to the last node cutting access.</p>{}</section></div><section class=\"card\"><h2>Recent denies</h2>{}<p><a href=\"/console/decisions?denied=1\">All denied decisions</a></p></section><p class=\"muted small\">{} · {} · refreshes every 15 seconds</p></div>",
        stats,
        nodes_table(now, &o.nodes),
        policy,
        latency,
        denies,
        o.trust_domain,
        o.public_url
    );
    layout(viewer, Nav::Overview, "Overview", None, body)
}

/// Users and groups.
pub fn users(
    viewer: &Viewer,
    users: &[UserRow],
    groups: &[GroupRow],
    flash: Option<&Flash>,
) -> Html {
    let now = viewer.now;
    let rows: Html = users
        .iter()
        .map(|u| {
            let name = if u.email.is_empty() { &u.subject } else { &u.email };
            let status = if u.disabled {
                badge("bad", "disabled")
            } else {
                badge("ok", "active")
            };
            let admin = if u.admin {
                html!(" {}", badge("info", "admin"))
            } else {
                Html::new()
            };
            let act = if u.id == viewer.user_id {
                html!("<span class=\"muted small\">you</span>")
            } else if u.disabled {
                action(
                    viewer,
                    &format!("/console/users/{}/enable", u.id),
                    "Enable",
                    "",
                    None,
                )
            } else {
                action(
                    viewer,
                    &format!("/console/users/{}/disable", u.id),
                    "Disable",
                    "danger",
                    Some(&format!(
                        "Disable {name}? Their sessions and certificates stop working within seconds."
                    )),
                )
            };
            html!(
                "<tr><td><strong>{}</strong>{}<br><span class=\"id\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"actions\">{}</td></tr>",
                name,
                admin,
                u.id,
                chips(&u.groups),
                u.devices,
                when(now, u.last_auth_at),
                status,
                act
            )
        })
        .collect();
    let users_html = if users.is_empty() {
        empty("Nobody has signed in yet. Users appear here after their first sign-in.")
    } else {
        html!(
            "{}<div class=\"table-wrap\"><table id=\"users\"><thead><tr><th>User</th><th>Groups</th><th>Devices</th><th>Last sign-in</th><th>Status</th><th></th></tr></thead><tbody>{}</tbody></table></div>",
            filter("users", "Filter users"),
            rows
        )
    };
    let group_rows: Html = groups
        .iter()
        .map(|g| {
            let rules = if g.rules.is_empty() {
                html!("<span class=\"muted\">no rule names it</span>")
            } else {
                chips(&g.rules)
            };
            html!(
                "<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td></tr>",
                g.name,
                chips(&g.members),
                rules
            )
        })
        .collect();
    let groups_html = if groups.is_empty() {
        empty("No groups yet.")
    } else {
        html!(
            "<div class=\"table-wrap\"><table><thead><tr><th>Group</th><th>Members</th><th>Policy rules</th></tr></thead><tbody>{}</tbody></table></div>",
            group_rows
        )
    };
    let body = html!(
        "{}<section class=\"card\"><h2>Users</h2><p class=\"muted\">Disabling a user cuts their live access within seconds and refuses their sign-ins until they are enabled again.</p>{}</section><section class=\"card\"><h2>Groups</h2><p class=\"muted\">Groups come from the identity provider at each sign-in, and from policy.</p>{}</section>",
        reauth_note(viewer, "/console/users"),
        users_html,
        groups_html
    );
    layout(viewer, Nav::Users, "Users & groups", flash, body)
}

/// Devices, optionally only those with one status.
pub fn devices(
    viewer: &Viewer,
    devices: &[DeviceRow],
    status: Option<&str>,
    flash: Option<&Flash>,
) -> Html {
    let now = viewer.now;
    let count = |s: &str| devices.iter().filter(|d| d.status == s).count();
    let tab = |key: Option<&str>, label: &str, n: usize| {
        let href = match key {
            Some(k) => format!("/console/devices?status={k}"),
            None => "/console/devices".into(),
        };
        let current = if key == status {
            html!(" aria-current=\"page\"")
        } else {
            Html::new()
        };
        html!(
            "<a href=\"{}\"{}>{} <span class=\"count\">{}</span></a>",
            href,
            current,
            label,
            n
        )
    };
    let tabs = html!(
        "<nav class=\"tabs\" aria-label=\"Device status\">{}{}{}{}{}</nav>",
        tab(None, "All", devices.len()),
        tab(Some("pending"), "Pending", count("pending")),
        tab(Some("approved"), "Approved", count("approved")),
        tab(Some("disabled"), "Disabled", count("disabled")),
        tab(Some("revoked"), "Revoked", count("revoked"))
    );
    let shown: Vec<&DeviceRow> = devices
        .iter()
        .filter(|d| status.is_none_or(|s| d.status == s))
        .collect();
    let rows: Html = shown
        .iter()
        .map(|d| {
            let mut acts = Html::new();
            if d.status == "pending" {
                acts.push(action(
                    viewer,
                    &format!("/console/devices/{}/approve", d.id),
                    "Approve",
                    "primary",
                    None,
                ));
            }
            if d.status != "revoked" {
                acts.push(action(
                    viewer,
                    &format!("/console/devices/{}/revoke", d.id),
                    "Revoke",
                    "danger",
                    Some(&format!(
                        "Revoke {}? This cannot be undone: the device must enroll with a new key.",
                        if d.hostname.is_empty() { &d.id } else { &d.hostname }
                    )),
                ));
            }
            let key = if d.key_storage == "secure-enclave" {
                badge("ok", "Secure Enclave")
            } else {
                badge("muted", &d.key_storage)
            };
            let cert = match d.certified_until {
                Some(t) => html!("until {}", when(now, t)),
                None => html!("<span class=\"muted\">none</span>"),
            };
            html!(
                "<tr><td><strong>{}</strong><br><span class=\"id\">{}</span><br><span class=\"muted small\">enrolled {}</span></td><td>{}</td><td>{}<br><span class=\"muted small\">{}</span><br>{} <span class=\"muted small\">class {}</span></td><td>{}</td><td>{}</td><td>{}<div class=\"row-actions\">{}</div></td></tr>",
                if d.hostname.is_empty() { "unnamed device" } else { d.hostname.as_str() },
                d.id,
                when(now, d.created_at),
                chips(&d.users),
                d.os,
                d.model,
                key,
                d.trust_class,
                d.tunnel
                    .split_whitespace()
                    .map(|a| html!("<div><code class=\"small\">{}</code></div>", a))
                    .collect::<Html>(),
                cert,
                status_badge(&d.status),
                acts
            )
        })
        .collect();
    let table = if devices.is_empty() {
        empty(
            "No devices have enrolled yet. A device enrolls the first time someone signs in with the warren app.",
        )
    } else if shown.is_empty() {
        empty("No devices with this status.")
    } else {
        html!(
            "{}<div class=\"table-wrap\"><table id=\"devices\"><thead><tr><th>Device</th><th>Users</th><th>Platform and key</th><th>Tunnel</th><th>Certificate</th><th>Status</th></tr></thead><tbody>{}</tbody></table></div>",
            filter("devices", "Filter devices"),
            rows
        )
    };
    let body = html!(
        "{}<section class=\"card\">{}<p class=\"muted\">Access needs both a valid user and an approved device. Revoking a device cuts its connections within seconds and is permanent.</p>{}</section>",
        reauth_note(viewer, "/console/devices"),
        tabs,
        table
    );
    layout(viewer, Nav::Devices, "Devices", flash, body)
}

fn destinations(list: &[DestinationRow]) -> Html {
    list.iter()
        .map(|d| {
            let ports = if d.ports.is_empty() {
                html!("all ports")
            } else {
                html!("port {}", d.ports)
            };
            html!(
                "<div class=\"dest\"><code>{}</code> <span class=\"muted small\">{} · {}</span></div>",
                d.target,
                d.protocol,
                ports
            )
        })
        .collect()
}

/// Apps and the connector groups that serve them.
pub fn apps(viewer: &Viewer, apps: &[AppRow], groups: &[GroupScope]) -> Html {
    let now = viewer.now;
    let group_cards: Html = groups
        .iter()
        .map(|g| {
            let connectors = if g.connectors.is_empty() {
                empty("No connector in this group has joined.")
            } else {
                g.connectors
                    .iter()
                    .map(|c| {
                        html!(
                            "<div class=\"conn\"><strong>{}</strong> {}</div>",
                            c.name,
                            node_health(now, c)
                        )
                    })
                    .collect()
            };
            let up = g.connectors.iter().filter(|c| c.connected).count();
            let health = dot(up > 0, &format!("{up} of {} connected", g.connectors.len()));
            html!(
                "<section class=\"card\"><div class=\"card-head\"><h2>{}</h2>{}</div><dl class=\"facts\"><dt>Domains</dt><dd>{}</dd><dt>Address ranges</dt><dd>{}</dd><dt>Client names</dt><dd>{}</dd><dt>Defined in</dt><dd>{}</dd></dl><h3>Connectors</h3>{}</section>",
                g.name,
                health,
                chips(&g.domains),
                chips(&g.cidrs),
                chips(&g.client_names),
                mono(&g.source),
                connectors
            )
        })
        .collect();
    let rows: Html = apps
        .iter()
        .map(|a| {
            let mut flags = Vec::new();
            if a.discoverable {
                flags.push("discoverable".to_owned());
            }
            if a.server_initiated {
                flags.push("server-initiated flows".to_owned());
            }
            let rules = if a.rules.is_empty() {
                html!("<span class=\"warn-text\">no rule grants it</span>")
            } else {
                chips(&a.rules)
            };
            html!(
                "<tr><td><strong>{}</strong><br>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                a.name,
                if a.labels.is_empty() { Html::new() } else { chips(&a.labels) },
                mono(&a.connector_group),
                destinations(&a.destinations),
                rules,
                if flags.is_empty() { Html::new() } else { chips(&flags) },
                mono(&a.source)
            )
        })
        .collect();
    let apps_html = if apps.is_empty() {
        empty("No apps are defined in policy.")
    } else {
        html!(
            "{}<div class=\"table-wrap\"><table id=\"apps\"><thead><tr><th>App</th><th>Connector group</th><th>Destinations</th><th>Rules</th><th>Options</th><th>Defined in</th></tr></thead><tbody>{}</tbody></table></div>",
            filter("apps", "Filter apps"),
            rows
        )
    };
    let body = html!(
        "<div class=\"flash info\" role=\"note\">{} Apps and connector groups are managed in Git, in the policy directory; change them there.</div><section class=\"card\"><h2>Apps</h2>{}</section>{}",
        badge("info", "Managed by Git"),
        apps_html,
        group_cards
    );
    layout(viewer, Nav::Apps, "Apps", None, body)
}

/// Policies, as written, with the compiled Cedar.
pub fn policies(viewer: &Viewer, p: &PolicyPage) -> Html {
    let now = viewer.now;
    let errors = if p.summary.errors.is_empty() {
        Html::new()
    } else {
        html!(
            "<section class=\"card error-card\"><h2>The last change did not compile</h2><p>The policy loaded {} stays in force until the errors are fixed. Last attempt {}.</p><ul class=\"errors\">{}</ul></section>",
            when(now, p.summary.loaded_at),
            when(now, p.attempted_at),
            p.summary
                .errors
                .iter()
                .map(|e| html!("<li><code>{}</code></li>", e))
                .collect::<Html>()
        )
    };
    let warnings = if p.summary.warnings.is_empty() {
        Html::new()
    } else {
        html!(
            "<section class=\"card\"><h2>Warnings</h2><ul class=\"errors\">{}</ul></section>",
            p.summary
                .warnings
                .iter()
                .map(|w| html!("<li><code>{}</code></li>", w))
                .collect::<Html>()
        )
    };
    let docs: Html = p
        .policies
        .iter()
        .map(|doc| {
            let rows: Html = doc
                .rules
                .iter()
                .map(|r| {
                    let effect = if r.deny {
                        badge("bad", "deny")
                    } else {
                        badge("ok", "allow")
                    };
                    let conditions = if r.when.is_empty() {
                        html!("<span class=\"muted\">always</span>")
                    } else {
                        r.when
                            .iter()
                            .map(|c| html!("<div>{}</div>", c))
                            .collect()
                    };
                    html!(
                        "<tr id=\"rule-{}\"><td><strong>{}</strong> {}<br><span class=\"id\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        r.id,
                        r.name,
                        effect,
                        r.id,
                        chips(&r.who),
                        chips(&r.what),
                        conditions,
                        mono(&r.source)
                    )
                })
                .collect();
            html!(
                "<section class=\"card\"><div class=\"card-head\"><h2>{}</h2><span class=\"muted small\">{}</span></div><div class=\"table-wrap\"><table><thead><tr><th>Rule</th><th>Who</th><th>What</th><th>When</th><th>Defined in</th></tr></thead><tbody>{}</tbody></table></div></section>",
                doc.name,
                doc.source,
                rows
            )
        })
        .collect();
    let docs = if p.policies.is_empty() {
        html!(
            "<section class=\"card\">{}</section>",
            empty("No access policies are defined, so nobody can reach anything (default deny).")
        )
    } else {
        docs
    };
    let summary = if p.summary.loaded {
        html!(
            "<dl class=\"facts\"><dt>Directory</dt><dd>{}</dd><dt>Version</dt><dd>{} <span class=\"muted\">bundle {}</span></dd><dt>Loaded</dt><dd>{}</dd><dt>Compiled rules</dt><dd>{}</dd></dl>",
            mono(&p.dir),
            mono(&short_digest(&p.summary.digest)),
            p.summary
                .bundle_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".into()),
            when(now, p.summary.loaded_at),
            p.summary.rules
        )
    } else {
        empty("No policy is loaded.")
    };
    let body = html!(
        "<div class=\"flash info\" role=\"note\">{} These policies are read from <code>{}</code>. Change them in Git and reload with <code>warren admin policy reload</code> or SIGHUP; the console never edits them. Deny rules win, and anything no rule allows is denied.</div><section class=\"card\"><h2>Policy in force</h2>{}</section>{}{}{}<section class=\"card\"><details><summary>Compiled Cedar policy set</summary><pre class=\"code\">{}</pre></details></section>",
        badge("info", "Managed by Git"),
        p.dir,
        summary,
        errors,
        warnings,
        docs,
        p.cedar
    );
    layout(viewer, Nav::Policies, "Policies", None, body)
}

/// Recent access decisions.
pub fn decisions(viewer: &Viewer, rows: &[DecisionRow], denied_only: bool, kept: usize) -> Html {
    let toggle = if denied_only {
        html!("<a class=\"btn small\" href=\"/console/decisions\">Show all</a>")
    } else {
        html!("<a class=\"btn small\" href=\"/console/decisions?denied=1\">Denied only</a>")
    };
    let table = if rows.is_empty() {
        empty(if denied_only {
            "No denied decisions since the control plane started."
        } else {
            "No access decisions since the control plane started. Connectors report each decision as it happens."
        })
    } else {
        html!(
            "{}{}",
            filter("decisions", "Filter by user, app, destination or reason"),
            decisions_table(viewer.now, rows, "decisions")
        )
    };
    let body = html!(
        "<section class=\"card\"><div class=\"card-head\"><p class=\"muted\">The newest {} decisions connectors reported since the control plane started, newest first. The audit log keeps every record.</p>{}</div>{}</section>",
        kept,
        toggle,
        table
    );
    layout(viewer, Nav::Decisions, "Decisions", None, body)
}

/// Why one decision came out as it did.
pub fn explanation(viewer: &Viewer, e: &Explanation) -> Html {
    let now = viewer.now;
    let d = &e.decision;
    let verdict = if d.allowed {
        html!("<div class=\"verdict ok\"><span class=\"verdict-word\">Allowed</span></div>")
    } else {
        html!(
            "<div class=\"verdict bad\"><span class=\"verdict-word\">Denied</span><code>{}</code></div>",
            d.reason
        )
    };
    let told = if d.message.is_empty() {
        Html::new()
    } else {
        html!(
            "<blockquote class=\"told\"><span class=\"muted small\">What the user saw</span><br>{}</blockquote>",
            d.message
        )
    };
    let version_note = match (e.policy_version, e.current_version) {
        (Some(a), Some(b)) if a != b => html!(
            " <span class=\"warn-text\">the policy has changed since (now bundle {}); the rules below are as they are now</span>",
            b
        ),
        _ => Html::new(),
    };
    let rules = if e.rules.is_empty() {
        if d.allowed {
            empty("The record names no rule.")
        } else {
            html!(
                "<p>No rule names both this user and this app, so the default applies: <strong>deny</strong>. To grant access, add a rule to an access policy in Git that names one of the user's groups and this app.</p>"
            )
        }
    } else {
        e.rules
            .iter()
            .map(|r| {
                if !r.found {
                    return html!(
                        "<div class=\"rule\"><h3>{}</h3><p class=\"warn-text\">This rule is no longer in the policy in force.</p></div>",
                        r.id
                    );
                }
                let conditions: Html = r
                    .conditions
                    .iter()
                    .map(|c| {
                        let mark = if c.failed {
                            badge("bad", "failed")
                        } else {
                            Html::new()
                        };
                        html!(
                            "<li class=\"{}\"><div><strong>{}</strong> {}</div><div class=\"small\">{}</div><code class=\"small\">{}</code></li>",
                            if c.failed { "cond failed" } else { "cond" },
                            c.kind,
                            mark,
                            c.message,
                            c.expression
                        )
                    })
                    .collect();
                html!(
                    "<div class=\"rule\"><div class=\"card-head\"><h3><a href=\"/console/policies#rule-{}\">{}</a></h3>{}</div><p class=\"muted small\">Defined in {}</p><ol class=\"conds\">{}</ol></div>",
                    r.id,
                    r.id,
                    if r.effect == "forbid" { badge("bad", "deny rule") } else { badge("ok", "allow rule") },
                    mono(&r.source),
                    conditions
                )
            })
            .collect()
    };
    let failed = match &e.failed_condition {
        Some(c) => html!("<dt>Failed condition</dt><dd><code>{}</code></dd>", c),
        None => Html::new(),
    };
    let translated = match &e.translated {
        Some(t) => html!("<dt>Translated to</dt><dd><code>{}</code></dd>", t),
        None => Html::new(),
    };
    let body = html!(
        "<section class=\"card\">{}<p class=\"lead\">{}</p>{}</section><div class=\"grid2\"><section class=\"card\"><h2>Facts</h2><dl class=\"facts\"><dt>When</dt><dd>{}</dd><dt>User</dt><dd>{} <span class=\"id\">{}</span></dd><dt>Device</dt><dd><code>{}</code></dd><dt>App</dt><dd>{}</dd><dt>Destination</dt><dd><code>{}</code> <span class=\"muted\">{}</span></dd>{}<dt>Source</dt><dd><code>{}</code></dd><dt>Connector</dt><dd>{}</dd>{}<dt>Policy</dt><dd>bundle {}{}</dd><dt>Decision ID</dt><dd><code>{}</code></dd></dl></section><section class=\"card\"><h2>Rules that decided it</h2>{}</section></div><section class=\"card\"><details><summary>The audit record</summary><pre class=\"code\">{}</pre></details></section><p><a href=\"/console/decisions\">All decisions</a></p>",
        verdict,
        e.reason_text,
        told,
        when(now, d.time_ms / 1000),
        d.user,
        d.user_id,
        d.device,
        if d.app.is_empty() {
            "none identified"
        } else {
            d.app.as_str()
        },
        d.destination,
        d.protocol,
        translated,
        e.source,
        d.connector,
        failed,
        e.policy_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        version_note,
        d.id,
        rules,
        e.record
    );
    let title = if d.allowed {
        "Why was this allowed?"
    } else {
        "Why was this denied?"
    };
    layout(viewer, Nav::Decisions, title, None, body)
}

/// The signed-in user's own apps and devices.
pub fn portal(viewer: &Viewer, p: &Portal) -> Html {
    let now = viewer.now;
    let apps = if !p.policy_loaded {
        empty("No policy is loaded yet, so there is nothing to reach.")
    } else if p.apps.is_empty() {
        empty("No app is open to you yet. Ask your administrator for access.")
    } else {
        let cards: Html = p
            .apps
            .iter()
            .map(|a| {
                let access = if a.requestable {
                    badge("warn", "request access")
                } else {
                    badge("ok", "allowed")
                };
                html!(
                    "<div class=\"app card\"><div class=\"card-head\"><h3>{}</h3>{}</div>{}</div>",
                    a.name,
                    access,
                    destinations(&a.destinations)
                )
            })
            .collect();
        html!("<div class=\"app-grid\">{}</div>", cards)
    };
    let devices = if p.devices.is_empty() {
        empty(
            "You have no enrolled devices. Install the warren app and sign in to enroll this one.",
        )
    } else {
        let rows: Html = p
            .devices
            .iter()
            .map(|d| {
                html!(
                    "<tr><td><strong>{}</strong><br><span class=\"id\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    if d.hostname.is_empty() { "unnamed device" } else { d.hostname.as_str() },
                    d.id,
                    d.os,
                    when(now, d.created_at),
                    status_badge(&d.status)
                )
            })
            .collect();
        html!(
            "<div class=\"table-wrap\"><table><thead><tr><th>Device</th><th>Platform</th><th>Enrolled</th><th>Status</th></tr></thead><tbody>{}</tbody></table></div>",
            rows
        )
    };
    let body = html!(
        "<section class=\"card\"><h2>Apps you can reach</h2><p class=\"muted\">With the warren app connected, these names and addresses work as if you were on the internal network. Policy may still ask for a recent sign-in or a healthy device.</p>{}</section><section class=\"card\"><h2>Your devices</h2>{}<p class=\"muted small\">To set up another device, install the warren app and enter <code>{}</code>.</p></section>",
        apps,
        devices,
        p.public_url
    );
    layout(viewer, Nav::Mine, "My apps", None, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_render() {
        assert_eq!(absolute(0), "1970-01-01 00:00 UTC");
        assert_eq!(absolute(1_791_813_537), "2026-10-12 13:58 UTC");
        assert_eq!(absolute(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(iso(1_791_813_537), "2026-10-12T13:58:57Z");
        assert_eq!(relative(1000, 990), "just now");
        assert_eq!(relative(10_000, 10_000 - 600), "10 min ago");
        assert_eq!(relative(100_000, 100_000 - 7200), "2 h ago");
        assert_eq!(relative(1_000_000, 1_000_000 - 3 * 86_400), "3 d ago");
        assert_eq!(relative(0, 7200), "in 2 h");
    }

    #[test]
    fn sign_in_links_keep_only_safe_characters() {
        assert_eq!(
            start_url("/console/devices?status=pending", true),
            "/console/login/start?next=/console/devices%3Fstatus%3Dpending&reauth=1"
        );
        let mut viewer = Viewer::default();
        assert_eq!(
            again_url(&viewer, "/console/users"),
            "/console/login/start?next=/console/users&reauth=1"
        );
        viewer.local = true;
        assert_eq!(
            again_url(&viewer, "/console/users"),
            "/console/login?next=/console/users&reauth=1"
        );
    }

    #[test]
    fn the_sign_in_page_offers_what_the_deployment_has() {
        let idp_only = sign_in(&SignIn {
            next: "/console/".into(),
            idp: Some("Google".into()),
            ..SignIn::default()
        });
        assert!(idp_only.as_str().contains("Continue to sign in"));
        assert!(!idp_only.as_str().contains("<form"));
        let local_only = sign_in(&SignIn {
            next: "/console/users".into(),
            local: Some(LocalSignIn {
                csrf: "tok".into(),
                username: "<ada>".into(),
            }),
            message: Some("Wrong".into()),
            ..SignIn::default()
        });
        let page = local_only.as_str();
        assert!(page.contains("action=\"/console/login\""));
        assert!(page.contains("name=\"csrf\" value=\"tok\""));
        assert!(page.contains("name=\"next\" value=\"/console/users\""));
        assert!(page.contains("value=\"&lt;ada&gt;\""));
        assert!(page.contains("role=\"alert\">Wrong<"));
        assert!(!page.contains("/console/login/start"));
        let both = sign_in(&SignIn {
            next: "/console/".into(),
            idp: Some("Google".into()),
            reauth: true,
            local: Some(LocalSignIn::default()),
            ..SignIn::default()
        });
        assert!(both.as_str().contains("Sign in with Google"));
        assert!(
            both.as_str()
                .contains("/console/login/start?next=/console/&amp;reauth=1")
        );
        assert!(both.as_str().contains("<form"));
    }
}
