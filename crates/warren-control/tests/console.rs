//! The web console end to end: browser sign-in through the OIDC provider
//! and with built-in accounts (with and without an IdP), every page, and
//! every permission case (signed out, user, admin without MFA, admin with a
//! stale sign-in, an IdP that leaves out `auth_time`, admin), form tokens
//! and origins, admin
//! actions through the same code as the admin API, decisions reported by a
//! connector and their explanation, and escaping of what users, devices and
//! connectors control.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, StatusCode};
use serde_json::{Value, json};
use support::{IdpUser, RunningIdp, StubNode, TempDir, TestClient, free_port, query_of, write};
use warren_control::accounts::{totp_code, totp_step};
use warren_control::config::Config;
use warren_control::console::{LOGIN_COOKIE, ROUTES, SESSION_COOKIE};
use warren_control::web::{Client, Reply};
use warren_control::{ControlPlane, admin_request, audit};
use warren_core::audit::{DecisionRecord, NodeInfo, Subject};
use warren_core::clock;

const GROUP: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: ConnectorGroup
metadata: { name: homelab }
spec:
  destinations:
    domains: ["*.lab.example.com"]
    cidrs: ["10.20.0.0/16"]
  clientNames: ["*.lab.example.com"]
"#;

const APPS: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: App
metadata:
  name: grafana
  labels: { team: observability }
spec:
  connectorGroup: homelab
  destinations:
    - host: grafana.lab.example.com
      ports: [443]
      protocol: tcp
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: billing }
spec:
  connectorGroup: homelab
  destinations:
    - host: billing.lab.example.com
      ports: [443]
      protocol: tcp
"#;

const POLICY: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata: { name: base }
spec:
  rules:
    - name: engineers-grafana
      who: { groups: [engineering] }
      what: { apps: [grafana] }
      when:
        auth: { maxAge: 12h, mfa: true }
    - name: finance-billing
      who: { groups: [finance] }
      what: { apps: [billing] }
"#;

fn admin_user() -> IdpUser {
    IdpUser {
        sub: "00u-root".into(),
        email: "root@example.com".into(),
        groups: vec!["warren-admins".into(), "engineering".into()],
        amr: vec!["pwd".into(), "mfa".into()],
    }
}

fn plain_user() -> IdpUser {
    IdpUser {
        sub: "00u-ada".into(),
        email: "ada@example.com".into(),
        groups: vec!["engineering".into()],
        amr: vec!["pwd".into(), "mfa".into()],
    }
}

struct Deployment {
    _dir: TempDir,
    idp: RunningIdp,
    cp: ControlPlane,
    audit: Arc<Mutex<Vec<u8>>>,
    base: String,
    bundle: String,
}

/// The bootstrap admin's password in deployments with built-in accounts.
const PASSWORD: &str = "correct horse battery staple";

impl Deployment {
    async fn start() -> Deployment {
        Deployment::start_with(true, "").await
    }

    /// A deployment with built-in accounts: the bootstrap admin `admin`, in
    /// `local:admins`, which the console names as admins, with `email` if
    /// given. `extra` goes under `localAccounts`.
    async fn with_accounts(with_idp: bool, email: Option<&str>, extra: &str) -> Deployment {
        let email = email
            .map(|e| format!("    email: {e}\n"))
            .unwrap_or_default();
        Deployment::start_with(
            with_idp,
            &format!(
                "localAccounts:\n  bootstrapAdmin:\n    passwordFile: {{dir}}/admin-password\n{email}{extra}"
            ),
        )
        .await
    }

    /// A deployment, with the IdP configured or not; `extra` is more
    /// configuration, where `{dir}` names the deployment's directory.
    async fn start_with(with_idp: bool, extra: &str) -> Deployment {
        Deployment::start_with_admins(with_idp, "[Grace@Example.com]", extra).await
    }

    /// A deployment like `start_with` whose `console.admins.users` is
    /// `users`.
    async fn start_with_admins(with_idp: bool, users: &str, extra: &str) -> Deployment {
        let dir = TempDir::new("console");
        let idp = RunningIdp::start(admin_user()).await;
        write(&dir.path().join("policy/groups.yaml"), GROUP);
        write(&dir.path().join("policy/apps.yaml"), APPS);
        write(&dir.path().join("policy/base.yaml"), POLICY);
        write(&dir.path().join("idp-ca.pem"), &idp.pki.ca_pem);
        write(&dir.path().join("idp-secret"), "s3cret\n");
        write(&dir.path().join("admin-password"), &format!("{PASSWORD}\n"));
        let port = free_port();
        let idp_config = if with_idp {
            format!(
                "idp:\n  issuer: {issuer}\n  clientId: warren\n  clientSecretFile: {dir}/idp-secret\n  caFile: {dir}/idp-ca.pem\n",
                dir = dir.path().display(),
                issuer = idp.idp.issuer,
            )
        } else {
            String::new()
        };
        let config_text = format!(
            "trustDomain: example.test\n\
             publicUrl: https://localhost:{port}\n\
             listen: 127.0.0.1:{port}\n\
             dataDir: {data}\n\
             policyDir: {dir}/policy\n\
             {idp_config}\
             devices:\n  approval: manual\n\
             console:\n  admins:\n    groups: [warren-admins, \"local:admins\"]\n    users: {users}\n\
             {extra}",
            data = dir.path().join("data").display(),
            dir = dir.path().display(),
            extra = extra.replace("{dir}", &dir.path().display().to_string()),
        );
        let config = Config::parse(&config_text).unwrap();
        let audit = Arc::new(Mutex::new(Vec::new()));
        let cp = ControlPlane::start_with_audit(config, Some(audit::Sink::memory(audit.clone())))
            .await
            .unwrap();
        let bundle = cp.app().authority.trust_bundle();
        Deployment {
            _dir: dir,
            base: format!("https://localhost:{port}"),
            idp,
            cp,
            audit,
            bundle,
        }
    }

    /// The same deployment, restarted with its configuration changed by
    /// `change`.
    async fn restart(self, change: impl FnOnce(&mut Config)) -> Deployment {
        let mut config = Config::clone(&self.cp.app().config);
        change(&mut config);
        let Deployment {
            _dir,
            idp,
            cp,
            audit: log,
            base,
            ..
        } = self;
        cp.shutdown().await;
        let cp = ControlPlane::start_with_audit(config, Some(audit::Sink::memory(log.clone())))
            .await
            .unwrap();
        let bundle = cp.app().authority.trust_bundle();
        Deployment {
            _dir,
            idp,
            cp,
            audit: log,
            base,
            bundle,
        }
    }

    fn browser(&self) -> Browser {
        Browser {
            base: self.base.clone(),
            http: Client::new(Client::roots_from_pem(&self.bundle).unwrap(), None).unwrap(),
            idp_http: Client::new(Client::roots_from_pem(&self.idp.pki.ca_pem).unwrap(), None)
                .unwrap(),
            cookies: HashMap::new(),
        }
    }

    /// A browser signed in as `user`.
    async fn signed_in(&self, user: IdpUser) -> Browser {
        *self.idp.idp.user.lock().unwrap() = user;
        let mut b = self.browser();
        let landed = b.sign_in("/console/").await;
        assert!(landed.starts_with("/console/"), "{landed}");
        b
    }

    fn client(&self) -> TestClient {
        TestClient::new(&self.base, &self.bundle, &self.idp.pki.ca_pem)
    }

    async fn admin(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let socket = self.cp.admin_socket.clone();
        let method = method.to_owned();
        let path = path.to_owned();
        let (status, text) = tokio::task::spawn_blocking(move || {
            admin_request(&socket, &method, &path, body.map(|b| b.to_string())).unwrap()
        })
        .await
        .unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    fn audit_records(&self) -> Vec<Value> {
        let text = String::from_utf8(self.audit.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Enrolls a device for `user` with the warren app's flow; it waits
    /// for approval.
    async fn enroll(&self, user: IdpUser) -> String {
        *self.idp.idp.user.lock().unwrap() = user;
        let mut client = self.client();
        client.sign_in().await;
        let (status, body) = client.enroll().await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["status"], "pending");
        body["id"].as_str().unwrap().to_owned()
    }

    async fn connector(&self, name: &str) -> StubNode {
        let (status, body) = self
            .admin(
                "POST",
                "/v1/admin/join-tokens",
                Some(json!({ "role": "connector", "group": "homelab", "name": name })),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        StubNode::join(&self.base, body["token"].as_str().unwrap())
            .await
            .unwrap()
    }

    async fn user_id(&self, email: &str) -> String {
        let (_, users) = self.admin("GET", "/v1/admin/users", None).await;
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["email"] == email)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn device_status(&self, id: &str) -> String {
        let (_, devices) = self.admin("GET", "/v1/admin/devices", None).await;
        devices
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == id)
            .unwrap()["status"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// A browser: keeps cookies, sends the console's origin on POSTs.
struct Browser {
    base: String,
    http: Client,
    idp_http: Client,
    cookies: HashMap<String, String>,
}

fn text(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn location(r: &Reply) -> String {
    r.headers
        .get("location")
        .unwrap_or_else(|| panic!("no location in {} {}", r.status, text(r)))
        .to_str()
        .unwrap()
        .to_owned()
}

fn set_cookies(r: &Reply) -> Vec<String> {
    r.headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

/// The form token in a page.
fn csrf(page: &str) -> String {
    let at = page
        .find("name=\"csrf\" value=\"")
        .expect("the page has a form token");
    let rest = &page[at + "name=\"csrf\" value=\"".len()..];
    rest[..rest.find('"').unwrap()].to_owned()
}

impl Browser {
    async fn request(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<String>,
    ) -> Reply {
        let url = if url.starts_with("https://") {
            url.to_owned()
        } else {
            format!("{}{url}", self.base)
        };
        let cookie = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut all: Vec<(&str, &str)> = headers.to_vec();
        if !cookie.is_empty() {
            all.push(("cookie", &cookie));
        }
        let reply = self
            .http
            .request(method, &url, &all, body.map(Bytes::from))
            .await
            .unwrap();
        for c in set_cookies(&reply) {
            let (pair, attrs) = c.split_once(';').unwrap_or((&c, ""));
            let (k, v) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.cookies.remove(k);
            } else {
                self.cookies.insert(k.to_owned(), v.to_owned());
            }
        }
        reply
    }

    async fn get(&mut self, path: &str) -> Reply {
        self.request(Method::GET, path, &[], None).await
    }

    async fn post_with(&mut self, path: &str, form: &[(&str, &str)], origin: &str) -> Reply {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in form {
            ser.append_pair(k, v);
        }
        let origin = origin.to_owned();
        self.request(
            Method::POST,
            path,
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("origin", &origin),
                ("sec-fetch-site", "same-origin"),
            ],
            Some(ser.finish()),
        )
        .await
    }

    /// Posts a form from `page`, with that page's form token.
    async fn post_from(&mut self, page: &str, path: &str) -> Reply {
        let token = csrf(&text(&self.get(page).await));
        let base = self.base.clone();
        self.post_with(path, &[("csrf", &token)], &base).await
    }

    /// Starts sign-in and takes it through the IdP, returning where the
    /// control plane sent the browser at the end.
    async fn sign_in_with(&mut self, start: &str) -> String {
        let to_idp = location(&self.get(start).await);
        let idp_reply = self
            .idp_http
            .request(Method::GET, &to_idp, &[], None)
            .await
            .unwrap();
        let callback = location(&idp_reply);
        let back = self.request(Method::GET, &callback, &[], None).await;
        assert_eq!(back.status, StatusCode::SEE_OTHER, "{}", text(&back));
        location(&back)
    }

    async fn sign_in(&mut self, next: &str) -> String {
        self.sign_in_with(&format!("/console/login/start?next={next}"))
            .await
    }

    /// Posts the built-in account form of the sign-in page at `page`.
    async fn password(&mut self, page: &str, username: &str, password: &str) -> Reply {
        let form = text(&self.get(page).await);
        let token = csrf(&form);
        let next = field(&form, "next");
        let base = self.base.clone();
        self.post_with(
            "/console/login",
            &[
                ("csrf", &token),
                ("next", &next),
                ("username", username),
                ("password", password),
            ],
            &base,
        )
        .await
    }

    /// Signs in to the console with a built-in account from the sign-in
    /// page at `page`: with the authenticator `secret` and the code for
    /// `step`, or enrolling an authenticator when there is none yet.
    /// Returns the secret and where the browser landed.
    async fn local_sign_in(
        &mut self,
        page: &str,
        username: &str,
        secret: Option<(&[u8], i64)>,
    ) -> (Vec<u8>, String) {
        let reply = self.password(page, username, PASSWORD).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", text(&reply));
        let page = text(&reply);
        let flow = field(&page, "flow");
        let base = self.base.clone();
        match secret {
            Some((secret, step)) => {
                assert!(page.contains("Enter your authenticator code"), "{page}");
                let reply = self
                    .post_with(
                        "/v1/auth/code",
                        &[("flow", &flow), ("code", &code_at(secret, step))],
                        &base,
                    )
                    .await;
                (secret.to_vec(), location(&reply))
            }
            None => {
                let secret = enrollment_secret(&page);
                let step = totp_step(clock::now_secs());
                let reply = self
                    .post_with(
                        "/v1/auth/code",
                        &[("flow", &flow), ("code", &code_at(&secret, step))],
                        &base,
                    )
                    .await;
                assert!(text(&reply).contains("Save your recovery codes"));
                let reply = self
                    .post_with("/v1/auth/continue", &[("flow", &flow)], &base)
                    .await;
                (secret, location(&reply))
            }
        }
    }
}

impl Browser {
    /// Posts the step-up form with `code`, returning to `next`.
    async fn step_up(&mut self, next: &str, code: &str) -> Reply {
        let page = text(&self.get(&format!("/console/step-up?next={next}")).await);
        let token = csrf(&page);
        let base = self.base.clone();
        self.post_with(
            "/console/step-up",
            &[("csrf", &token), ("next", next), ("code", code)],
            &base,
        )
        .await
    }
}

/// The value of a hidden form field on a page.
fn field(page: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = page
        .find(&marker)
        .unwrap_or_else(|| panic!("no {name} in {page}"))
        + marker.len();
    page[start..]
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&")
}

/// The authenticator key on the enrollment page, decoded.
fn enrollment_secret(page: &str) -> Vec<u8> {
    let start = page
        .find("<code class=\"key\">")
        .expect("an enrollment page")
        + 18;
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in page[start..]
        .split('<')
        .next()
        .unwrap()
        .bytes()
        .filter(|c| !c.is_ascii_whitespace())
    {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32"),
        };
        buffer = (buffer << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

fn code_at(secret: &[u8], step: i64) -> String {
    format!("{:06}", totp_code(secret, step))
}

/// The audit record with `message`.
fn audited(d: &Deployment, message: &str) -> Value {
    d.audit_records()
        .into_iter()
        .rfind(|r| r["message"] == message)
        .unwrap_or_else(|| panic!("no audit record {message:?}"))
}

const ADMIN_PAGES: &[&str] = &[
    "/console/",
    "/console/users",
    "/console/devices",
    "/console/devices?status=pending",
    "/console/apps",
    "/console/policies",
    "/console/decisions",
    "/console/decisions?denied=1",
];

#[tokio::test]
async fn signed_out_browsers_are_sent_to_sign_in() {
    let d = Deployment::start().await;
    let mut b = d.browser();
    assert_eq!(location(&b.get("/").await), "/console/");
    assert_eq!(location(&b.get("/console").await), "/console/");
    for page in ADMIN_PAGES
        .iter()
        .chain(&["/console/me", "/console/decisions/abc"])
    {
        let r = b.get(page).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{page}");
        let to = location(&r);
        assert!(to.starts_with("/console/login?next="), "{page}: {to}");
        assert_eq!(query_of(&to)["next"], *page);
    }
    for path in [
        "/console/devices/d-1/approve",
        "/console/devices/d-1/revoke",
        "/console/users/u-1/disable",
        "/console/users/u-1/enable",
    ] {
        let base = b.base.clone();
        let r = b.post_with(path, &[("csrf", "x")], &base).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{path}");
        let to = location(&r);
        assert!(to.starts_with("/console/login"), "{path}");
        // Signing in returns to the page the change was made from.
        let page = path.rsplitn(3, '/').nth(2).unwrap();
        assert_eq!(query_of(&to)["next"], page, "{path}");
    }
    // A logout without a session just lands on the sign-in page.
    let base = b.base.clone();
    let r = b.post_with("/console/logout", &[], &base).await;
    assert_eq!(location(&r), "/console/login?why=signed-out");

    // The sign-in page, and assets, need no session.
    let r = b.get("/console/login?next=/console/devices").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(text(&r).contains("/console/login/start?next=/console/devices"));
    // With an IdP and no built-in accounts, there is no form to post.
    assert!(!text(&r).contains("<form"));
    let base = b.base.clone();
    let r = b
        .post_with("/console/login", &[("username", "admin")], &base)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    for (path, kind) in [
        ("/console/assets/console.css", "text/css"),
        ("/console/assets/console.js", "text/javascript"),
    ] {
        let r = b.get(path).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            r.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with(kind)
        );
        assert!(!r.body.is_empty());
    }
    let r = b.get("/console/nothing-here").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = b.request(Method::DELETE, "/console/", &[], None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    d.cp.shutdown().await;
}

#[tokio::test]
async fn admins_sign_in_and_see_every_page() {
    let d = Deployment::start().await;
    *d.idp.idp.user.lock().unwrap() = admin_user();
    let mut b = d.browser();
    // Sign-in sets a binding cookie, then the session cookie.
    let start = b.get("/console/login/start?next=/console/users").await;
    assert_eq!(start.status, StatusCode::SEE_OTHER);
    let login = set_cookies(&start);
    assert!(
        login[0].starts_with(&format!("{LOGIN_COOKIE}="))
            && login[0].contains("Secure")
            && login[0].contains("HttpOnly")
            && login[0].contains("SameSite=Lax")
            && login[0].contains("Path=/"),
        "{login:?}"
    );
    let to_idp = location(&start);
    let callback = location(
        &b.idp_http
            .request(Method::GET, &to_idp, &[], None)
            .await
            .unwrap(),
    );
    let back = b.request(Method::GET, &callback, &[], None).await;
    assert_eq!(location(&back), "/console/users");
    let cookies = set_cookies(&back);
    let session = cookies
        .iter()
        .find(|c| c.starts_with(&format!("{SESSION_COOKIE}=")))
        .unwrap();
    for attr in [
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=43200",
    ] {
        assert!(session.contains(attr), "{session}");
    }
    assert!(!session.contains("Domain"), "{session}");
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with(&format!("{LOGIN_COOKIE}=;")))
    );
    assert!(!b.cookies.contains_key(LOGIN_COOKIE));

    for page in ADMIN_PAGES {
        let r = b.get(page).await;
        assert_eq!(r.status, StatusCode::OK, "{page}: {}", text(&r));
        let csp = r.headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'") && csp.contains("form-action 'self'"));
        assert_eq!(r.headers["x-content-type-options"], "nosniff");
        assert_eq!(r.headers["x-frame-options"], "DENY");
        // Browsers send `Origin: null` under no-referrer, failing every form.
        assert_eq!(r.headers["referrer-policy"], "same-origin");
        assert_eq!(r.headers["cache-control"], "no-store");
        let body = text(&r);
        assert!(body.contains("root@example.com"), "{page}");
        assert!(body.contains("Administration"), "{page}");
        assert!(
            !body.contains("<script>") && !body.contains("style="),
            "{page}"
        );
    }
    let overview = text(&b.get("/console/").await);
    assert!(overview.contains("Relays and connectors"));
    assert!(overview.contains("No relays or connectors have joined yet"));
    let users = text(&b.get("/console/users").await);
    assert!(users.contains("warren-admins") && users.contains("engineering"));
    assert!(users.contains("base/engineers-grafana"));
    let apps = text(&b.get("/console/apps").await);
    assert!(apps.contains("grafana.lab.example.com") && apps.contains("Managed by Git"));
    assert!(apps.contains("*.lab.example.com") && apps.contains("base/finance-billing"));
    let policies = text(&b.get("/console/policies").await);
    assert!(policies.contains("Managed by Git"));
    assert!(policies.contains("engineers-grafana") && policies.contains("signed in with MFA"));
    assert!(policies.contains("signed in within 12h") && policies.contains("group:finance"));
    assert!(policies.contains("permit"), "the compiled Cedar is shown");
    // Admins have their own apps page too.
    let me = text(&b.get("/console/me").await);
    assert!(me.contains("grafana") && !me.contains("billing"));

    // A sign-in is audited.
    let logon = d
        .audit_records()
        .into_iter()
        .find(|r| r["message"] == "signed in to the console")
        .unwrap();
    assert_eq!(logon["actor"]["user"]["email_addr"], "root@example.com");
    assert_eq!(logon["actor"]["app_name"], "warren console");
    assert_eq!(logon["is_mfa"], true);

    // Signed in already: the sign-in page sends the browser on.
    assert_eq!(
        location(&b.get("/console/login?next=/console/apps").await),
        "/console/apps"
    );
    d.cp.shutdown().await;
}

#[tokio::test]
async fn admins_can_be_named_by_email() {
    let d = Deployment::start().await;
    let grace = IdpUser {
        sub: "00u-grace".into(),
        email: "grace@example.com".into(),
        groups: vec![],
        amr: vec!["mfa".into()],
    };
    let mut b = d.signed_in(grace).await;
    assert_eq!(b.get("/console/devices").await.status, StatusCode::OK);
    d.cp.shutdown().await;
}

#[tokio::test]
async fn admin_names_tell_built_in_accounts_from_idp_subjects() {
    // The bootstrap admin `admin` is not in an admin group here, and an IdP
    // user's subject is `admin` too: `local:admin` names only the built-in
    // account, and a plain `admin` only the IdP user.
    for (users, local_admin) in [("[admin]", false), ("[\"local:admin\"]", true)] {
        let d = Deployment::start_with_admins(
            true,
            users,
            "localAccounts:\n  bootstrapAdmin:\n    passwordFile: {dir}/admin-password\n    groups: [ops]\n",
        )
        .await;
        let mut own = d.browser();
        own.local_sign_in("/console/login", "admin", None).await;
        let status = own.get("/console/users").await.status;
        assert_eq!(status == StatusCode::OK, local_admin, "{users}: {status}");
        let mut idp = d
            .signed_in(IdpUser {
                sub: "admin".into(),
                email: "someone@example.com".into(),
                groups: vec![],
                amr: vec!["mfa".into()],
            })
            .await;
        let status = idp.get("/console/users").await.status;
        assert_eq!(status == StatusCode::OK, !local_admin, "{users}: {status}");
        d.cp.shutdown().await;
    }
}

#[tokio::test]
async fn users_see_only_their_own_apps() {
    let d = Deployment::start().await;
    let mut b = d.signed_in(plain_user()).await;
    // The start of the console is their apps page.
    assert_eq!(location(&b.get("/console/").await), "/console/me");
    let me = b.get("/console/me").await;
    assert_eq!(me.status, StatusCode::OK);
    let me = text(&me);
    assert!(me.contains("grafana.lab.example.com"), "{me}");
    assert!(
        !me.contains("billing"),
        "apps the user cannot reach are never named"
    );
    assert!(!me.contains("Administration"));
    for page in ADMIN_PAGES.iter().skip(1) {
        let r = b.get(page).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{page}");
        assert!(text(&r).contains("for warren administrators"), "{page}");
    }
    // Their form token is valid, but they are not an admin.
    let device = d.enroll(admin_user()).await;
    let r = b
        .post_from("/console/me", &format!("/console/devices/{device}/approve"))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(d.device_status(&device).await, "pending");
    let root = d.user_id("root@example.com").await;
    let r = b
        .post_from("/console/me", &format!("/console/users/{root}/disable"))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    d.cp.shutdown().await;
}

#[tokio::test]
async fn admins_without_mfa_read_admin_pages_but_change_nothing() {
    let d = Deployment::start().await;
    let device = d.enroll(plain_user()).await;
    let ada_id = d.user_id("ada@example.com").await;
    let mut no_mfa = admin_user();
    no_mfa.amr = vec!["pwd".into()];
    let mut b = d.signed_in(no_mfa).await;
    for page in ADMIN_PAGES {
        assert_eq!(b.get(page).await.status, StatusCode::OK, "{page}");
    }
    let page = text(&b.get("/console/devices").await);
    assert!(
        page.contains("Changes need a multi-factor sign-in"),
        "{page}"
    );
    assert!(page.contains("disabled title=\"Changes need a multi-factor sign-in\""));
    assert!(page.contains("/console/login/start?next=/console/devices&amp;reauth=1"));

    for (from, path) in [
        (
            "/console/devices",
            format!("/console/devices/{device}/approve"),
        ),
        (
            "/console/devices",
            format!("/console/devices/{device}/revoke"),
        ),
        ("/console/users", format!("/console/users/{ada_id}/disable")),
        ("/console/users", format!("/console/users/{ada_id}/enable")),
    ] {
        let r = b.post_from(from, &path).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}");
        let body = text(&r);
        assert!(body.contains("Multi-factor sign-in required"), "{body}");
        assert!(body.contains("Nothing was changed."), "{body}");
        assert!(
            body.contains(&format!("/console/login/start?next={from}&amp;reauth=1")),
            "{body}"
        );
    }
    assert_eq!(d.device_status(&device).await, "pending");
    let (_, users) = d.admin("GET", "/v1/admin/users", None).await;
    let ada = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == ada_id.as_str())
        .unwrap();
    assert_eq!(ada["disabled"], false);

    // Signing in again with MFA allows changes.
    *d.idp.idp.user.lock().unwrap() = admin_user();
    let landed = b
        .sign_in_with("/console/login/start?next=/console/devices&reauth=1")
        .await;
    assert_eq!(landed, "/console/devices");
    let r = b
        .post_from(
            "/console/devices",
            &format!("/console/devices/{device}/approve"),
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", text(&r));
    assert_eq!(d.device_status(&device).await, "approved");
    d.cp.shutdown().await;
}

#[tokio::test]
async fn devices_are_approved_and_revoked_from_the_console() {
    let d = Deployment::start().await;
    let device = d.enroll(plain_user()).await;
    let mut b = d.signed_in(admin_user()).await;

    let page = text(&b.get("/console/devices?status=pending").await);
    assert!(page.contains(&device) && page.contains("Approve"));
    assert!(page.contains("ada@example.com"));

    let r = b
        .post_from(
            "/console/devices",
            &format!("/console/devices/{device}/approve"),
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", text(&r));
    let back = location(&r);
    assert_eq!(back, format!("/console/devices?done=approve&id={device}"));
    assert!(text(&b.get(&back).await).contains(&format!("Device {device} approved.")));
    assert_eq!(d.device_status(&device).await, "approved");

    // Approving again changes nothing.
    let r = b
        .post_from(
            "/console/devices",
            &format!("/console/devices/{device}/approve"),
        )
        .await;
    assert!(location(&r).contains("done=unchanged"));

    let r = b
        .post_from(
            "/console/devices",
            &format!("/console/devices/{device}/revoke"),
        )
        .await;
    assert_eq!(
        location(&r),
        format!("/console/devices?done=revoke&id={device}")
    );
    assert_eq!(d.device_status(&device).await, "revoked");
    // A revoked device cannot be approved.
    let r = b
        .post_from(
            "/console/devices",
            &format!("/console/devices/{device}/approve"),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(text(&r).contains("revoked"));
    let r = b
        .post_from("/console/devices", "/console/devices/d-nope/revoke")
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Each change is audited as the admin, through the console.
    let records = d.audit_records();
    for message in ["device approved", "device revoked"] {
        let r = records.iter().find(|r| r["message"] == message).unwrap();
        assert_eq!(r["actor"]["user"]["email_addr"], "root@example.com");
        assert_eq!(r["actor"]["app_name"], "warren console");
        assert_eq!(r["entity"]["uid"], device.as_str());
    }
    // The revocation reaches the push channel like the admin API's.
    let (_, latency) = d.admin("GET", "/v1/admin/revocation-latency", None).await;
    assert!(latency["deadline_ms"].is_u64());
    d.cp.shutdown().await;
}

#[tokio::test]
async fn users_are_disabled_and_enabled_from_the_console() {
    let d = Deployment::start().await;
    let mut ada = d.signed_in(plain_user()).await;
    let mut b = d.signed_in(admin_user()).await;
    let ada_id = d.user_id("ada@example.com").await;
    let root_id = d.user_id("root@example.com").await;

    let r = b
        .post_from(
            "/console/users",
            &format!("/console/users/{ada_id}/disable"),
        )
        .await;
    assert_eq!(
        location(&r),
        format!("/console/users?done=disable&id={ada_id}")
    );
    let page = text(&b.get(&location(&r)).await);
    assert!(page.contains("disabled") && page.contains("Enable"));
    // Ada's console session stops at once.
    let r = ada.get("/console/me").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(location(&r).contains("why=disabled"));
    let r = ada.get(&location(&r)).await;
    assert!(text(&r).contains("Your warren account is disabled"));
    // And she cannot sign in again.
    *d.idp.idp.user.lock().unwrap() = plain_user();
    let landed = ada.sign_in("/console/me").await;
    assert!(landed.contains("why=disabled"), "{landed}");
    assert!(!ada.cookies.contains_key(SESSION_COOKIE));

    let r = b
        .post_from("/console/users", &format!("/console/users/{ada_id}/enable"))
        .await;
    assert_eq!(
        location(&r),
        format!("/console/users?done=enable&id={ada_id}")
    );
    let (_, users) = d.admin("GET", "/v1/admin/users", None).await;
    assert!(
        users
            .as_array()
            .unwrap()
            .iter()
            .all(|u| u["disabled"] == false)
    );

    // Not on yourself, and only by ID.
    let r = b
        .post_from(
            "/console/users",
            &format!("/console/users/{root_id}/disable"),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = b
        .post_from("/console/users", "/console/users/ada@example.com/disable")
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let records = d.audit_records();
    let disabled = records
        .iter()
        .find(|r| r["message"] == "user disabled")
        .unwrap();
    assert_eq!(disabled["actor"]["app_name"], "warren console");
    assert_eq!(disabled["user"]["uid"], ada_id.as_str());
    d.cp.shutdown().await;
}

#[tokio::test]
async fn changes_need_a_form_token_from_this_origin() {
    let d = Deployment::start().await;
    let device = d.enroll(plain_user()).await;
    let mut b = d.signed_in(admin_user()).await;
    let path = format!("/console/devices/{device}/approve");
    let token = csrf(&text(&b.get("/console/devices").await));
    let base = b.base.clone();

    let r = b.post_with(&path, &[], &base).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "no token");
    let r = b.post_with(&path, &[("csrf", "forged")], &base).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a wrong token");
    let r = b
        .post_with(&path, &[("csrf", &token)], "https://evil.example")
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "another origin");
    let r = b.post_with(&path, &[("csrf", &token)], "null").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "an opaque origin");
    let r = b
        .request(
            Method::POST,
            &path,
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("sec-fetch-site", "cross-site"),
            ],
            Some(format!("csrf={token}")),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a cross-site fetch");
    assert_eq!(d.device_status(&device).await, "pending");

    // Another session's token does not work in this one.
    let mut other = d.signed_in(admin_user()).await;
    let other_token = csrf(&text(&other.get("/console/devices").await));
    assert_ne!(other_token, token);
    let r = b.post_with(&path, &[("csrf", &other_token)], &base).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let r = b.post_with(&path, &[("csrf", &token)], &base).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(d.device_status(&device).await, "approved");
    d.cp.shutdown().await;
}

#[tokio::test]
async fn changes_need_a_recent_sign_in() {
    let d = Deployment::start().await;
    let device = d.enroll(plain_user()).await;
    // The IdP does not say when the user authenticated, and a plain
    // sign-in may reuse the IdP's session, so it counts as old.
    *d.idp.idp.omit_auth_time.lock().unwrap() = true;
    let mut b = d.signed_in(admin_user()).await;
    let page = text(&b.get("/console/devices").await);
    assert!(page.contains("Changes need a recent sign-in"), "{page}");
    assert!(page.contains("disabled title=\"Sign in again to make changes\""));
    let r = b
        .post_from("/console/", &format!("/console/devices/{device}/approve"))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let body = text(&r);
    assert!(body.contains("Sign in again to make changes"), "{body}");
    assert!(
        body.contains("next=/console/devices&amp;reauth=1"),
        "{body}"
    );
    assert_eq!(d.device_status(&device).await, "pending");

    // Signing in again asks the IdP to authenticate afresh, so even
    // without auth_time the sign-in counts from its callback.
    b.sign_in_with("/console/login/start?next=/console/devices&reauth=1")
        .await;
    let again = d
        .idp
        .idp
        .authorize_requests
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(again.get("prompt").map(String::as_str), Some("login"));
    assert_eq!(again.get("max_age").map(String::as_str), Some("3600"));
    assert!(!text(&b.get("/console/devices").await).contains("Changes need a recent sign-in"));
    let r = b
        .post_from(
            "/console/devices",
            &format!("/console/devices/{device}/approve"),
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(d.device_status(&device).await, "approved");
    d.cp.shutdown().await;
}

#[tokio::test]
async fn sign_in_must_finish_in_the_browser_that_started_it() {
    let d = Deployment::start().await;
    let mut victim = d.browser();
    let mut attacker = d.browser();
    // The attacker starts a sign-in and hands the IdP's answer to the
    // victim's browser, which never started one.
    let to_idp = location(&attacker.get("/console/login/start?next=/console/").await);
    let callback = location(
        &attacker
            .idp_http
            .request(Method::GET, &to_idp, &[], None)
            .await
            .unwrap(),
    );
    let r = victim.request(Method::GET, &callback, &[], None).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(location(&r).contains("why=browser"));
    assert!(!victim.cookies.contains_key(SESSION_COOKIE));
    let page = victim.get(&location(&r)).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(text(&page).contains("started in another browser"));
    // The state was used up, so the attacker cannot finish it either.
    let r = attacker.request(Method::GET, &callback, &[], None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        d.audit_records()
            .iter()
            .any(|r| r["message"] == "console sign-in refused: it was started in another browser")
    );
    d.cp.shutdown().await;
}

#[tokio::test]
async fn sign_in_only_returns_to_the_console() {
    let d = Deployment::start().await;
    *d.idp.idp.user.lock().unwrap() = admin_user();
    let mut b = d.browser();
    for next in [
        "https://evil.example/",
        "//evil.example/",
        "/v1/admin/users",
    ] {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        ser.append_pair("next", next);
        let landed = b
            .sign_in_with(&format!("/console/login/start?{}", ser.finish()))
            .await;
        assert_eq!(landed, "/console/", "{next}");
    }
    d.cp.shutdown().await;
}

#[tokio::test]
async fn signing_out_ends_the_session() {
    let d = Deployment::start().await;
    let mut b = d.signed_in(admin_user()).await;
    let cookie = b.cookies[SESSION_COOKIE].clone();
    let r = b.post_from("/console/", "/console/logout").await;
    assert_eq!(location(&r), "/console/login?why=signed-out");
    assert!(!b.cookies.contains_key(SESSION_COOKIE));
    assert!(text(&b.get(&location(&r)).await).contains("You have signed out"));
    // The old cookie no longer works anywhere.
    b.cookies.insert(SESSION_COOKIE.into(), cookie);
    let r = b.get("/console/").await;
    assert!(location(&r).contains("why=expired"));
    assert!(
        d.audit_records()
            .iter()
            .any(|r| r["message"] == "signed out of the console" && r["activity_name"] == "Logoff")
    );
    // A made-up cookie is no session either.
    b.cookies.insert(SESSION_COOKIE.into(), "nonsense".into());
    assert!(location(&b.get("/console/users").await).contains("why=expired"));
    d.cp.shutdown().await;
}

fn decision(
    id: &str,
    user: &str,
    device: &str,
    allowed: bool,
    hostname: &str,
    rules: &[String],
) -> Value {
    let node = NodeInfo {
        role: "connector".into(),
        name: "connector/homelab/c1".into(),
    };
    let src: SocketAddr = "100.96.0.2:51000".parse().unwrap();
    let dst: SocketAddr = "100.64.0.9:443".parse().unwrap();
    warren_core::audit::decision(
        &node,
        &DecisionRecord {
            id,
            subject: Subject {
                user,
                device,
                session: "s-1",
            },
            app: Some("grafana"),
            hostname: Some(hostname),
            protocol: 6,
            src,
            dst,
            translated_dst: Some("10.20.0.5:443".parse().unwrap()),
            allowed,
            reason: (!allowed).then_some("mfa_required"),
            message: if allowed {
                ""
            } else {
                "Sign in again with multi-factor authentication to reach grafana."
            },
            rules,
            failed_condition: (!allowed).then_some("auth.mfa"),
            policy_version: 1,
            server_initiated: false,
        },
    )
}

#[tokio::test]
async fn decisions_and_why_they_were_made() {
    let d = Deployment::start().await;
    let mut b = d.signed_in(admin_user()).await;
    let connector = d.connector("c1").await;
    let _events = connector.events(None).await;
    let ada = {
        let mut ada = d.signed_in(plain_user()).await;
        ada.get("/console/me").await;
        d.user_id("ada@example.com").await
    };
    let rule = vec!["base/engineers-grafana".to_owned()];
    let records = [
        decision(
            "aaaa01",
            &ada,
            "d-1",
            true,
            "grafana.lab.example.com",
            &rule,
        ),
        decision(
            "aaaa02",
            &ada,
            "d-1",
            false,
            "<script>alert(1)</script>.lab.example.com",
            &rule,
        ),
    ];
    let body: String = records.iter().map(|r| format!("{r}\n")).collect();
    let r = connector
        .post("/v1/node/audit", "application/x-ndjson", body.into_bytes())
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);

    let page = text(&b.get("/console/decisions").await);
    assert!(page.contains("aaaa01") && page.contains("aaaa02"));
    assert!(page.contains("ada@example.com"), "users are shown by name");
    assert!(page.contains("connector/homelab/c1"));
    // What a connector or user controls is escaped, never markup.
    assert!(!page.contains("<script>alert(1)</script>"));
    assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    let denied = text(&b.get("/console/decisions?denied=1").await);
    assert!(denied.contains("aaaa02") && !denied.contains("aaaa01"));

    let why = b.get("/console/decisions/aaaa02").await;
    assert_eq!(why.status, StatusCode::OK);
    let why = text(&why);
    assert!(why.contains("Why was this denied?"));
    assert!(why.contains("mfa_required"));
    assert!(why.contains("requires a multi-factor sign-in"));
    assert!(why.contains("base/engineers-grafana") && why.contains("base.yaml"));
    assert!(why.contains("cond failed") && why.contains("auth.mfa"));
    assert!(why.contains("Sign in again with multi-factor authentication to reach grafana."));
    assert!(why.contains("10.20.0.5:443") && why.contains("100.96.0.2:51000"));
    assert!(!why.contains("<script>alert(1)</script>"));
    let allowed = text(&b.get("/console/decisions/aaaa01").await);
    assert!(allowed.contains("Why was this allowed?"));
    let r = b.get("/console/decisions/ffff99").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(text(&r).contains("audit log"));

    // The overview shows the connector connected, the deny, and the device
    // that reached an app just now.
    let overview = text(&b.get("/console/").await);
    assert!(overview.contains("connected"), "{overview}");
    assert!(overview.contains("aaaa02"));
    assert!(overview.contains("c1"));
    let apps = text(&b.get("/console/apps").await);
    assert!(apps.contains("1 of 1 connected"), "{apps}");
    d.cp.shutdown().await;
}

#[tokio::test]
async fn names_users_and_devices_control_are_escaped() {
    let d = Deployment::start().await;
    let evil = IdpUser {
        sub: "00u-<b>evil</b>".into(),
        email: "x\"><img src=x onerror=alert(1)>@example.com".into(),
        groups: vec!["<i>group</i>".into()],
        amr: vec!["mfa".into()],
    };
    d.enroll(evil.clone()).await;
    let mut b = d.signed_in(admin_user()).await;
    for page in ["/console/users", "/console/devices"] {
        let body = text(&b.get(page).await);
        assert!(!body.contains("<img src=x"), "{page}");
        assert!(
            body.contains("&lt;img src=x onerror=alert(1)&gt;"),
            "{page}"
        );
        assert!(!body.contains("<i>group</i>"), "{page}");
    }
    let users = text(&b.get("/console/users").await);
    assert!(users.contains("&lt;i&gt;group&lt;/i&gt;"));
    d.cp.shutdown().await;
}

#[tokio::test]
async fn built_in_accounts_sign_in_without_an_idp() {
    let d = Deployment::with_accounts(false, None, "").await;
    let mut b = d.browser();
    let to = location(&b.get("/console/users").await);
    assert_eq!(query_of(&to)["next"], "/console/users");
    // The sign-in page is the built-in account form, and nothing else.
    let r = b.get(&to).await;
    assert_eq!(r.status, StatusCode::OK);
    let page = text(&r);
    assert!(page.contains("action=\"/console/login\""), "{page}");
    assert!(!page.contains("/console/login/start"), "{page}");
    assert!(b.cookies.contains_key(LOGIN_COOKIE));
    // The IdP button's address, from an old link, leads back to it.
    let r = b.get("/console/login/start?next=/console/users").await;
    assert!(location(&r).starts_with("/console/login?next="));

    // A wrong password gets the one answer every failure gets.
    let r = b
        .password(
            "/console/login?next=/console/users",
            "admin",
            "wrong password!",
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(text(&r).contains("The username or password is incorrect"));
    assert!(text(&r).contains("value=\"admin\""));
    assert!(!b.cookies.contains_key(SESSION_COOKIE));

    // The first sign-in enrolls an authenticator, then lands where it was
    // going, signed in with MFA just now: changes are allowed.
    let (secret, landed) = b
        .local_sign_in("/console/login?next=/console/users", "admin", None)
        .await;
    assert_eq!(landed, "/console/users");
    assert!(b.cookies.contains_key(SESSION_COOKIE));
    let page = text(&b.get("/console/users").await);
    assert!(page.contains("admin"), "{page}");
    assert!(!page.contains("Changes need"), "{page}");
    let r = audited(&d, "signed in to the console with a built-in account");
    assert_eq!(r["auth_protocol"], "password+TOTP");
    assert_eq!(r["is_mfa"], true);
    assert_eq!(r["status_id"], 1);

    // Changes work.
    let (status, ada) = d
        .admin(
            "POST",
            "/v1/admin/users",
            Some(json!({ "username": "ada" })),
        )
        .await;
    assert_eq!(status, 201, "{ada}");
    let ada_id = ada["user"]["id"].as_str().unwrap().to_owned();
    let r = b
        .post_from(
            "/console/users",
            &format!("/console/users/{ada_id}/disable"),
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", text(&r));
    let (_, users) = d.admin("GET", "/v1/admin/users", None).await;
    let ada = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == ada_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(ada["disabled"], true);

    // Signing in again is the same form, even while signed in.
    let r = b.get("/console/login?next=/console/users&reauth=1").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(text(&r).contains("action=\"/console/login\""));

    // A wrong authenticator code is refused and signs nobody in; the next
    // code works.
    let mut other = d.browser();
    let reply = other
        .password("/console/login?next=/console/devices", "admin", PASSWORD)
        .await;
    let flow = field(&text(&reply), "flow");
    let step = totp_step(clock::now_secs());
    let base = other.base.clone();
    let r = other
        .post_with(
            "/v1/auth/code",
            &[("flow", &flow), ("code", &code_at(&secret, step - 5))],
            &base,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(text(&r).contains("That code is not right"));
    assert!(!other.cookies.contains_key(SESSION_COOKIE));
    let r = other
        .post_with(
            "/v1/auth/code",
            &[("flow", &flow), ("code", &code_at(&secret, step + 1))],
            &base,
        )
        .await;
    assert_eq!(location(&r), "/console/devices");
    assert_eq!(other.get("/console/devices").await.status, StatusCode::OK);
    d.cp.shutdown().await;
}

#[tokio::test]
async fn disabled_built_in_accounts_cannot_sign_in_to_the_console() {
    let d = Deployment::with_accounts(false, None, "").await;
    let mut b = d.browser();
    let (status, _) = d.admin("POST", "/v1/admin/users/admin/disable", None).await;
    assert_eq!(status, 200);
    // The right password reads like a wrong one.
    let r = b.password("/console/login", "admin", PASSWORD).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(text(&r).contains("The username or password is incorrect"));
    audited(&d, "sign-in refused: the user is disabled");

    // Disabled between the password and the end of the sign-in.
    let (status, _) = d.admin("POST", "/v1/admin/users/admin/enable", None).await;
    assert_eq!(status, 200);
    let reply = b.password("/console/login", "admin", PASSWORD).await;
    let page = text(&reply);
    let flow = field(&page, "flow");
    let secret = enrollment_secret(&page);
    let base = b.base.clone();
    let r = b
        .post_with(
            "/v1/auth/code",
            &[
                ("flow", &flow),
                ("code", &code_at(&secret, totp_step(clock::now_secs()))),
            ],
            &base,
        )
        .await;
    assert!(text(&r).contains("Save your recovery codes"));
    d.admin("POST", "/v1/admin/users/admin/disable", None).await;
    let r = b
        .post_with("/v1/auth/continue", &[("flow", &flow)], &base)
        .await;
    assert!(location(&r).contains("why=disabled"), "{}", location(&r));
    assert!(!b.cookies.contains_key(SESSION_COOKIE));
    audited(&d, "console sign-in refused: the user is disabled");
    d.cp.shutdown().await;
}

#[tokio::test]
async fn console_sign_in_failures_count_against_the_source() {
    let d = Deployment::with_accounts(false, None, "  maxFailuresPerSource: 3\n").await;
    let mut b = d.browser();
    for i in 0..3 {
        let r = b
            .password("/console/login", &format!("nobody-{i}"), "wrong password!")
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    // Even the right password is refused for the rest of the window, as
    // at the warren app's sign-in.
    let r = b.password("/console/login", "admin", PASSWORD).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(text(&r).contains("too many failed sign-ins"));
    assert!(!b.cookies.contains_key(SESSION_COOKIE));
    d.cp.shutdown().await;
}

#[tokio::test]
async fn built_in_accounts_and_the_idp_share_the_sign_in_page() {
    let d = Deployment::with_accounts(true, None, "").await;
    let mut b = d.browser();
    let page = text(&b.get("/console/login?next=/console/devices").await);
    assert!(
        page.contains("/console/login/start?next=/console/devices"),
        "{page}"
    );
    assert!(
        page.contains("Sign in with your identity provider"),
        "{page}"
    );
    assert!(page.contains("action=\"/console/login\""), "{page}");

    // The form needs its token, bound to this browser, from this origin.
    let token = csrf(&page);
    let base = b.base.clone();
    fn form(token: &str) -> [(&str, &str); 3] {
        [
            ("csrf", token),
            ("username", "admin"),
            ("password", PASSWORD),
        ]
    }
    let r = b.post_with("/console/login", &form("forged"), &base).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a wrong token");
    let r = b
        .post_with("/console/login", &form(&token), "https://evil.example")
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "another origin");
    let r = b.post_with("/console/login", &form(&token), "null").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "an opaque origin");
    let mut stranger = d.browser();
    let r = stranger
        .post_with("/console/login", &form(&token), &base)
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "another browser");
    assert!(text(&r).contains("The sign-in form expired"));
    let r = b
        .request(
            Method::POST,
            "/console/login",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("sec-fetch-site", "cross-site"),
            ],
            Some(format!("csrf={token}&username=admin&password=x")),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a cross-site fetch");
    assert!(!b.cookies.contains_key(SESSION_COOKIE));
    // None of those reached the password check.
    assert!(
        !d.audit_records()
            .iter()
            .any(|r| r["message"] == "sign-in refused: wrong password")
    );

    // Both ways in work.
    let (_, landed) = b
        .local_sign_in("/console/login?next=/console/devices", "admin", None)
        .await;
    assert_eq!(landed, "/console/devices");
    let page = text(&b.get("/console/devices").await);
    assert!(!page.contains("Changes need"), "{page}");
    let idp_admin = d.signed_in(admin_user()).await;
    assert!(idp_admin.cookies.contains_key(SESSION_COOKIE));
    d.cp.shutdown().await;
}

/// An admin as Google signs them in: no MFA reported, no `auth_time`.
fn google_style_admin(d: &Deployment) -> IdpUser {
    *d.idp.idp.omit_auth_time.lock().unwrap() = true;
    let mut admin = admin_user();
    admin.amr = vec![];
    admin
}

#[tokio::test]
async fn idp_sign_ins_without_mfa_change_only_after_a_step_up() {
    let d = Deployment::with_accounts(true, Some("Root@Example.com"), "").await;
    // A user to disable, known from their own console sign-in.
    d.signed_in(plain_user()).await;
    let ada = d.user_id("ada@example.com").await;
    let disable = format!("/console/users/{ada}/disable");
    let disabled = || async {
        let (_, users) = d.admin("GET", "/v1/admin/users", None).await;
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == ada.as_str())
            .unwrap()["disabled"]
            == true
    };
    // The admin's built-in account, with the IdP account's email, enrolls
    // its authenticator.
    let mut own = d.browser();
    let (secret, _) = own.local_sign_in("/console/login", "admin", None).await;
    let enrolled = totp_step(clock::now_secs());

    let mut b = d.signed_in(google_style_admin(&d)).await;
    let page = text(&b.get("/console/users").await);
    assert!(
        page.contains("Confirm with your authenticator code"),
        "{page}"
    );
    assert!(page.contains("/console/step-up?next=/console/users"));
    assert!(
        page.contains("disabled title=\"Confirm with your authenticator code to make changes\"")
    );
    let r = b.post_from("/console/users", &disable).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let body = text(&r);
    assert!(body.contains("Nothing was changed."), "{body}");
    assert!(
        body.contains("/console/step-up?next=/console/users"),
        "{body}"
    );
    assert!(!disabled().await);

    // The step-up page names the account whose code it takes.
    let r = b.get("/console/step-up?next=/console/users").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(text(&r).contains("<strong>admin</strong>"));

    // Its form needs the session's token, from this origin.
    let base = b.base.clone();
    let code = code_at(&secret, enrolled + 1);
    let fields = [("next", "/console/users"), ("code", code.as_str())];
    let r = b.post_with("/console/step-up", &fields, &base).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "no token");
    let token = csrf(&text(&b.get("/console/users").await));
    let with_token = [
        ("csrf", token.as_str()),
        ("next", "/console/users"),
        ("code", code.as_str()),
    ];
    let r = b
        .post_with("/console/step-up", &with_token, "https://evil.example")
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "another origin");

    // A wrong code, and the code the sign-in already used, are refused.
    let r = b
        .step_up("/console/users", &code_at(&secret, enrolled - 5))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(text(&r).contains("That code is not right"));
    let r = b
        .step_up("/console/users", &code_at(&secret, enrolled))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "a replayed code");
    let r = b.post_from("/console/users", &disable).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(!disabled().await);
    let refused = audited(&d, "console step-up refused: wrong authenticator code");
    assert_eq!(refused["auth_protocol"], "TOTP");

    // The next code steps the sign-in up: changes work.
    let r = b.step_up("/console/users", &code).await;
    assert_eq!(location(&r), "/console/users");
    let page = text(&b.get("/console/users").await);
    assert!(
        !page.contains("Confirm with your authenticator code"),
        "{page}"
    );
    let r = b.post_from("/console/users", &disable).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", text(&r));
    assert!(disabled().await);
    let r = audited(
        &d,
        "stepped up a console sign-in with a built-in account's authenticator code",
    );
    assert_eq!(r["auth_protocol"], "TOTP");
    assert_eq!(r["is_mfa"], true);
    assert_eq!(r["user"]["name"], "admin");
    assert_eq!(r["actor"]["user"]["email_addr"], "root@example.com");
    // The step-up is the session's own: another IdP sign-in needs its own.
    let mut other = d.signed_in(google_style_admin(&d)).await;
    let page = text(&other.get("/console/users").await);
    assert!(
        page.contains("Confirm with your authenticator code"),
        "{page}"
    );
    d.cp.shutdown().await;
}

#[tokio::test]
async fn a_step_up_needs_exactly_one_enabled_account_with_an_authenticator() {
    let d = Deployment::with_accounts(true, Some("root@example.com"), "").await;
    let no_step_up = |page: &str| {
        page.contains("Changes need a multi-factor sign-in") && !page.contains("/console/step-up")
    };
    // No authenticator yet.
    let mut b = d.signed_in(google_style_admin(&d)).await;
    assert!(no_step_up(&text(&b.get("/console/users").await)));
    let r = b.get("/console/step-up?next=/console/users").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(text(&r).contains("No step-up available"));
    let r = b.step_up("/console/users", "123456").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let mut own = d.browser();
    own.local_sign_in("/console/login", "admin", None).await;
    assert!(!no_step_up(&text(&b.get("/console/users").await)));

    // Disabled.
    d.admin("POST", "/v1/admin/users/admin/disable", None).await;
    assert!(no_step_up(&text(&b.get("/console/users").await)));
    d.admin("POST", "/v1/admin/users/admin/enable", None).await;
    assert!(!no_step_up(&text(&b.get("/console/users").await)));

    // Two accounts with the email: neither is the one.
    let (status, created) = d
        .admin(
            "POST",
            "/v1/admin/users",
            Some(json!({ "username": "root", "email": "ROOT@example.com" })),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    let mut setup = d.browser();
    let page = text(&setup.get(created["setup_url"].as_str().unwrap()).await);
    let token = field(&page, "token");
    let base = setup.base.clone();
    let r = setup
        .post_with(
            "/v1/auth/setup",
            &[
                ("token", &token),
                ("password", PASSWORD),
                ("confirm", PASSWORD),
            ],
            &base,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", text(&r));
    // Without an authenticator it does not count yet; with one it does.
    assert!(!no_step_up(&text(&b.get("/console/users").await)));
    setup.local_sign_in("/console/login", "root", None).await;
    assert!(no_step_up(&text(&b.get("/console/users").await)));
    d.cp.shutdown().await;
}

#[tokio::test]
async fn step_ups_follow_the_built_in_accounts_switch() {
    let d = Deployment::with_accounts(true, Some("root@example.com"), "").await;
    let mut own = d.browser();
    let (secret, _) = own.local_sign_in("/console/login", "admin", None).await;
    let step = totp_step(clock::now_secs());
    let d = d.restart(|c| c.local_accounts.enabled = false).await;
    let mut b = d.signed_in(google_style_admin(&d)).await;
    let page = text(&b.get("/console/users").await);
    assert!(
        page.contains("Changes need a multi-factor sign-in"),
        "{page}"
    );
    assert!(!page.contains("/console/step-up"), "{page}");
    let r = b.get("/console/step-up?next=/console/users").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let body = text(&r);
    assert!(body.contains("No step-up available"), "{body}");
    assert!(body.contains("Built-in accounts are turned off"), "{body}");
    assert!(!body.contains("ask an administrator"), "{body}");
    let r = b
        .step_up("/console/users", &code_at(&secret, step + 1))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let page = text(&b.get("/console/users").await);
    assert!(
        page.contains("Changes need a multi-factor sign-in"),
        "{page}"
    );
    d.cp.shutdown().await;
}

#[tokio::test]
async fn stale_sign_ins_that_reported_mfa_sign_in_again() {
    let d = Deployment::with_accounts(true, Some("root@example.com"), "").await;
    let mut own = d.browser();
    own.local_sign_in("/console/login", "admin", None).await;
    d.idp
        .idp
        .claims_patch
        .lock()
        .unwrap()
        .insert("auth_time".into(), json!(clock::now_secs() - 7200));
    let mut b = d.signed_in(admin_user()).await;
    let page = text(&b.get("/console/users").await);
    assert!(page.contains("Changes need a recent sign-in"), "{page}");
    assert!(!page.contains("/console/step-up"), "{page}");
    let r = b.get("/console/step-up?next=/console/users").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let body = text(&r);
    assert!(body.contains("too long ago"), "{body}");
    assert!(body.contains("reauth=1"), "{body}");

    // The same sign-in without `auth_time` steps up.
    d.idp.idp.claims_patch.lock().unwrap().remove("auth_time");
    *d.idp.idp.omit_auth_time.lock().unwrap() = true;
    let mut b = d.signed_in(admin_user()).await;
    let page = text(&b.get("/console/users").await);
    assert!(
        page.contains("/console/step-up?next=/console/users"),
        "{page}"
    );

    // Without an account to step up with, the reason is the missing
    // account, not the time it never reported.
    let mut other = d
        .signed_in(IdpUser {
            sub: "00u-other".into(),
            email: "other@example.com".into(),
            groups: vec!["warren-admins".into()],
            amr: vec!["mfa".into()],
        })
        .await;
    let r = other.get("/console/step-up?next=/console/users").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let body = text(&r);
    assert!(!body.contains("too long ago"), "{body}");
    assert!(body.contains("a warren account with your email"), "{body}");
    d.cp.shutdown().await;
}

#[tokio::test]
async fn failed_step_ups_lock_the_account() {
    let d = Deployment::with_accounts(true, Some("root@example.com"), "").await;
    let mut own = d.browser();
    let (secret, _) = own.local_sign_in("/console/login", "admin", None).await;
    let step = totp_step(clock::now_secs());
    let mut b = d.signed_in(google_style_admin(&d)).await;
    for _ in 0..5 {
        let r = b.step_up("/console/", &code_at(&secret, step - 5)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    audited(&d, "built-in account locked after too many failed sign-ins");
    // The right code is refused while the account is locked, and so is a
    // sign-in with it.
    let r = b.step_up("/console/", &code_at(&secret, step + 1)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    audited(
        &d,
        "console step-up refused: the account is locked after too many failed sign-ins",
    );
    let r = d
        .browser()
        .password("/console/login", "admin", PASSWORD)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    d.cp.shutdown().await;
}

#[tokio::test]
async fn step_ups_count_against_the_source() {
    let d = Deployment::with_accounts(
        true,
        Some("root@example.com"),
        "  maxFailuresPerSource: 3\n",
    )
    .await;
    let mut own = d.browser();
    let (secret, _) = own.local_sign_in("/console/login", "admin", None).await;
    let step = totp_step(clock::now_secs());
    let mut b = d.signed_in(google_style_admin(&d)).await;
    for _ in 0..3 {
        let r = b.step_up("/console/", "000000").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = b.step_up("/console/", &code_at(&secret, step + 1)).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(text(&r).contains("too many failed sign-ins"));
    d.cp.shutdown().await;
}

#[test]
fn every_route_is_documented() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/console.md"
    ))
    .unwrap();
    for (method, path) in ROUTES {
        assert!(
            doc.contains(&format!("`{method} {path}`")),
            "docs/console.md does not describe {method} {path}"
        );
    }
}
