//! Built-in accounts and Google sign-in, end to end: the bootstrap admin,
//! sign-in with a password and an authenticator code through the browser
//! pages the client opens, enrollment and recovery codes, lockout, setup
//! links, credential resets, accounts and groups declared in the policy
//! directory, offboarding pushed to a connector within the revocation
//! deadline (G9), and the Google preset against a provider that issues
//! tokens the way Google does.

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, StatusCode};
use serde_json::{Value, json};
use support::{IdpUser, REDIRECT_URI, RunningIdp, StubNode, TempDir, TestClient, free_port, write};
use tokio::sync::mpsc;
use warren_control::accounts::{totp_code, totp_step};
use warren_control::config::{Config, Endpoints};
use warren_control::web::{Client, Reply};
use warren_control::{ControlPlane, admin_request, audit};
use warren_core::api::Session;
use warren_core::clock;
use warren_core::events::{EventBody, Line};
use warren_core::jose::b64url;
use warren_core::keys::{random_bytes, sha256};
use warren_core::params::REVOCATION_DEADLINE;
use warren_core::policy_bundle::{Bundle, View};

const POLICY: &str = r#"
apiVersion: warren.dev/v1alpha1
kind: ConnectorGroup
metadata: { name: homelab }
spec:
  destinations:
    domains: ["*.lab.example.com"]
  clientNames: ["*.lab.example.com"]
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: grafana }
spec:
  connectorGroup: homelab
  destinations:
    - host: grafana.lab.example.com
      ports: [443]
      protocol: tcp
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: wiki }
spec:
  connectorGroup: homelab
  destinations:
    - host: wiki.lab.example.com
      ports: [443]
      protocol: tcp
---
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata: { name: base }
spec:
  rules:
    - name: admins-grafana
      who: { groups: ["local:admins"] }
      what: { apps: [grafana] }
      when:
        auth: { maxAge: 1h, mfa: true }
    - name: ops-wiki
      who: { groups: ["local:ops"] }
      what: { apps: [wiki] }
"#;

const PASSWORD: &str = "correct horse battery staple";

struct Deployment {
    dir: TempDir,
    cp: ControlPlane,
    audit: Arc<Mutex<Vec<u8>>>,
    base: String,
    bundle: String,
    idp: Option<RunningIdp>,
}

impl Deployment {
    /// A deployment with built-in accounts only, and a bootstrap admin when
    /// `admin_password` is given.
    async fn local(admin_password: Option<&str>) -> Deployment {
        let dir = TempDir::new("accounts");
        let mut extra = String::new();
        if let Some(password) = admin_password {
            write(&dir.path().join("admin-password"), &format!("{password}\n"));
            extra = format!(
                "localAccounts:\n  bootstrapAdmin:\n    passwordFile: {}/admin-password\n",
                dir.path().display()
            );
        }
        Deployment::start(dir, &extra, None, |_| {}).await
    }

    async fn start(
        dir: TempDir,
        extra: &str,
        idp: Option<RunningIdp>,
        adjust: impl FnOnce(&mut Config),
    ) -> Deployment {
        if !dir.path().join("policy/base.yaml").exists() {
            write(&dir.path().join("policy/base.yaml"), POLICY);
        }
        let port = free_port();
        let mut config = Config::parse(&format!(
            "trustDomain: example.test\n\
             publicUrl: https://localhost:{port}\n\
             listen: 127.0.0.1:{port}\n\
             dataDir: {d}/data\n\
             policyDir: {d}/policy\n\
             devices:\n  approval: automatic\n{extra}",
            d = dir.path().display(),
        ))
        .unwrap();
        adjust(&mut config);
        let audit = Arc::new(Mutex::new(Vec::new()));
        let cp = ControlPlane::start_with_audit(config, Some(audit::Sink::memory(audit.clone())))
            .await
            .unwrap();
        let bundle = cp.app().authority.trust_bundle();
        Deployment {
            base: format!("https://localhost:{port}"),
            dir,
            cp,
            audit,
            bundle,
            idp,
        }
    }

    fn client(&self) -> TestClient {
        let idp_ca = self
            .idp
            .as_ref()
            .map(|i| i.pki.ca_pem.clone())
            .unwrap_or_else(|| self.bundle.clone());
        TestClient::new(&self.base, &self.bundle, &idp_ca)
    }

    fn browser(&self) -> Browser {
        let mut roots = self.bundle.clone();
        if let Some(idp) = &self.idp {
            roots.push_str(&idp.pki.ca_pem);
        }
        Browser {
            base: self.base.clone(),
            http: Client::new(Client::roots_from_pem(&roots).unwrap(), None).unwrap(),
            cookie: None,
            referrer_policy: None,
        }
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

    fn audit_messages(&self) -> Vec<String> {
        let text = String::from_utf8(self.audit.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .map(|r| r["message"].as_str().unwrap_or("").to_owned())
            .collect()
    }

    async fn user(&self, username: &str) -> Value {
        let (_, users) = self.admin("GET", "/v1/admin/users", None).await;
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["local"]["username"] == username || u["subject"] == username)
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// Creates a built-in account and sets its password with the setup link.
    async fn create(&self, username: &str, groups: &[&str]) -> String {
        let (status, created) = self
            .admin(
                "POST",
                "/v1/admin/users",
                Some(json!({ "username": username, "email": format!("{username}@example.com"), "groups": groups })),
            )
            .await;
        assert_eq!(status, 201, "{created}");
        let mut b = self.browser();
        set_password(&mut b, created["setup_url"].as_str().unwrap(), PASSWORD).await;
        created["user"]["id"].as_str().unwrap().to_owned()
    }

    async fn connector(&self) -> StubNode {
        let (status, token) = self
            .admin(
                "POST",
                "/v1/admin/join-tokens",
                Some(json!({ "role": "connector", "group": "homelab", "name": "lab-1" })),
            )
            .await;
        assert_eq!(status, 201, "{token}");
        StubNode::join(&self.base, token["token"].as_str().unwrap())
            .await
            .unwrap()
    }
}

/// A scripted browser that keeps the sign-in cookie and posts forms the
/// way a browser does: with the Origin the last page's Referrer-Policy
/// allows (`null` under `no-referrer`, per the Fetch spec).
struct Browser {
    base: String,
    http: Client,
    cookie: Option<String>,
    referrer_policy: Option<String>,
}

impl Browser {
    fn url(&self, path: &str) -> String {
        if path.starts_with("https://") {
            path.to_owned()
        } else {
            format!("{}{path}", self.base)
        }
    }

    fn keep_cookie(&mut self, reply: &Reply) {
        if let Some(v) = reply.headers.get("set-cookie") {
            let pair = v.to_str().unwrap().split(';').next().unwrap().to_owned();
            self.cookie = Some(pair);
        }
        if let Some(v) = reply.headers.get("referrer-policy") {
            self.referrer_policy = Some(v.to_str().unwrap().to_owned());
        }
    }

    async fn get(&mut self, path: &str) -> Reply {
        let url = self.url(path);
        let mut headers = Vec::new();
        if url.starts_with(&self.base)
            && let Some(c) = &self.cookie
        {
            headers.push(("cookie", c.as_str()));
        }
        let reply = self
            .http
            .request(Method::GET, &url, &headers, None)
            .await
            .unwrap();
        self.keep_cookie(&reply);
        reply
    }

    async fn post(&mut self, path: &str, fields: &[(&str, &str)]) -> Reply {
        let origin = match self.referrer_policy.as_deref() {
            Some("no-referrer") => "null".to_owned(),
            _ => self.base.clone(),
        };
        self.post_from(path, fields, &origin).await
    }

    async fn post_from(&mut self, path: &str, fields: &[(&str, &str)], origin: &str) -> Reply {
        let body = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            for (k, v) in fields {
                form.append_pair(k, v);
            }
            form.finish()
        };
        let mut headers = vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("origin", origin),
        ];
        let cookie = self.cookie.clone();
        if let Some(c) = &cookie {
            headers.push(("cookie", c.as_str()));
        }
        let reply = self
            .http
            .request(
                Method::POST,
                &self.url(path),
                &headers,
                Some(Bytes::from(body)),
            )
            .await
            .unwrap();
        self.keep_cookie(&reply);
        reply
    }
}

fn text(reply: &Reply) -> String {
    String::from_utf8_lossy(&reply.body).into_owned()
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

/// The authenticator key shown on the enrollment page, decoded.
fn enrollment_secret(page: &str) -> Vec<u8> {
    let start = page
        .find("<code class=\"key\">")
        .expect("an enrollment page")
        + 18;
    let key: String = page[start..]
        .split('<')
        .next()
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in key.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32: {key}"),
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

fn location(reply: &Reply) -> String {
    assert!(
        reply.status.is_redirection(),
        "{}: {}",
        reply.status,
        text(reply)
    );
    reply.headers["location"].to_str().unwrap().to_owned()
}

fn query_of(url: &str) -> HashMap<String, String> {
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    form_urlencoded::parse(q.as_bytes()).into_owned().collect()
}

/// Starts a sign-in as the warren app does. Returns the browser, the
/// first reply and the PKCE verifier.
async fn begin(d: &Deployment, extra: &[(&str, &str)]) -> (Browser, Reply, String) {
    let verifier = b64url(&random_bytes::<32>().unwrap());
    let mut q = form_urlencoded::Serializer::new(String::new());
    q.append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("code_challenge", &b64url(&sha256(verifier.as_bytes())))
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", "app-state");
    for (k, v) in extra {
        q.append_pair(k, v);
    }
    let mut b = d.browser();
    let reply = b.get(&format!("/v1/auth/authorize?{}", q.finish())).await;
    (b, reply, verifier)
}

/// The end of a sign-in: the redirect back to the app, exchanged for a
/// session by `client`.
async fn finish(client: &mut TestClient, reply: &Reply, verifier: &str) -> Session {
    let back = location(reply);
    assert!(back.starts_with(REDIRECT_URI), "{back}");
    let q = query_of(&back);
    assert_eq!(q["state"], "app-state");
    let code = q.get("code").unwrap_or_else(|| panic!("no code: {back}"));
    let reply = client.exchange(code, verifier).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", text(&reply));
    client.session.clone().unwrap()
}

/// Signs in with a password and a code, enrolling an authenticator first
/// if the account has none. Returns the session and the authenticator
/// secret, and the recovery codes when it enrolled.
async fn sign_in(
    d: &Deployment,
    client: &mut TestClient,
    username: &str,
    secret: Option<(&[u8], i64)>,
) -> (Session, Vec<u8>, Vec<String>) {
    let (mut b, page, verifier) = begin(d, &[]).await;
    let flow = field(&text(&page), "flow");
    let reply = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", username),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", text(&reply));
    match secret {
        Some((secret, step)) => {
            assert!(text(&reply).contains("Enter your authenticator code"));
            let reply = b
                .post(
                    "/v1/auth/code",
                    &[("flow", &flow), ("code", &code_at(secret, step))],
                )
                .await;
            (
                finish(client, &reply, &verifier).await,
                secret.to_vec(),
                vec![],
            )
        }
        None => {
            let secret = enrollment_secret(&text(&reply));
            let step = totp_step(clock::now_secs());
            let reply = b
                .post(
                    "/v1/auth/code",
                    &[("flow", &flow), ("code", &code_at(&secret, step))],
                )
                .await;
            let page = text(&reply);
            assert!(page.contains("Save your recovery codes"), "{page}");
            let codes: Vec<String> = page
                .split("<li>")
                .skip(1)
                .map(|c| c.split('<').next().unwrap().to_owned())
                .collect();
            let reply = b.post("/v1/auth/continue", &[("flow", &flow)]).await;
            (finish(client, &reply, &verifier).await, secret, codes)
        }
    }
}

async fn set_password(b: &mut Browser, setup_url: &str, password: &str) {
    let page = b.get(setup_url).await;
    assert_eq!(page.status, StatusCode::OK, "{}", text(&page));
    let token = field(&text(&page), "token");
    let reply = b
        .post(
            "/v1/auth/setup",
            &[
                ("token", &token),
                ("password", password),
                ("confirm", password),
            ],
        )
        .await;
    assert!(
        text(&reply).contains("Your password is set"),
        "{}",
        text(&reply)
    );
}

async fn next_event(
    rx: &mut mpsc::UnboundedReceiver<support::Received>,
    want: impl Fn(&EventBody) -> bool,
) -> support::Received {
    let deadline = Instant::now() + REVOCATION_DEADLINE;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let received = tokio::time::timeout(left, rx.recv())
            .await
            .expect("the event did not arrive within the revocation deadline")
            .expect("the event stream ended");
        if let Line::Event(e) = &received.line
            && want(&e.body)
        {
            return received;
        }
    }
}

async fn wait_for_bundle(node: &StubNode, want: impl Fn(&Bundle) -> bool) -> Bundle {
    let key = node.policy_key.to_key().unwrap();
    let deadline = Instant::now() + REVOCATION_DEADLINE;
    loop {
        let jws = String::from_utf8(node.get("/v1/node/bundle").await.body.to_vec()).unwrap();
        let bundle = Bundle::verify(&jws, &key, "example.test", View::Connector, None).unwrap();
        if want(&bundle) {
            return bundle;
        }
        assert!(
            Instant::now() < deadline,
            "no such bundle within the deadline"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn entity_groups(bundle: &Bundle, user_id: &str) -> Option<Vec<String>> {
    bundle
        .entities
        .as_ref()
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["uid"]["id"] == user_id)
        .map(|e| {
            e["parents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["id"].as_str().unwrap().to_owned())
                .collect()
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bootstrap_admin_signs_in_with_a_password_and_an_authenticator() {
    let d = Deployment::local(Some(PASSWORD)).await;
    assert!(
        d.audit_messages()
            .iter()
            .any(|m| m == "bootstrap admin created from the mounted password file")
    );
    let admin = d.user("admin").await;
    assert_eq!(admin["issuer"], "local");
    assert_eq!(admin["groups"], json!(["local:admins"]));
    assert_eq!(admin["local"]["password_set"], true);
    assert_eq!(admin["local"]["authenticator"], false);

    // Without an IdP, sign-in opens on the password form, bound to this
    // browser by a cookie.
    let (mut b, page, verifier) = begin(&d, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let html = text(&page);
    assert!(
        html.contains("Sign in to warren") && !html.contains("Sign in with"),
        "{html}"
    );
    let csp = page.headers["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"),
        "{csp}"
    );
    assert!(
        page.headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("__Host-warren-signin=")
    );
    let flow = field(&html, "flow");

    // A wrong password, and an unknown username, read the same.
    let wrong = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", "admin"),
                ("password", "not the password"),
            ],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(text(&wrong).contains("The username or password is incorrect"));
    let unknown = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", "nobody"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert!(text(&unknown).contains("The username or password is incorrect"));

    // The same form from another site, or from a browser without the
    // cookie, gets nowhere.
    let foreign = b
        .post_from(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", "admin"),
                ("password", PASSWORD),
            ],
            "https://evil.example",
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    let mut stranger = d.browser();
    let stolen = stranger
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", "admin"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert!(text(&stolen).contains("This sign-in has expired"));

    // The right password leads to enrolling an authenticator: a password
    // alone never signs in.
    let reply = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", "Admin "),
                ("password", PASSWORD),
            ],
        )
        .await;
    let html = text(&reply);
    assert!(html.contains("Set up an authenticator app"), "{html}");
    assert!(html.contains("<svg"), "a QR code");
    let secret = enrollment_secret(&html);
    assert_eq!(secret.len(), 20);
    // The password step cannot be replayed.
    let again = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", "admin"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert!(text(&again).contains("This sign-in has expired"));
    let bad = b
        .post("/v1/auth/code", &[("flow", &flow), ("code", "000000")])
        .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(text(&bad).contains("did not match"));
    let step = totp_step(clock::now_secs());
    let reply = b
        .post(
            "/v1/auth/code",
            &[("flow", &flow), ("code", &code_at(&secret, step))],
        )
        .await;
    let html = text(&reply);
    assert!(html.contains("Save your recovery codes"), "{html}");
    let codes: Vec<String> = html
        .split("<li>")
        .skip(1)
        .map(|c| c.split('<').next().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    let reply = b.post("/v1/auth/continue", &[("flow", &flow)]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let mut client = d.client();
    let session = finish(&mut client, &reply, &verifier).await;
    assert!(session.mfa);
    assert!((session.auth_time - clock::now_secs()).abs() <= 5);
    assert_eq!(session.user.groups, ["local:admins"]);
    // Policy names the admin as local:admins, with a freshness rule.
    let apps: Vec<String> = client
        .entitlements()
        .await
        .apps
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert_eq!(apps, ["grafana"]);
    let admin = d.user("admin").await;
    assert_eq!(admin["local"]["authenticator"], true);
    assert_eq!(admin["local"]["recovery_codes"], 10);

    // Next time: the password, then a code. A code is accepted once.
    let (mut b, page, verifier) = begin(&d, &[("prompt", "login")]).await;
    let flow = field(&text(&page), "flow");
    let reply = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", "admin"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert!(text(&reply).contains("Enter your authenticator code"));
    let replayed = b
        .post(
            "/v1/auth/code",
            &[("flow", &flow), ("code", &code_at(&secret, step))],
        )
        .await;
    assert_eq!(replayed.status, StatusCode::UNAUTHORIZED);
    let reply = b
        .post(
            "/v1/auth/code",
            &[("flow", &flow), ("code", &code_at(&secret, step + 1))],
        )
        .await;
    let mut client = d.client();
    assert!(finish(&mut client, &reply, &verifier).await.mfa);

    // A recovery code works once, however it is typed.
    let typed = format!(" {} ", codes[0].to_ascii_uppercase());
    let (mut b, page, verifier) = begin(&d, &[]).await;
    let flow = field(&text(&page), "flow");
    b.post(
        "/v1/auth/password",
        &[
            ("flow", &flow),
            ("username", "admin"),
            ("password", PASSWORD),
        ],
    )
    .await;
    let reply = b
        .post("/v1/auth/code", &[("flow", &flow), ("code", &typed)])
        .await;
    let mut client = d.client();
    assert!(finish(&mut client, &reply, &verifier).await.mfa);
    let (mut b, page, _) = begin(&d, &[]).await;
    let flow = field(&text(&page), "flow");
    b.post(
        "/v1/auth/password",
        &[
            ("flow", &flow),
            ("username", "admin"),
            ("password", PASSWORD),
        ],
    )
    .await;
    let reused = b
        .post("/v1/auth/code", &[("flow", &flow), ("code", &typed)])
        .await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(d.user("admin").await["local"]["recovery_codes"], 9);

    let messages = d.audit_messages();
    for m in [
        "authenticator app enrolled, with new recovery codes",
        "signed in with a built-in account",
        "recovery code used",
        "sign-in refused: wrong password",
        "sign-in refused: unknown username",
        "sign-in refused: wrong authenticator or recovery code",
    ] {
        assert!(messages.iter().any(|x| x == m), "no audit record {m:?}");
    }
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_links_lockout_and_resets() {
    let d = Deployment::local(None).await;
    let (status, created) = d
        .admin(
            "POST",
            "/v1/admin/users",
            Some(json!({ "username": "ada", "email": "Ada@Example.com", "display_name": "Ada", "groups": ["local:ops"] })),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["user"]["groups"], json!(["local:ops"]));
    assert_eq!(created["user"]["email"], "ada@example.com");
    let setup_url = created["setup_url"].as_str().unwrap().to_owned();
    assert!(setup_url.starts_with(&format!("{}/v1/auth/setup?token=", d.base)));
    let (status, _) = d
        .admin(
            "POST",
            "/v1/admin/users",
            Some(json!({ "username": "ada" })),
        )
        .await;
    assert_eq!(status, 409, "usernames are unique");
    let (status, _) = d
        .admin(
            "POST",
            "/v1/admin/users",
            Some(json!({ "username": "Ada Lovelace" })),
        )
        .await;
    assert_eq!(status, 400);

    // Before the setup link is used, nothing signs in.
    let (mut b, page, _) = begin(&d, &[]).await;
    let flow = field(&text(&page), "flow");
    let reply = b
        .post(
            "/v1/auth/password",
            &[("flow", &flow), ("username", "ada"), ("password", "")],
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    // The setup link checks the new password and works once.
    let mut b = d.browser();
    let page = text(&b.get(&setup_url).await);
    assert!(page.contains("ada"), "{page}");
    let token = field(&page, "token");
    let reply = b
        .post(
            "/v1/auth/setup",
            &[
                ("token", &token),
                ("password", PASSWORD),
                ("confirm", "something else"),
            ],
        )
        .await;
    assert!(text(&reply).contains("different"));
    let reply = b
        .post(
            "/v1/auth/setup",
            &[
                ("token", &token),
                ("password", "short"),
                ("confirm", "short"),
            ],
        )
        .await;
    assert!(text(&reply).contains("at least 12"));
    let reply = b
        .post(
            "/v1/auth/setup",
            &[
                ("token", &token),
                ("password", PASSWORD),
                ("confirm", PASSWORD),
            ],
        )
        .await;
    assert!(text(&reply).contains("Your password is set"));
    assert!(text(&b.get(&setup_url).await).contains("expired"));

    // Five wrong passwords in a row lock the account, even against the
    // right one, until an admin unlocks it. The page never says so.
    let (mut b, page, _) = begin(&d, &[]).await;
    let flow = field(&text(&page), "flow");
    for _ in 0..5 {
        let reply = b
            .post(
                "/v1/auth/password",
                &[
                    ("flow", &flow),
                    ("username", "ada"),
                    ("password", "wrong password!"),
                ],
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let reply = b
        .post(
            "/v1/auth/password",
            &[("flow", &flow), ("username", "ada"), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(text(&reply).contains("The username or password is incorrect"));
    assert!(d.user("ada").await["local"]["locked_until"].is_i64());
    let (status, body) = d.admin("POST", "/v1/admin/users/ada/unlock", None).await;
    assert_eq!((status, body["changed"].clone()), (200, json!(true)));
    let mut client = d.client();
    let (session, secret, _) = sign_in(&d, &mut client, "ada", None).await;
    assert_eq!(session.user.groups, ["local:ops"]);

    // A reset clears the password and the authenticator, revokes the
    // session, and hands out a new setup link.
    let (status, reset) = d
        .admin("POST", "/v1/admin/users/local:ada/reset", None)
        .await;
    assert_eq!(status, 200, "{reset}");
    assert_eq!(reset["sessions_revoked"], 1);
    let reply = client.get("/v1/entitlements").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    let ada = d.user("ada").await;
    assert_eq!(ada["local"]["password_set"], false);
    assert_eq!(ada["local"]["authenticator"], false);
    let mut b = d.browser();
    set_password(&mut b, reset["setup_url"].as_str().unwrap(), PASSWORD).await;
    let mut client = d.client();
    let (_, new_secret, _) = sign_in(&d, &mut client, "ada", None).await;
    assert_ne!(secret, new_secret, "a new authenticator");

    // Accounts of the IdP cannot be given built-in credentials, and
    // deletion is for built-in accounts.
    let (status, _) = d.admin("POST", "/v1/admin/users/nobody/reset", None).await;
    assert_eq!(status, 404);

    // Too many failures from one source are refused for a while.
    let (mut b, page, _) = begin(&d, &[]).await;
    let flow = field(&text(&page), "flow");
    let mut refused = false;
    for _ in 0..30 {
        let reply = b
            .post(
                "/v1/auth/password",
                &[("flow", &flow), ("username", "nobody"), ("password", "x")],
            )
            .await;
        if reply.status == StatusCode::TOO_MANY_REQUESTS {
            refused = true;
            break;
        }
    }
    assert!(refused, "the source limit never applied");
    let messages = d.audit_messages();
    for m in [
        "built-in account created",
        "password set with a setup link",
        "built-in account locked after too many failed sign-ins",
        "built-in account unlocked",
    ] {
        assert!(messages.iter().any(|x| x == m), "no audit record {m:?}");
    }
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("built-in account credentials reset"))
    );
    d.cp.shutdown().await;
}

/// A password attempt in a sign-in of its own: the status and the page,
/// without what differs between any two sign-ins (the flow and the
/// username typed back).
async fn attempt(d: &Deployment, username: &str, password: &str) -> (StatusCode, String) {
    let (mut b, page, _) = begin(d, &[]).await;
    let flow = field(&text(&page), "flow");
    let reply = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("username", username),
                ("password", password),
            ],
        )
        .await;
    let page = text(&reply)
        .replace(&flow, "")
        .replace(&format!("value=\"{username}\""), "");
    (reply.status, page)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_and_locked_usernames_look_the_same() {
    let d = Deployment::local(None).await;
    d.create("ada", &[]).await;
    let first = attempt(&d, "nobody", "wrong password!").await;
    assert_eq!(first.0, StatusCode::UNAUTHORIZED);
    assert!(
        first.1.contains("The username or password is incorrect"),
        "{}",
        first.1
    );
    for _ in 0..4 {
        assert_eq!(attempt(&d, "ada", "wrong password!").await, first);
        assert_eq!(attempt(&d, "nobody", "wrong password!").await, first);
    }
    assert_eq!(attempt(&d, "ada", "wrong password!").await, first);
    // Locked, even against the right password, yet it reads exactly like
    // an unknown username, which is locked out the same way.
    assert!(d.user("ada").await["local"]["locked_until"].is_i64());
    assert_eq!(attempt(&d, "ada", PASSWORD).await, first);
    assert_eq!(attempt(&d, "nobody", PASSWORD).await, first);
    assert_eq!(attempt(&d, "nobody-else", PASSWORD).await, first);
    // Only the audit log tells them apart.
    let messages = d.audit_messages();
    for m in [
        "sign-in refused: unknown username",
        "sign-in refused: wrong password",
        "sign-in refused: the username is locked after too many failed sign-ins",
        "built-in account locked after too many failed sign-ins",
    ] {
        assert!(messages.iter().any(|x| x == m), "no audit record {m:?}");
    }
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_disabled_account_looks_like_a_wrong_password() {
    let d = Deployment::local(None).await;
    d.create("ada", &[]).await;
    let wrong = attempt(&d, "ada", "wrong password!").await;
    assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
    let (status, _) = d.admin("POST", "/v1/admin/users/ada/disable", None).await;
    assert_eq!(status, 200);
    // The right password is not confirmed for a disabled account.
    assert_eq!(attempt(&d, "ada", PASSWORD).await, wrong);
    assert!(
        d.audit_messages()
            .iter()
            .any(|m| m == "sign-in refused: the user is disabled")
    );
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_guesses_cannot_outrun_the_lockout() {
    let d = Deployment::local(None).await;
    d.create("ada", &[]).await;
    let mut flows = Vec::new();
    for _ in 0..12 {
        let (b, page, _) = begin(&d, &[]).await;
        flows.push((b, field(&text(&page), "flow")));
    }
    let guesses: Vec<_> = flows
        .into_iter()
        .map(|(mut b, flow)| {
            tokio::spawn(async move {
                b.post(
                    "/v1/auth/password",
                    &[
                        ("flow", &flow),
                        ("username", "ada"),
                        ("password", "wrong password!"),
                    ],
                )
                .await
                .status
            })
        })
        .collect();
    for guess in guesses {
        assert_eq!(guess.await.unwrap(), StatusCode::UNAUTHORIZED);
    }
    let messages = d.audit_messages();
    let checked = messages
        .iter()
        .filter(|m| *m == "sign-in refused: wrong password")
        .count();
    assert_eq!(checked, 5, "only five guesses were checked");
    assert_eq!(
        messages
            .iter()
            .filter(
                |m| *m == "sign-in refused: the username is locked after too many failed sign-ins"
            )
            .count(),
        7
    );
    assert!(d.user("ada").await["local"]["locked_until"].is_i64());
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_ends_sign_ins_in_progress() {
    let d = Deployment::local(None).await;
    d.create("ada", &[]).await;
    // Whoever set the password has reached the authenticator enrollment.
    let (mut b, page, _) = begin(&d, &[]).await;
    let flow = field(&text(&page), "flow");
    let reply = b
        .post(
            "/v1/auth/password",
            &[("flow", &flow), ("username", "ada"), ("password", PASSWORD)],
        )
        .await;
    let secret = enrollment_secret(&text(&reply));
    let (status, _) = d.admin("POST", "/v1/admin/users/ada/reset", None).await;
    assert_eq!(status, 200);
    // After the reset, that sign-in neither enrolls nor finishes.
    let code = code_at(&secret, totp_step(clock::now_secs()));
    let reply = b
        .post("/v1/auth/code", &[("flow", &flow), ("code", &code)])
        .await;
    assert!(text(&reply).contains("This sign-in has expired"));
    let ada = d.user("ada").await;
    assert_eq!(ada["local"]["authenticator"], false);
    assert_eq!(ada["local"]["password_set"], false);
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offboarding_reaches_connectors_within_the_deadline() {
    let d = Deployment::local(None).await;
    let ada = d.create("ada", &["ops"]).await;
    let mut client = d.client();
    sign_in(&d, &mut client, "ada", None).await;
    assert_eq!(client.entitlements().await.apps[0].name, "wiki");
    let connector = d.connector().await;
    let bundle = wait_for_bundle(&connector, |b| entity_groups(b, &ada).is_some()).await;
    assert_eq!(entity_groups(&bundle, &ada).unwrap(), ["local:ops"]);
    let mut events = connector.events(None).await;
    events.recv().await.unwrap();

    // Leaving a group ships as a new bundle without it.
    let started = Instant::now();
    let (status, _) = d
        .admin(
            "PUT",
            "/v1/admin/users/ada/groups",
            Some(json!({ "groups": [] })),
        )
        .await;
    assert_eq!(status, 200);
    let received = next_event(&mut events, |b| {
        matches!(b, EventBody::BundleUpdated { .. })
    })
    .await;
    assert!(received.at.duration_since(started) < REVOCATION_DEADLINE);
    let bundle = wait_for_bundle(&connector, |b| {
        entity_groups(b, &ada).is_some_and(|g| g.is_empty())
    })
    .await;
    assert!(!bundle.revocations.users.contains(&ada));
    assert!(client.entitlements().await.apps.is_empty());

    // Disabling cuts the session and reaches the connector in time.
    let started = Instant::now();
    d.admin("POST", "/v1/admin/users/ada/disable", None).await;
    let received = next_event(
        &mut events,
        |b| matches!(b, EventBody::UserDisabled { user_id } if *user_id == ada),
    )
    .await;
    assert!(received.at.duration_since(started) < REVOCATION_DEADLINE);
    let reply = client.get("/v1/entitlements").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let problem: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(problem["reason"], "user_disabled");

    // Deleting a live account does the same, keeps its revocation in the
    // bundle, and frees the username.
    let bob = d.create("bob", &["ops"]).await;
    let mut bob_client = d.client();
    sign_in(&d, &mut bob_client, "bob", None).await;
    let started = Instant::now();
    let (status, body) = d.admin("DELETE", "/v1/admin/users/bob", None).await;
    assert_eq!(
        (status, body["changed"].clone()),
        (200, json!(true)),
        "{body}"
    );
    let received = next_event(
        &mut events,
        |b| matches!(b, EventBody::UserDisabled { user_id } if *user_id == bob),
    )
    .await;
    assert!(received.at.duration_since(started) < REVOCATION_DEADLINE);
    assert_eq!(
        bob_client.get("/v1/entitlements").await.status,
        StatusCode::FORBIDDEN
    );
    let bundle = wait_for_bundle(&connector, |b| b.revocations.users.contains(&bob)).await;
    assert!(entity_groups(&bundle, &bob).is_none());
    assert!(
        d.user("bob").await.is_null(),
        "deleted accounts are not listed"
    );
    let again = d.create("bob", &[]).await;
    assert_ne!(again, bob);

    // Accounts and groups declared in the policy directory are created,
    // owned there, and deleted when they leave it, with their revocation.
    write(
        &d.dir.path().join("policy/people.yaml"),
        "apiVersion: warren.dev/v1alpha1\nkind: LocalUser\nmetadata: { name: carol }\nspec:\n  email: carol@example.com\n---\napiVersion: warren.dev/v1alpha1\nkind: LocalGroup\nmetadata: { name: ops }\nspec:\n  members:\n    users: [carol, ghost]\n",
    );
    let (status, policy) = d.admin("POST", "/v1/admin/policy/reload", None).await;
    assert_eq!(status, 200, "{policy}");
    assert!(
        policy["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("ghost")),
        "{policy}"
    );
    let carol = d.user("carol").await;
    assert_eq!(carol["local"]["managed_by"], "config");
    assert_eq!(carol["local"]["password_set"], false);
    assert_eq!(carol["groups"], json!(["local:ops"]));
    let carol_id = carol["id"].as_str().unwrap().to_owned();
    let (status, _) = d.admin("DELETE", "/v1/admin/users/carol", None).await;
    assert_eq!(status, 409, "managed in the policy directory");
    let (status, _) = d
        .admin(
            "PUT",
            "/v1/admin/users/bob/groups",
            Some(json!({ "groups": ["ops"] })),
        )
        .await;
    assert_eq!(status, 409, "ops belongs to the policy directory");
    // An admin gets a config account going with a setup link.
    let (status, reset) = d.admin("POST", "/v1/admin/users/carol/reset", None).await;
    assert_eq!(status, 200);
    assert!(reset["setup_url"].as_str().is_some());
    let (_, groups) = d.admin("GET", "/v1/admin/groups", None).await;
    let ops = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "ops")
        .unwrap();
    assert_eq!(ops["managed_by"], "config");
    assert_eq!(ops["policy_name"], "local:ops");

    std::fs::remove_file(d.dir.path().join("policy/people.yaml")).unwrap();
    let started = Instant::now();
    let (status, _) = d.admin("POST", "/v1/admin/policy/reload", None).await;
    assert_eq!(status, 200);
    let received = next_event(
        &mut events,
        |b| matches!(b, EventBody::UserDisabled { user_id } if *user_id == carol_id),
    )
    .await;
    assert!(received.at.duration_since(started) < REVOCATION_DEADLINE);
    assert!(d.user("carol").await.is_null());
    let messages = d.audit_messages();
    for m in [
        "built-in account created from the policy directory",
        "built-in account deleted: it left the policy directory",
        "built-in account deleted",
        "local group memberships set",
    ] {
        assert!(messages.iter().any(|x| x == m), "no audit record {m:?}");
    }
    d.cp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bootstrap_admin_is_created_once() {
    let dir = TempDir::new("bootstrap");
    write(&dir.path().join("admin-password"), "too short\n");
    let extra = format!(
        "localAccounts:\n  bootstrapAdmin:\n    username: root\n    passwordFile: {}/admin-password\n    groups: [admins, ops]\n",
        dir.path().display()
    );
    let config_text = |port: u16| {
        format!(
            "trustDomain: example.test\npublicUrl: https://localhost:{port}\nlisten: 127.0.0.1:{port}\ndataDir: {d}/data\npolicyDir: {d}/policy\n{extra}",
            d = dir.path().display()
        )
    };
    write(&dir.path().join("policy/base.yaml"), POLICY);
    let err = ControlPlane::start(Config::parse(&config_text(free_port())).unwrap())
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("at least 12"), "{err}");

    write(
        &dir.path().join("admin-password"),
        &format!("{PASSWORD}\r\n"),
    );
    let config = Config::parse(&config_text(free_port())).unwrap();
    let cp = ControlPlane::start(config.clone()).await.unwrap();
    let store = &cp.app().store;
    let root = store.local_account_named("root").await.unwrap().unwrap();
    assert!(warren_control::accounts::verify_password(
        root.password_hash.as_deref().unwrap(),
        PASSWORD
    ));
    let user = store.user(&root.user_id).await.unwrap().unwrap();
    assert_eq!(user.groups, ["local:admins", "local:ops"]);
    store.delete_local_user(&root.user_id).await.unwrap();
    cp.shutdown().await;

    // The file is never read again: deleting the admin is final.
    let cp = ControlPlane::start(config).await.unwrap();
    assert!(
        cp.app()
            .store
            .local_account_named("root")
            .await
            .unwrap()
            .is_none()
    );
    cp.shutdown().await;
}

/// A provider that issues tokens the way Google does: issuer without a
/// scheme, `hd` for Workspace accounts, no groups, no `amr`, no
/// `auth_time`.
async fn google_like(sub: &str, email: &str, hd: Option<&str>) -> RunningIdp {
    let idp = RunningIdp::start(IdpUser {
        sub: sub.into(),
        email: email.into(),
        groups: vec!["admins".into()],
        amr: vec![],
    })
    .await;
    google_claims(&idp, hd);
    idp
}

fn google_claims(idp: &RunningIdp, hd: Option<&str>) {
    let mut patch = idp.idp.claims_patch.lock().unwrap();
    patch.clear();
    patch.insert(
        "iss".into(),
        json!(idp.idp.issuer.trim_start_matches("https://")),
    );
    patch.insert("azp".into(), json!("warren"));
    patch.insert("hd".into(), hd.map_or(Value::Null, |h| json!(h)));
    patch.insert("groups".into(), Value::Null);
    patch.insert("amr".into(), Value::Null);
    patch.insert("auth_time".into(), Value::Null);
}

fn set_user(idp: &RunningIdp, sub: &str, email: &str) {
    let mut user = idp.idp.user.lock().unwrap();
    user.sub = sub.into();
    user.email = email.into();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_google_preset() {
    let idp = google_like(
        "110169484474386276334",
        "ada@example.com",
        Some("example.com"),
    )
    .await;
    let dir = TempDir::new("google");
    write(&dir.path().join("idp-ca.pem"), &idp.pki.ca_pem);
    write(&dir.path().join("google-secret"), "s3cret\n");
    let extra = format!(
        "idp:\n  type: google\n  clientId: warren\n  clientSecretFile: {d}/google-secret\n  hostedDomain: example.com\n  allowedEmails: [contractor@gmail.com]\n",
        d = dir.path().display()
    );
    let (issuer, ca) = (idp.idp.issuer.clone(), dir.path().join("idp-ca.pem"));
    // Only the location of the preset endpoints changes, to reach the
    // stand-in for Google.
    let d = Deployment::start(dir, &extra, Some(idp), move |c| {
        let g = c.idp.as_mut().unwrap();
        g.endpoints = Some(Endpoints {
            authorization: format!("{issuer}/authorize"),
            token: format!("{issuer}/token"),
            jwks: format!("{issuer}/jwks"),
        });
        g.issuer_aliases = vec![issuer.trim_start_matches("https://").into()];
        g.issuer = issuer;
        g.ca_file = Some(ca);
    })
    .await;
    let idp = d.idp.as_ref().unwrap();

    // Google carries no groups: warren's own come from a LocalGroup that
    // lists a verified email, bound to the first account that signs in
    // with it.
    write(
        &d.dir.path().join("policy/groups.yaml"),
        "apiVersion: warren.dev/v1alpha1\nkind: LocalGroup\nmetadata: { name: admins }\nspec:\n  members:\n    emails: [Ada@Example.com]\n",
    );
    let (status, policy) = d.admin("POST", "/v1/admin/policy/reload", None).await;
    assert_eq!(status, 200, "{policy}");
    let (_, groups) = d.admin("GET", "/v1/admin/groups", None).await;
    assert_eq!(
        groups[0]["invites"][0]["email"], "ada@example.com",
        "{groups}"
    );

    // With no built-in accounts, sign-in goes straight to Google, asking
    // for what Google supports.
    let mut client = d.client();
    let q = client.browser_sign_in_with(&[("prompt", "login")]).await;
    let session = finish_code(&mut client, &q).await;
    let asked = idp
        .idp
        .authorize_requests
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(asked["scope"], "openid email profile");
    assert_eq!(asked["hd"], "example.com");
    assert_eq!(asked["prompt"], "select_account");
    assert!(!asked.contains_key("max_age"));
    assert_eq!(session.user.groups, ["local:admins"]);
    assert_eq!(session.user.email.as_deref(), Some("ada@example.com"));
    assert!(!session.mfa);
    assert_eq!(
        session.auth_time, 0,
        "Google reports no authentication time"
    );
    // The freshness rule on grafana cannot be met by a Google sign-in, but
    // the app is still listed: entitlements name apps, rules decide flows.
    assert_eq!(client.entitlements().await.apps[0].name, "grafana");
    let (_, groups) = d.admin("GET", "/v1/admin/groups", None).await;
    assert_eq!(groups[0]["invites"], json!([]), "{groups}");
    assert_eq!(groups[0]["members"][0]["invited_email"], "ada@example.com");
    assert_eq!(groups[0]["members"][0]["managed_by"], "config");

    // Another account later holding the same email gets nothing.
    set_user(idp, "222", "ada@example.com");
    let mut other = d.client();
    let q = other.browser_sign_in().await;
    assert!(finish_code(&mut other, &q).await.user.groups.is_empty());

    // Only accounts of the hosted domain, by the hd claim, or on the
    // allowed list may sign in, and only with a verified email.
    set_user(idp, "333", "eve@other.example");
    google_claims(idp, Some("other.example"));
    let back = d.client().browser_sign_in().await;
    assert_eq!(back["error"], "access_denied");
    assert!(
        back["error_description"].contains("Use your example.com account"),
        "{back:?}"
    );
    set_user(idp, "444", "contractor@gmail.com");
    google_claims(idp, None);
    let mut contractor = d.client();
    let q = contractor.browser_sign_in().await;
    assert!(
        finish_code(&mut contractor, &q)
            .await
            .user
            .groups
            .is_empty()
    );
    set_user(idp, "555", "ada@example.com");
    google_claims(idp, Some("example.com"));
    idp.idp
        .claims_patch
        .lock()
        .unwrap()
        .insert("email_verified".into(), json!(false));
    let back = d.client().browser_sign_in().await;
    assert!(back["error_description"].contains("email"), "{back:?}");
    assert!(
        d.audit_messages()
            .iter()
            .any(|m| m.starts_with("sign-in refused: This Google account is not allowed"))
    );

    // Once built-in accounts exist, sign-in offers both.
    d.create("ops-admin", &[]).await;
    google_claims(idp, Some("example.com"));
    set_user(idp, "110169484474386276334", "ada@example.com");
    let (mut b, page, verifier) = begin(&d, &[("prompt", "login")]).await;
    let html = text(&page);
    assert!(html.contains("Sign in with Google"), "{html}");
    // A wrong password first keeps the app's request for a fresh sign-in.
    let flow = field(&html, "flow");
    let retry = b
        .post(
            "/v1/auth/password",
            &[
                ("flow", &flow),
                ("login", &field(&html, "login")),
                ("username", "ops-admin"),
                ("password", "wrong password!"),
            ],
        )
        .await;
    assert_eq!(retry.status, StatusCode::UNAUTHORIZED);
    let html = text(&retry);
    let start = html.find("href=\"/v1/auth/idp?").unwrap() + 6;
    let href = html[start..]
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&");
    // The IdP button is bound to the browser that got the page.
    let mut stranger = d.browser();
    assert!(text(&stranger.get(&href).await).contains("expired"));
    let to_google = location(&b.get(&href).await);
    assert_eq!(query_of(&to_google)["prompt"], "select_account");
    let to_cp = location(&b.get(&to_google).await);
    let reply = b.get(&to_cp).await;
    let mut client = d.client();
    let session = finish(&mut client, &reply, &verifier).await;
    assert_eq!(session.user.groups, ["local:admins"]);
    d.cp.shutdown().await;
}

/// Exchanges the code of a browser sign-in through the IdP.
async fn finish_code(client: &mut TestClient, q: &HashMap<String, String>) -> Session {
    let code = q.get("code").unwrap_or_else(|| panic!("no code: {q:?}"));
    let reply = client.exchange(code, &q["verifier"]).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", text(&reply));
    client.session.clone().unwrap()
}
