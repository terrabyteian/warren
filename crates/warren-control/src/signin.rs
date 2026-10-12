//! Sign-in with built-in accounts, in the browser the client opened
//! (docs/protocol.md section 11.1): a password, then an authenticator code
//! or a single-use recovery code, enrolling the authenticator app at the
//! first sign-in. The pages also offer the IdP when one is configured, and
//! one-time setup links let a user set their password.
//!
//! Every page is server-rendered HTML with no script. Each step is bound to
//! the browser that started it by a cookie, moves the sign-in forward at
//! most once, and is refused from another origin. Every attempt counts,
//! before it is checked, against the source address and the username,
//! whether or not an account has it (locking it after
//! `MAX_FAILED_ATTEMPTS` failures in a row); a locked or unknown username
//! looks exactly like a wrong password, and only the audit log says which.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;
use warren_core::clock;
use warren_core::keys::sha256;
use zeroize::Zeroizing;

use crate::accounts;
use crate::api::{AUTH_CODE_LIFETIME, with_query};
use crate::app::{App, new_secret, secret_hash};
use crate::audit::{self, Activity, Actor};
use crate::store::{AuthCode, AuthRequest, LocalAccount, User};
use crate::web::{ApiError, Body, Peer, escape_html, param, query, read_body, see_other};

/// The cookie that binds a sign-in to its browser. `__Host-` means the
/// browser keeps it only for this host, over HTTPS, on every path.
const COOKIE: &str = "__Host-warren-signin";
/// The largest form accepted.
const FORM_BODY: usize = 16 << 10;

/// Stages of a built-in account sign-in, after the password.
const STAGE_CODE: &str = "code";
const STAGE_ENROLL: &str = "enroll";
const STAGE_ENROLLED: &str = "enrolled";

/// What every failed or refused password step shows.
const INCORRECT: &str =
    "The username or password is incorrect, or the account is temporarily locked. Try again later.";

const CSS: &str = "\
:root{color-scheme:light dark;--fg:#1d1d1f;--muted:#6e6e73;--bg:#f5f5f7;--card:#fff;--line:#d2d2d7;--accent:#2f6f4f;--bad:#b3261e}\
@media (prefers-color-scheme:dark){:root{--fg:#f5f5f7;--muted:#a1a1a6;--bg:#1c1c1e;--card:#2c2c2e;--line:#48484a;--accent:#6fbf8f;--bad:#ff8a80}}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,sans-serif;padding:16px}\
main{width:100%;max-width:26rem;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}\
h1{font-size:1.35rem;margin:0 0 4px}\
p{margin:8px 0 16px}\
.muted{color:var(--muted);font-size:.9rem}\
label{display:block;font-weight:600;font-size:.9rem;margin:14px 0 6px}\
input{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit}\
input:focus{outline:2px solid var(--accent);outline-offset:1px}\
button,.button{display:block;width:100%;margin-top:18px;padding:11px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;font-weight:600;text-align:center;text-decoration:none;cursor:pointer}\
.secondary{background:transparent;color:var(--accent);border:1px solid var(--line)}\
.error{border-left:3px solid var(--bad);padding:8px 12px;margin:12px 0;color:var(--bad);background:transparent}\
.or{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:.85rem;margin:20px 0 4px}\
.or::before,.or::after{content:'';flex:1;border-top:1px solid var(--line)}\
.qr{display:flex;justify-content:center;margin:12px 0}\
.qr svg{border-radius:6px}\
code,.codes{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}\
.key{word-break:break-all;letter-spacing:.05em}\
.codes{columns:2;padding-left:1.4em;margin:12px 0}\
details{margin:8px 0}\
summary{cursor:pointer;color:var(--accent)}";

/// Where a form may send the browser: the control plane itself and, for
/// the step that hands the code back, the client's redirect URI.
fn form_action_source(redirect_uri: &str) -> Option<String> {
    let source = match redirect_uri.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            format!("{scheme}://{authority}")
        }
        None => format!("{}:", redirect_uri.split(':').next().unwrap_or("")),
    };
    // A CSP source must not smuggle in another directive.
    let safe = source.len() > 3
        && source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.:/[]".contains(&b));
    safe.then_some(source)
}

/// A sign-in page: escaped by the caller, no script, styled by one inline
/// stylesheet allowed by its hash, never framed, never leaking its URL.
fn html(
    status: StatusCode,
    title: &str,
    content: &str,
    redirect_uri: Option<&str>,
    cookie: Option<&str>,
) -> Response<Body> {
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{} · warren</title><style>{CSS}</style></head><body><main>{content}</main></body></html>",
        escape_html(title),
    );
    let mut resp = crate::web::body(status, "text/html; charset=utf-8", page);
    let form_action = match redirect_uri.and_then(form_action_source) {
        Some(source) => format!("'self' {source}"),
        None => "'self'".into(),
    };
    let csp = format!(
        "default-src 'none'; style-src 'sha256-{}'; form-action {form_action}; frame-ancestors 'none'; base-uri 'none'",
        STANDARD.encode(sha256(CSS.as_bytes()))
    );
    let headers = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&csp) {
        headers.insert("content-security-policy", v);
    }
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    if let Some(value) = cookie
        && let Ok(v) = HeaderValue::from_str(&format!(
            "{COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600"
        ))
    {
        headers.insert("set-cookie", v);
    }
    resp
}

/// A page that only says something went wrong and what to do.
fn notice(status: StatusCode, title: &str, text: &str) -> Response<Body> {
    html(
        status,
        title,
        &format!(
            "<h1>{}</h1><p>{}</p>",
            escape_html(title),
            escape_html(text)
        ),
        None,
        None,
    )
}

fn expired() -> Response<Body> {
    notice(
        StatusCode::BAD_REQUEST,
        "This sign-in has expired",
        "It was already finished, is too old, or was started in another browser. Start sign-in again from the warren app.",
    )
}

fn error_box(error: Option<&str>) -> String {
    error
        .map(|e| format!("<p class=\"error\" role=\"alert\">{}</p>", escape_html(e)))
        .unwrap_or_default()
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
        escape_html(value)
    )
}

/// The first page: a username and password form, and the IdP when one is
/// configured. `login` carries the client's request for a fresh sign-in on
/// to the IdP.
fn password_page(
    app: &App,
    flow: &str,
    login: bool,
    username: &str,
    error: Option<&str>,
    status: StatusCode,
    cookie: Option<&str>,
) -> Response<Body> {
    let idp = app.idp.as_ref().map(|idp| {
        let href = with_query(
            "/v1/auth/idp",
            &[("flow", flow), ("login", if login { "1" } else { "0" })],
        );
        format!(
            "<a class=\"button\" href=\"{}\">Sign in with {}</a><div class=\"or\">or with a warren account</div>",
            escape_html(&href),
            escape_html(&idp.config().display_name)
        )
    });
    let content = format!(
        "<h1>Sign in to warren</h1><p class=\"muted\">{td}</p>{idp}{error}\
         <form method=\"post\" action=\"/v1/auth/password\">{flow}{login}\
         <label for=\"username\">Username</label>\
         <input id=\"username\" name=\"username\" value=\"{username}\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" required{focus}>\
         <label for=\"password\">Password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>\
         <button type=\"submit\"{secondary}>Continue</button></form>",
        td = escape_html(&app.config.trust_domain),
        idp = idp.as_deref().unwrap_or(""),
        error = error_box(error),
        flow = hidden("flow", flow),
        login = hidden("login", if login { "1" } else { "0" }),
        username = escape_html(username),
        focus = if idp.is_none() { " autofocus" } else { "" },
        secondary = if idp.is_some() {
            " class=\"secondary\""
        } else {
            ""
        },
    );
    html(status, "Sign in", &content, None, cookie)
}

fn code_page(
    flow: &str,
    username: &str,
    error: Option<&str>,
    status: StatusCode,
    redirect_uri: &str,
) -> Response<Body> {
    let content = format!(
        "<h1>Enter your authenticator code</h1>\
         <p>Open the authenticator app you set up for warren and enter the 6-digit code for <strong>{user}</strong>.</p>{error}\
         <form method=\"post\" action=\"/v1/auth/code\">{flow}\
         <label for=\"code\">Code</label>\
         <input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" autocapitalize=\"none\" spellcheck=\"false\" required autofocus>\
         <button type=\"submit\">Sign in</button></form>\
         <p class=\"muted\">Lost your authenticator? Enter one of your recovery codes instead, or ask an administrator to reset your account.</p>",
        user = escape_html(username),
        error = error_box(error),
        flow = hidden("flow", flow),
    );
    html(
        status,
        "Authenticator code",
        &content,
        Some(redirect_uri),
        None,
    )
}

/// The enrollment page: the QR code an authenticator app scans, the key to
/// type in instead, and a field for the first code, which proves it worked.
fn enroll_page(
    app: &App,
    flow: &str,
    username: &str,
    secret: &[u8],
    error: Option<&str>,
    status: StatusCode,
) -> Response<Body> {
    let issuer = format!("warren {}", app.config.trust_domain);
    let uri = accounts::otpauth_uri(secret, &issuer, username);
    let qr = match accounts::qr_svg(&uri) {
        Ok(svg) => svg,
        Err(e) => {
            crate::log::error("sign-in", &e.to_string());
            String::new()
        }
    };
    let key: Vec<String> = accounts::base32(secret)
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    let content = format!(
        "<h1>Set up an authenticator app</h1>\
         <p>warren needs a second step besides your password. Scan this code with an authenticator app, then enter the 6-digit code it shows.</p>\
         <div class=\"qr\">{qr}</div>\
         <details><summary>Can't scan it?</summary><p>Add an account by hand with this key, time-based, 6 digits, every 30 seconds:</p><p><code class=\"key\">{key}</code></p></details>{error}\
         <form method=\"post\" action=\"/v1/auth/code\">{flow}\
         <label for=\"code\">Code from the app</label>\
         <input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required autofocus>\
         <button type=\"submit\">Turn it on</button></form>\
         <p class=\"muted\">Signing in as {user}.</p>",
        key = escape_html(&key.join(" ")),
        error = error_box(error),
        flow = hidden("flow", flow),
        user = escape_html(username),
    );
    html(status, "Set up an authenticator", &content, None, None)
}

fn recovery_page(flow: &str, codes: &[Zeroizing<String>], redirect_uri: &str) -> Response<Body> {
    let items: String = codes
        .iter()
        .map(|c| format!("<li>{}</li>", escape_html(c)))
        .collect();
    let content = format!(
        "<h1>Save your recovery codes</h1>\
         <p>Your authenticator is set up. If you ever lose it, each of these codes signs you in once instead of an authenticator code. Keep them somewhere safe: they are not shown again.</p>\
         <ol class=\"codes\">{items}</ol>\
         <form method=\"post\" action=\"/v1/auth/continue\">{flow}\
         <button type=\"submit\">I saved them, continue</button></form>",
        flow = hidden("flow", flow),
    );
    html(
        StatusCode::OK,
        "Recovery codes",
        &content,
        Some(redirect_uri),
        None,
    )
}

/// The page `GET /v1/auth/authorize` shows when built-in accounts can sign
/// in, setting the cookie that binds the sign-in to this browser.
pub(crate) fn start(app: &App, flow: &str, login: bool, browser: &str) -> Response<Body> {
    password_page(app, flow, login, "", None, StatusCode::OK, Some(browser))
}

/// A form body, refusing repeated fields.
async fn read_form(req: Request<Incoming>) -> Result<Vec<(String, String)>, ApiError> {
    let form_type = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !form_type {
        return Err(ApiError::bad_request("expected a form"));
    }
    let body = read_body(req, FORM_BODY).await?;
    let pairs: Vec<(String, String)> = form_urlencoded::parse(&body).into_owned().collect();
    for (i, (k, _)) in pairs.iter().enumerate() {
        if pairs[..i].iter().any(|(other, _)| other == k) {
            return Err(ApiError::bad_request(format!("field {k} is repeated")));
        }
    }
    Ok(pairs)
}

fn cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_owned())
}

/// Refuses a form posted from a page of another origin.
fn same_origin(app: &App, headers: &HeaderMap) -> bool {
    // Browsers leave the default port out of an origin.
    let ours = app.config.public_url.trim_end_matches(":443");
    match headers.get(http::header::ORIGIN) {
        None => true,
        Some(origin) => origin
            .to_str()
            .is_ok_and(|o| o.trim_end_matches(":443").eq_ignore_ascii_case(ours)),
    }
}

/// Whether a sign-in in flight belongs to the browser that sent `headers`.
pub(crate) fn bound_to_browser(headers: &HeaderMap, request: &AuthRequest) -> bool {
    match (&request.browser_hash, cookie(headers)) {
        (Some(expected), Some(value)) => *expected == secret_hash(&value),
        _ => false,
    }
}

/// A built-in account sign-in in progress: the request, its key, and the
/// account once the password checked out.
struct Flow {
    flow: String,
    key: String,
    request: AuthRequest,
}

/// Finds the sign-in a form continues: it must exist, be bound to this
/// browser, and come from this origin.
async fn flow_of(
    app: &App,
    headers: &HeaderMap,
    form: &[(String, String)],
) -> Result<Result<Flow, Response<Body>>, ApiError> {
    if !same_origin(app, headers) {
        return Ok(Err(notice(
            StatusCode::FORBIDDEN,
            "Sign-in refused",
            "The form came from another site. Start sign-in again from the warren app.",
        )));
    }
    let flow = param(form, "flow").unwrap_or("").to_owned();
    let key = secret_hash(&flow);
    let Some(request) = app.store.auth_request(&key).await? else {
        return Ok(Err(expired()));
    };
    if !bound_to_browser(headers, &request) {
        return Ok(Err(expired()));
    }
    Ok(Ok(Flow { flow, key, request }))
}

fn source(peer: &Peer) -> Option<IpAddr> {
    peer.addr.map(|a| a.ip())
}

fn actor(user: &User) -> Actor {
    Actor::User {
        id: user.id.clone(),
        email: user.email.clone(),
    }
}

fn logon_record(
    success: bool,
    actor: &Actor,
    message: &str,
    protocol: &str,
    peer: &Peer,
) -> serde_json::Map<String, serde_json::Value> {
    let mut r = audit::record(Activity::Logon, success, actor, message);
    r.insert("auth_protocol".into(), protocol.into());
    r.insert("is_mfa".into(), (success && protocol != "password").into());
    if let Some(ip) = source(peer) {
        r.insert("src_endpoint".into(), json!({ "ip": ip.to_string() }));
    }
    r
}

/// Counts an attempt against its source, refusing it once the source has
/// made too many.
fn too_many(app: &App, peer: &Peer) -> Option<Response<Body>> {
    (!app.limiter.attempt(source(peer), clock::now_secs())).then(|| {
        notice(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed sign-ins",
            "There have been too many failed sign-ins from your network. Wait 15 minutes and try again.",
        )
    })
}

/// Audits a failed or refused step, and the lockout of `locked` when this
/// attempt locked it.
fn failed(
    app: &App,
    peer: &Peer,
    user: Option<&User>,
    locked: Option<&LocalAccount>,
    message: &str,
    protocol: &str,
) {
    let actor = user.map(actor).unwrap_or(Actor::Anonymous);
    app.audit(logon_record(false, &actor, message, protocol, peer));
    let Some(account) = locked else {
        return;
    };
    let mut r = audit::record(
        Activity::Lock,
        true,
        &Actor::System,
        "built-in account locked after too many failed sign-ins",
    );
    r.insert(
        "user".into(),
        json!({ "uid": account.user_id, "name": account.username }),
    );
    app.audit(r);
}

/// `POST /v1/auth/password`: the first step.
pub(crate) async fn password(
    app: &App,
    req: Request<Incoming>,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    if !app.config.local_accounts.enabled {
        return Err(ApiError::not_found("built-in accounts are turned off"));
    }
    let headers = req.headers().clone();
    let form = read_form(req).await?;
    let f = match flow_of(app, &headers, &form).await? {
        Ok(f) => f,
        Err(page) => return Ok(page),
    };
    if f.request.local_stage.is_some() {
        return Ok(expired());
    }
    if let Some(page) = too_many(app, peer) {
        return Ok(page);
    }
    let username = param(&form, "username")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let password = Zeroizing::new(param(&form, "password").unwrap_or("").to_owned());
    let login = param(&form, "login") == Some("1");
    let retry = || {
        password_page(
            app,
            &f.flow,
            login,
            &username,
            Some(INCORRECT),
            StatusCode::UNAUTHORIZED,
            None,
        )
    };
    let account = if warren_core::identity::valid_id(&username) {
        app.store.local_account_named(&username).await?
    } else {
        None
    };
    let user = match &account {
        Some(a) => app.store.user(&a.user_id).await?,
        None => None,
    };
    let now = clock::now_secs();
    let reserved = match &account {
        Some(a) => app.store.reserve_local_attempt(&a.user_id, now).await?,
        None => app.unknown_names.attempt(&username, now),
    };
    let hash = account.as_ref().and_then(|a| a.password_hash.clone());
    let has_password = hash.is_some();
    let ok = app
        .verify_password(reserved.and(hash.clone()), password.clone())
        .await?;
    let Some(lock) = reserved else {
        failed(
            app,
            peer,
            user.as_ref(),
            None,
            "sign-in refused: the username is locked after too many failed sign-ins",
            "password",
        );
        return Ok(retry());
    };
    let (Some(account), Some(user)) = (account, user) else {
        failed(
            app,
            peer,
            None,
            None,
            "sign-in refused: unknown username",
            "password",
        );
        return Ok(retry());
    };
    if !ok {
        let why = if has_password {
            "sign-in refused: wrong password"
        } else {
            "sign-in refused: no password is set yet; the account needs its setup link"
        };
        failed(
            app,
            peer,
            Some(&user),
            (lock > 0).then_some(&account),
            why,
            "password",
        );
        return Ok(retry());
    }
    app.limiter.succeeded(source(peer), now);
    app.store
        .refund_local_attempt(&account.user_id, lock)
        .await?;
    if user.disabled {
        app.audit(logon_record(
            false,
            &actor(&user),
            "sign-in refused: the user is disabled",
            "password",
            peer,
        ));
        return Ok(notice(
            StatusCode::FORBIDDEN,
            "Your account is disabled",
            "Your warren account is disabled. Contact your administrator.",
        ));
    }
    let mut verified = hash.unwrap_or_default();
    if accounts::needs_rehash(&verified) {
        let rehashed = app.hash_password(password.clone()).await?;
        if !app
            .store
            .set_password_hash(&account.user_id, &verified, &rehashed)
            .await?
        {
            return Ok(expired());
        }
        verified = rehashed;
    }
    if account.totp_secret.is_none() {
        let secret = accounts::new_totp_secret()?;
        let sealed = app.kek.seal(&totp_aad(&account.user_id), &secret)?;
        if !app
            .store
            .advance_auth_request(
                &f.key,
                None,
                STAGE_ENROLL,
                &account.user_id,
                &verified,
                Some(&sealed),
            )
            .await?
        {
            return Ok(expired());
        }
        return Ok(enroll_page(
            app,
            &f.flow,
            &account.username,
            &secret,
            None,
            StatusCode::OK,
        ));
    }
    if !app
        .store
        .advance_auth_request(&f.key, None, STAGE_CODE, &account.user_id, &verified, None)
        .await?
    {
        return Ok(expired());
    }
    Ok(code_page(
        &f.flow,
        &account.username,
        None,
        StatusCode::OK,
        &f.request.client_redirect_uri,
    ))
}

/// What an authenticator secret is sealed to: the account it belongs to.
fn totp_aad(user_id: &str) -> String {
    format!("totp:{user_id}")
}

/// `POST /v1/auth/code`: an authenticator or recovery code, or the first
/// code from an authenticator being enrolled.
pub(crate) async fn code(
    app: &App,
    req: Request<Incoming>,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    if !app.config.local_accounts.enabled {
        return Err(ApiError::not_found("built-in accounts are turned off"));
    }
    let headers = req.headers().clone();
    let form = read_form(req).await?;
    let f = match flow_of(app, &headers, &form).await? {
        Ok(f) => f,
        Err(page) => return Ok(page),
    };
    let stage = f.request.local_stage.as_deref();
    if !matches!(stage, Some(STAGE_CODE | STAGE_ENROLL)) {
        return Ok(expired());
    }
    if let Some(page) = too_many(app, peer) {
        return Ok(page);
    }
    let user_id = f.request.local_user_id.clone().unwrap_or_default();
    let (Some(account), Some(user)) = (
        app.store.local_account(&user_id).await?,
        app.store.user(&user_id).await?,
    ) else {
        return Ok(expired());
    };
    let now = clock::now_secs();
    let typed: String = param(&form, "code")
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let reserved = app.store.reserve_local_attempt(&user_id, now).await?;

    if stage == Some(STAGE_ENROLL) {
        let sealed = f.request.pending_secret.clone().unwrap_or_default();
        let secret = app.kek.open(&totp_aad(&user_id), &sealed)?;
        let retry = || {
            enroll_page(
                app,
                &f.flow,
                &account.username,
                &secret,
                Some(
                    "That code did not match, or the account is temporarily locked. Check the time on your phone and enter the newest code.",
                ),
                StatusCode::UNAUTHORIZED,
            )
        };
        let Some(lock) = reserved else {
            failed(
                app,
                peer,
                Some(&user),
                None,
                "authenticator enrollment refused: the account is locked after too many failed sign-ins",
                "password+TOTP",
            );
            return Ok(retry());
        };
        let Some(step) = accounts::verify_totp(&secret, &typed, now, 0) else {
            failed(
                app,
                peer,
                Some(&user),
                (lock > 0).then_some(&account),
                "authenticator enrollment refused: wrong code",
                "password+TOTP",
            );
            return Ok(retry());
        };
        let codes = accounts::new_recovery_codes()?;
        let hashes: Vec<String> = codes
            .iter()
            .filter_map(|c| accounts::normalize_recovery_code(c))
            .map(|c| accounts::recovery_code_hash(&c))
            .collect();
        if !app
            .store
            .enroll_totp(&user_id, &sealed, step, &hashes)
            .await?
            || !app
                .store
                .advance_auth_request(
                    &f.key,
                    Some(STAGE_ENROLL),
                    STAGE_ENROLLED,
                    &user_id,
                    account.password_hash.as_deref().unwrap_or(""),
                    None,
                )
                .await?
        {
            return Ok(expired());
        }
        app.limiter.succeeded(source(peer), now);
        let mut r = audit::record(
            Activity::MfaEnable,
            true,
            &actor(&user),
            "authenticator app enrolled, with new recovery codes",
        );
        r.insert(
            "user".into(),
            json!({ "uid": user.id, "name": account.username }),
        );
        app.audit(r);
        return Ok(recovery_page(
            &f.flow,
            &codes,
            &f.request.client_redirect_uri,
        ));
    }

    let retry = || {
        code_page(
            &f.flow,
            &account.username,
            Some(
                "That code is not right or was already used, or the account is temporarily locked. Enter the newest code, or try again later.",
            ),
            StatusCode::UNAUTHORIZED,
            &f.request.client_redirect_uri,
        )
    };
    let Some(lock) = reserved else {
        failed(
            app,
            peer,
            Some(&user),
            None,
            "sign-in refused: the account is locked after too many failed sign-ins",
            "password+TOTP",
        );
        return Ok(retry());
    };
    let secret = app.kek.open(
        &totp_aad(&user_id),
        account.totp_secret.as_deref().unwrap_or(""),
    )?;
    let (accepted, protocol) =
        match accounts::verify_totp(&secret, &typed, now, account.totp_last_step) {
            Some(step) => (
                app.store
                    .record_local_success(&user_id, Some(step), now)
                    .await?,
                "password+TOTP",
            ),
            None => match accounts::normalize_recovery_code(&typed) {
                Some(code) => {
                    let left = app
                        .store
                        .use_recovery_code(&user_id, &accounts::recovery_code_hash(&code))
                        .await?;
                    match left {
                        Some(left) => {
                            app.store.record_local_success(&user_id, None, now).await?;
                            let mut r = audit::record(
                                Activity::Update,
                                true,
                                &actor(&user),
                                "recovery code used",
                            );
                            r.insert("entity".into(), audit::entity("recovery-code", ""));
                            r.insert("unmapped".into(), json!({ "recovery_codes_left": left }));
                            app.audit(r);
                            (true, "password+recovery code")
                        }
                        None => (false, "password+recovery code"),
                    }
                }
                None => (false, "password+TOTP"),
            },
        };
    if !accepted {
        failed(
            app,
            peer,
            Some(&user),
            (lock > 0).then_some(&account),
            "sign-in refused: wrong authenticator or recovery code",
            protocol,
        );
        return Ok(retry());
    }
    app.limiter.succeeded(source(peer), now);
    finish(app, &f.key, &user, protocol, peer).await
}

/// `POST /v1/auth/continue`: after the recovery codes were shown.
pub(crate) async fn proceed(
    app: &App,
    req: Request<Incoming>,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    let headers = req.headers().clone();
    let form = read_form(req).await?;
    let f = match flow_of(app, &headers, &form).await? {
        Ok(f) => f,
        Err(page) => return Ok(page),
    };
    if f.request.local_stage.as_deref() != Some(STAGE_ENROLLED) {
        return Ok(expired());
    }
    let user_id = f.request.local_user_id.clone().unwrap_or_default();
    let Some(user) = app.store.user(&user_id).await? else {
        return Ok(expired());
    };
    finish(app, &f.key, &user, "password+TOTP", peer).await
}

/// Ends a built-in account sign-in: the one-time code goes back to the
/// client, as after an IdP sign-in, with the time of authentication now
/// and MFA, since a password alone never gets here.
async fn finish(
    app: &App,
    key: &str,
    user: &User,
    protocol: &str,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    let Some(pending) = app.store.take_auth_request(key).await? else {
        return Ok(expired());
    };
    let back = |pairs: &[(&str, &str)]| {
        let mut all = pairs.to_vec();
        all.push(("state", pending.client_state.as_str()));
        see_other(&with_query(&pending.client_redirect_uri, &all))
    };
    if user.disabled {
        app.audit(logon_record(
            false,
            &actor(user),
            "sign-in refused: the user is disabled",
            protocol,
            peer,
        ));
        return Ok(back(&[
            ("error", "access_denied"),
            (
                "error_description",
                "Your warren account is disabled. Contact your administrator.",
            ),
        ]));
    }
    let auth_time = clock::now_secs();
    let code = new_secret()?;
    app.store
        .insert_auth_code(
            &secret_hash(&code),
            &AuthCode {
                user_id: user.id.clone(),
                client_challenge: pending.client_challenge.clone(),
                client_redirect_uri: pending.client_redirect_uri.clone(),
                auth_time,
                mfa: true,
            },
            auth_time + AUTH_CODE_LIFETIME,
        )
        .await?;
    let mut r = logon_record(
        true,
        &actor(user),
        "signed in with a built-in account",
        protocol,
        peer,
    );
    r.insert(
        "user".into(),
        json!({ "uid": user.id, "name": user.subject, "email_addr": user.email, "groups": user.groups.iter().map(|g| json!({ "name": g })).collect::<Vec<_>>() }),
    );
    app.audit(r);
    Ok(back(&[("code", &code)]))
}

fn setup_page(
    token: &str,
    username: &str,
    error: Option<&str>,
    status: StatusCode,
) -> Response<Body> {
    let content = format!(
        "<h1>Set your warren password</h1>\
         <p>Choose a password for <strong>{user}</strong>: at least {min} characters. A long phrase is easiest to remember.</p>{error}\
         <form method=\"post\" action=\"/v1/auth/setup\">{token}\
         <input type=\"text\" name=\"username\" value=\"{user}\" autocomplete=\"username\" hidden readonly>\
         <label for=\"password\">New password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"new-password\" minlength=\"{min}\" required autofocus>\
         <label for=\"confirm\">Repeat it</label>\
         <input id=\"confirm\" name=\"confirm\" type=\"password\" autocomplete=\"new-password\" minlength=\"{min}\" required>\
         <button type=\"submit\">Set password</button></form>",
        user = escape_html(username),
        min = accounts::PASSWORD_MIN_CHARS,
        error = error_box(error),
        token = hidden("token", token),
    );
    html(status, "Set your password", &content, None, None)
}

fn setup_expired() -> Response<Body> {
    notice(
        StatusCode::BAD_REQUEST,
        "This setup link has expired",
        "It was already used or is too old. Ask your administrator for a new one.",
    )
}

/// `GET /v1/auth/setup?token=...`: the password form of a setup link.
pub(crate) async fn setup_form<B>(app: &App, req: &Request<B>) -> Result<Response<Body>, ApiError> {
    let q = query(req)?;
    let token = param(&q, "token").unwrap_or("");
    match app.store.setup_link_account(&secret_hash(token)).await? {
        Some((_, username)) => Ok(setup_page(token, &username, None, StatusCode::OK)),
        None => Ok(setup_expired()),
    }
}

/// `POST /v1/auth/setup`: sets the password and spends the link.
pub(crate) async fn setup(app: &App, req: Request<Incoming>) -> Result<Response<Body>, ApiError> {
    if !same_origin(app, req.headers()) {
        return Ok(notice(
            StatusCode::FORBIDDEN,
            "Refused",
            "The form came from another site. Open your setup link again.",
        ));
    }
    let form = read_form(req).await?;
    let token = param(&form, "token").unwrap_or("").to_owned();
    let Some((user_id, username)) = app.store.setup_link_account(&secret_hash(&token)).await?
    else {
        return Ok(setup_expired());
    };
    let password = Zeroizing::new(param(&form, "password").unwrap_or("").to_owned());
    if param(&form, "confirm").unwrap_or("") != password.as_str() {
        return Ok(setup_page(
            &token,
            &username,
            Some("The two passwords are different."),
            StatusCode::BAD_REQUEST,
        ));
    }
    if let Err(e) = accounts::check_new_password(&password, &username) {
        return Ok(setup_page(
            &token,
            &username,
            Some(&e),
            StatusCode::BAD_REQUEST,
        ));
    }
    let hash = app.hash_password(password).await?;
    if app
        .store
        .complete_setup(&secret_hash(&token), &hash)
        .await?
        .is_none()
    {
        return Ok(setup_expired());
    }
    let mut r = audit::record(
        Activity::PasswordChange,
        true,
        &Actor::User {
            id: user_id.clone(),
            email: String::new(),
        },
        "password set with a setup link",
    );
    r.insert("user".into(), json!({ "uid": user_id, "name": username }));
    app.audit(r);
    Ok(notice(
        StatusCode::OK,
        "Your password is set",
        &format!(
            "Open the warren app and sign in as {username}. The first time, warren will ask you to set up an authenticator app."
        ),
    ))
}

/// Whether `GET /v1/auth/authorize` shows the sign-in page: built-in
/// accounts are on and either there is no IdP or there are accounts to
/// sign in with. With an IdP and no accounts, it goes straight there.
pub(crate) async fn offers_local(app: &App) -> Result<bool, ApiError> {
    Ok(app.config.local_accounts.enabled
        && (app.idp.is_none() || app.store.has_local_accounts().await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_may_only_lead_back_to_the_client() {
        assert_eq!(
            form_action_source("http://127.0.0.1:53682/callback").as_deref(),
            Some("http://127.0.0.1:53682")
        );
        assert_eq!(
            form_action_source("http://[::1]:8080/cb?x=1").as_deref(),
            Some("http://[::1]:8080")
        );
        assert_eq!(
            form_action_source("com.example.warren:/callback").as_deref(),
            Some("com.example.warren:")
        );
        // Nothing that could close the directive and open another.
        assert_eq!(form_action_source("http://a; script-src *"), None);
        assert_eq!(form_action_source("x"), None);
    }
}
