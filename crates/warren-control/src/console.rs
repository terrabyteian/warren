//! The web console (docs/console.md): server-rendered pages under
//! `/console` on the HTTPS listener, signed in through the IdP like the
//! warren app.
//!
//! A browser signs in through the same callback as the warren app; the
//! auth request it starts is marked [`REDIRECT`] and bound to the browser
//! by a short-lived cookie, so a sign-in started elsewhere cannot finish
//! here. A successful sign-in sets a host-only, `Secure`, `HttpOnly`
//! session cookie whose token is stored only as a hash. Every page checks
//! the session and the user on each request, so disabling a user or
//! signing out takes effect at once. Every POST carries a form token
//! derived from the session token and must come from this origin.
//!
//! Admin pages are open to the users and groups `console.admins` names.
//! Changes need a sign-in the IdP reported as multi-factor, authenticated
//! within `console.changeMaxAge` (threat model T5), and go through the
//! same code as the admin API. Everyone signed in sees the apps open to
//! them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use bytes::Bytes;
use http::header::{HeaderValue, LOCATION, SET_COOKIE};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::Value;
use warren_console::html::Html;
use warren_console::pages;
use warren_console::view::*;
use warren_core::clock;
use warren_core::identity::AUTH_TIME_UNKNOWN;
use warren_core::jose::b64url;
use warren_core::keys::sha256;
use warren_policy::compile::{Access, what_matches};
use warren_policy::model::{self, DestinationKind};

use crate::api::{IdpSignIn, finish_idp_sign_in, s256};
use crate::app::{App, new_secret, secret_hash};
use crate::audit::{self, Activity, Actor};
use crate::store::{AuthRequest, ConsoleSession, Device, User, new_id};
use crate::web::{self, ApiError, Body, param, query, read_body};

/// The `client_redirect_uri` that marks an auth request as a console
/// sign-in. It is no URI, so no native client can name it.
pub const REDIRECT: &str = "warren-console:";

/// The session cookie. `__Host-` makes browsers insist on `Secure`,
/// `Path=/` and no `Domain`.
pub const SESSION_COOKIE: &str = "__Host-warren-console";

/// The cookie that binds a sign-in in flight to the browser that started
/// it.
pub const LOGIN_COOKIE: &str = "__Host-warren-login";

/// How long a sign-in may take at the IdP.
const LOGIN_LIFETIME: i64 = 600;

/// The largest form body the console reads.
const MAX_FORM: usize = 8 << 10;

/// The content security policy of every page: scripts, styles and fetches
/// from this origin only, no frames, forms posting only here.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// A response that ends a request early (sign in first, refused), boxed
/// to keep results small.
type Stop = Box<Response<Body>>;

/// Every console route, as (method, path template).
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/"),
    ("GET", "/console/"),
    ("GET", "/console/me"),
    ("GET", "/console/users"),
    ("GET", "/console/devices"),
    ("GET", "/console/apps"),
    ("GET", "/console/policies"),
    ("GET", "/console/decisions"),
    ("GET", "/console/decisions/{id}"),
    ("POST", "/console/users/{user}/disable"),
    ("POST", "/console/users/{user}/enable"),
    ("POST", "/console/devices/{device}/approve"),
    ("POST", "/console/devices/{device}/revoke"),
    ("GET", "/console/login"),
    ("GET", "/console/login/start"),
    ("POST", "/console/logout"),
    ("GET", "/console/assets/console.css"),
    ("GET", "/console/assets/console.js"),
];

/// Whether `path` belongs to the console.
pub fn is_console_path(path: &str) -> bool {
    path == "/" || path == "/console" || path.starts_with("/console/")
}

// Responses.

fn secure_headers(resp: &mut Response<Body>) {
    let h = resp.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    // Not no-referrer: browsers then send `Origin: null` on form posts,
    // which the origin check must refuse. Other sites get nothing.
    h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
}

fn html(status: StatusCode, page: Html) -> Response<Body> {
    let mut resp = web::body(status, "text/html; charset=utf-8", page.into_string());
    secure_headers(&mut resp);
    resp
}

fn see_other(location: &str) -> Response<Body> {
    let mut resp = web::body(StatusCode::SEE_OTHER, "text/plain; charset=utf-8", "");
    match HeaderValue::from_str(location) {
        Ok(v) => {
            resp.headers_mut().insert(LOCATION, v);
        }
        Err(_) => *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR,
    }
    secure_headers(&mut resp);
    resp
}

fn asset(content_type: &'static str, text: &'static str) -> Response<Body> {
    let mut resp = web::body(
        StatusCode::OK,
        content_type,
        Bytes::from_static(text.as_bytes()),
    );
    // Asset URLs carry a digest of the assets, so they may be cached.
    resp.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static("public, max-age=86400"),
    );
    secure_headers(&mut resp);
    resp
}

fn cookie(name: &str, value: &str, max_age: i64) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    ))
    .ok()
}

fn set_cookie(resp: &mut Response<Body>, name: &str, value: &str, max_age: i64) {
    if let Some(v) = cookie(name, value, max_age) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

fn error_page(viewer: Option<&Viewer>, e: &ApiError) -> Response<Body> {
    let title = e.status.canonical_reason().unwrap_or("Error");
    html(e.status, pages::message(viewer, title, &e.detail, None))
}

/// The value of cookie `name`, from every `Cookie` header (HTTP/2 may split
/// them).
fn read_cookie<B>(req: &Request<B>, name: &str) -> Option<String> {
    req.headers()
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

/// Where to go after signing in: a console path, or the console's start.
/// Anything else (another origin, `//host`, backslashes) is replaced.
fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n)
            if (n == "/console" || n.starts_with("/console/"))
                && !n.contains("//")
                && !n.contains('\\')
                && n.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            n.to_owned()
        }
        _ => "/console/".into(),
    }
}

/// The form token for a session token: a hash of it, so it needs no
/// storage and is worthless without the cookie.
fn csrf_token(session_token: &str) -> String {
    b64url(&sha256(
        format!("warren-console-csrf\0{session_token}").as_bytes(),
    ))
}

fn display_name(u: &User) -> String {
    if u.email.is_empty() {
        u.subject.clone()
    } else {
        u.email.clone()
    }
}

/// Whether `user` is named by `console.admins`.
pub fn is_admin(app: &App, user: &User) -> bool {
    let c = &app.config.console;
    c.admin_groups.iter().any(|g| user.groups.contains(g))
        || c.admin_users.iter().any(|u| {
            *u == user.id
                || *u == user.subject
                || (!user.email.is_empty() && u.eq_ignore_ascii_case(&user.email))
        })
}

// Sign-in.

/// A signed-in browser.
struct Signed {
    session: ConsoleSession,
    user: User,
    viewer: Viewer,
}

/// Where to return after signing in during `req`: the page itself for a
/// GET, and for a change the page it was made from.
fn return_to<B>(req: &Request<B>) -> String {
    if req.method() == Method::GET {
        return safe_next(req.uri().path_and_query().map(|p| p.as_str()));
    }
    let page = req
        .uri()
        .path()
        .split('/')
        .take(3)
        .collect::<Vec<_>>()
        .join("/");
    safe_next(Some(&page))
}

fn login_redirect<B>(req: &Request<B>, why: Option<&str>) -> Response<Body> {
    let next = return_to(req);
    let mut ser = form_urlencoded::Serializer::new(String::new());
    ser.append_pair("next", &next);
    if let Some(w) = why {
        ser.append_pair("why", w);
    }
    see_other(&format!("/console/login?{}", ser.finish()))
}

/// The signed-in session behind the request's cookie, or the response that
/// sends the browser to sign in.
async fn signed_in<B>(app: &App, req: &Request<B>) -> Result<Signed, Stop> {
    let Some(token) = read_cookie(req, SESSION_COOKIE) else {
        return Err(Box::new(login_redirect(req, None)));
    };
    let internal = |e: crate::Error| Box::new(error_page(None, &e.into()));
    let Some(session) = app
        .store
        .console_session(&secret_hash(&token))
        .await
        .map_err(internal)?
    else {
        return Err(Box::new(login_redirect(req, Some("expired"))));
    };
    let now = clock::now_secs();
    if session.ended_at.is_some() || session.expires_at <= now {
        return Err(Box::new(login_redirect(req, Some("expired"))));
    }
    let Some(user) = app.store.user(&session.user_id).await.map_err(internal)? else {
        return Err(Box::new(login_redirect(req, Some("expired"))));
    };
    if user.disabled {
        let _ = app.store.end_console_session(&session.id).await;
        let mut resp = login_redirect(req, Some("disabled"));
        set_cookie(&mut resp, SESSION_COOKIE, "", 0);
        return Err(Box::new(resp));
    }
    let admin = is_admin(app, &user);
    let viewer = Viewer {
        user_id: user.id.clone(),
        name: display_name(&user),
        admin,
        changes: may_change(app, admin, &session, now),
        csrf: csrf_token(&token),
        now,
    };
    Ok(Signed {
        session,
        user,
        viewer,
    })
}

/// Whether a sign-in may make admin changes: the one check every change
/// passes. An admin needs a sign-in the IdP reported as multi-factor
/// (threat model T5) that authenticated them within
/// `console.changeMaxAge`.
fn may_change(app: &App, admin: bool, session: &ConsoleSession, now: i64) -> Changes {
    if !admin {
        Changes::NotAdmin
    } else if !session.mfa {
        Changes::NeedMfa
    } else if now - session.auth_time > app.config.console.change_max_age.as_secs() as i64 {
        Changes::NeedRecentSignIn
    } else {
        Changes::Allowed
    }
}

/// Refuses everyone `console.admins` does not name.
fn require_admin(s: &Signed) -> Result<(), Stop> {
    if s.viewer.admin {
        return Ok(());
    }
    Err(Box::new(html(
        StatusCode::FORBIDDEN,
        pages::message(
            Some(&s.viewer),
            "For administrators",
            "This page is for warren administrators. The apps open to you are under My apps.",
            Some(warren_console::html!(
                "<p><a class=\"btn\" href=\"/console/me\">My apps</a></p>"
            )),
        ),
    )))
}

/// Checks that a POST came from a console page: from this origin when the
/// browser says where it came from, and with the session's form token.
/// Returns the form.
async fn check_post(
    app: &App,
    s: &Signed,
    req: Request<Incoming>,
) -> Result<Vec<(String, String)>, Stop> {
    let refuse = |why: &str| -> Stop {
        Box::new(html(
            StatusCode::FORBIDDEN,
            pages::message(Some(&s.viewer), "Request refused", why, None),
        ))
    };
    let origin = app
        .config
        .public_url
        .trim_end_matches(":443")
        .to_ascii_lowercase();
    if let Some(o) = req.headers().get(http::header::ORIGIN)
        && o.to_str().map(|o| o.to_ascii_lowercase()).ok() != Some(origin)
    {
        return Err(refuse("The request came from another site."));
    }
    if let Some(site) = req.headers().get("sec-fetch-site")
        && site.as_bytes() != b"same-origin"
    {
        return Err(refuse("The request came from another site."));
    }
    let body = read_body(req, MAX_FORM)
        .await
        .map_err(|e| Box::new(error_page(Some(&s.viewer), &e)))?;
    let form: Vec<(String, String)> = form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let token = param(&form, "csrf").unwrap_or("");
    if aws_lc_rs::constant_time::verify_slices_are_equal(token.as_bytes(), s.viewer.csrf.as_bytes())
        .is_err()
    {
        return Err(refuse(
            "The form has expired. Go back, reload the page and try again.",
        ));
    }
    Ok(form)
}

fn why_text(why: Option<&str>) -> Option<&'static str> {
    Some(match why? {
        "expired" => "Your console sign-in has ended. Sign in again.",
        "signed-out" => "You have signed out.",
        "disabled" => "Your warren account is disabled. Contact your administrator.",
        "refused" => "Your identity provider did not complete the sign-in.",
        "unverified" => {
            "warren could not verify the sign-in with your identity provider. Try again."
        }
        "browser" => {
            "That sign-in was started in another browser or has expired. Sign in again here."
        }
        _ => return None,
    })
}

async fn login_page<B>(app: &App, req: &Request<B>) -> Result<Response<Body>, ApiError> {
    let q = query(req)?;
    let next = safe_next(param(&q, "next"));
    let why = param(&q, "why");
    if why.is_none() && signed_in(app, req).await.is_ok() {
        return Ok(see_other(&next));
    }
    let status = match why {
        Some("disabled" | "refused" | "unverified" | "browser") => StatusCode::FORBIDDEN,
        _ => StatusCode::OK,
    };
    Ok(html(status, pages::sign_in(&next, why_text(why), false)))
}

async fn login_start<B>(app: &App, req: &Request<B>) -> Result<Response<Body>, ApiError> {
    let q = query(req)?;
    let next = safe_next(param(&q, "next"));
    let reauth = param(&q, "reauth") == Some("1");
    // Signing in again is for changes, so ask the IdP for a sign-in recent
    // enough for them too.
    let policy_max_age = app.compiled().and_then(|c| c.shortest_max_age());
    let max_age = if reauth {
        let change = app.config.console.change_max_age.as_secs() as i64;
        Some(policy_max_age.map_or(change, |m| m.min(change)))
    } else {
        policy_max_age
    };
    let binding = new_secret()?;
    let state = new_secret()?;
    let nonce = new_secret()?;
    let verifier = new_secret()?;
    app.store
        .insert_auth_request(
            &secret_hash(&state),
            &AuthRequest {
                client_redirect_uri: REDIRECT.into(),
                client_state: next.clone(),
                client_challenge: secret_hash(&binding),
                nonce: nonce.clone(),
                idp_verifier: verifier.clone(),
                created_at: clock::now_secs(),
                login: reauth,
            },
            clock::now_secs() + LOGIN_LIFETIME,
        )
        .await?;
    let callback = format!("{}/v1/auth/callback", app.config.public_url);
    match app
        .idp
        .authorize_url(&callback, &state, &nonce, &s256(&verifier), max_age, reauth)
        .await
    {
        Ok(url) => {
            let mut resp = see_other(&url);
            set_cookie(&mut resp, LOGIN_COOKIE, &binding, LOGIN_LIFETIME);
            Ok(resp)
        }
        Err(e) => {
            crate::log::error("idp", &e.to_string());
            Ok(html(
                StatusCode::BAD_GATEWAY,
                pages::message(
                    None,
                    "Sign-in is unavailable",
                    "warren cannot reach your identity provider right now. Try again in a minute.",
                    None,
                ),
            ))
        }
    }
}

/// Finishes a console sign-in at the IdP's callback: checks the browser is
/// the one that started it, then opens a console session.
///
/// When the IdP does not say when it authenticated the user, the session
/// counts as authenticated now only if this sign-in asked the IdP to
/// authenticate them afresh (`prompt=login`) and the ID token, carrying
/// this request's nonce, was issued after the request was made. Otherwise
/// the time stays unknown, which is never recent enough for changes.
pub(crate) async fn finish_sign_in<B>(
    app: &App,
    req: &Request<B>,
    q: &[(String, String)],
    pending: &AuthRequest,
) -> Result<Response<Body>, ApiError> {
    let next = safe_next(Some(&pending.client_state));
    let back = |why: &str| {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        ser.append_pair("next", &next).append_pair("why", why);
        let mut resp = see_other(&format!("/console/login?{}", ser.finish()));
        set_cookie(&mut resp, LOGIN_COOKIE, "", 0);
        Ok(resp)
    };
    let bound = read_cookie(req, LOGIN_COOKIE).is_some_and(|b| {
        aws_lc_rs::constant_time::verify_slices_are_equal(
            secret_hash(&b).as_bytes(),
            pending.client_challenge.as_bytes(),
        )
        .is_ok()
    });
    if !bound {
        let mut r = audit::record(
            Activity::Logon,
            false,
            &Actor::Anonymous,
            "console sign-in refused: it was started in another browser",
        );
        r.insert("auth_protocol".into(), "OIDC".into());
        app.audit(r);
        return back("browser");
    }
    let (user, auth_time, mfa) = match finish_idp_sign_in(app, q, pending).await? {
        IdpSignIn::Refused => return back("refused"),
        IdpSignIn::Unverified => return back("unverified"),
        IdpSignIn::Disabled => return back("disabled"),
        IdpSignIn::Done {
            user,
            auth_time,
            issued_at,
            mfa,
        } => {
            let fresh = pending.login && issued_at >= pending.created_at;
            let auth_time = if auth_time == AUTH_TIME_UNKNOWN as i64 && fresh {
                clock::now_secs()
            } else {
                auth_time
            };
            (user, auth_time, mfa)
        }
    };
    let token = new_secret()?;
    let lifetime = app.config.console.session_lifetime.as_secs() as i64;
    let session = ConsoleSession {
        id: new_id("cs")?,
        user_id: user.id.clone(),
        auth_time,
        mfa,
        expires_at: clock::now_secs() + lifetime,
        ended_at: None,
    };
    app.store
        .insert_console_session(&session, &secret_hash(&token))
        .await?;
    let mut r = audit::record(
        Activity::Logon,
        true,
        &Actor::Console {
            id: user.id.clone(),
            email: user.email.clone(),
        },
        "signed in to the console",
    );
    r.insert("auth_protocol".into(), "OIDC".into());
    r.insert("is_mfa".into(), mfa.into());
    r.insert(
        "entity".into(),
        audit::entity("console-session", &session.id),
    );
    app.audit(r);
    let mut resp = see_other(&next);
    set_cookie(&mut resp, SESSION_COOKIE, &token, lifetime);
    set_cookie(&mut resp, LOGIN_COOKIE, "", 0);
    Ok(resp)
}

async fn logout(app: &App, req: Request<Incoming>) -> Response<Body> {
    let s = match signed_in(app, &req).await {
        Ok(s) => s,
        Err(_) => {
            let mut resp = see_other("/console/login?why=signed-out");
            set_cookie(&mut resp, SESSION_COOKIE, "", 0);
            return resp;
        }
    };
    if let Err(resp) = check_post(app, &s, req).await {
        return *resp;
    }
    if let Err(e) = app.store.end_console_session(&s.session.id).await {
        return error_page(Some(&s.viewer), &e.into());
    }
    let mut r = audit::record(
        Activity::Logoff,
        true,
        &Actor::Console {
            id: s.user.id.clone(),
            email: s.user.email.clone(),
        },
        "signed out of the console",
    );
    r.insert(
        "entity".into(),
        audit::entity("console-session", &s.session.id),
    );
    app.audit(r);
    let mut resp = see_other("/console/login?why=signed-out");
    set_cookie(&mut resp, SESSION_COOKIE, "", 0);
    resp
}

// Routing.

/// Answers one console request.
pub async fn route(app: &Arc<App>, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let result = match (&method, segments.as_slice()) {
        (&Method::GET, [""] | ["console"]) => Ok(see_other("/console/")),
        (&Method::GET, ["console", "assets", "console.css"]) => {
            Ok(asset("text/css; charset=utf-8", warren_console::CSS))
        }
        (&Method::GET, ["console", "assets", "console.js"]) => {
            Ok(asset("text/javascript; charset=utf-8", warren_console::JS))
        }
        (&Method::GET, ["console", "login"]) => login_page(app, &req).await,
        (&Method::GET, ["console", "login", "start"]) => login_start(app, &req).await,
        (&Method::POST, ["console", "logout"]) => Ok(logout(app, req).await),
        (&Method::GET, _) => Ok(get_page(app, &req, &segments).await),
        (&Method::POST, ["console", "users", id, action @ ("disable" | "enable")]) => {
            let (id, action) = ((*id).to_owned(), (*action).to_owned());
            Ok(user_action(app, req, &id, &action).await)
        }
        (&Method::POST, ["console", "devices", id, action @ ("approve" | "revoke")]) => {
            let (id, action) = ((*id).to_owned(), (*action).to_owned());
            Ok(device_action(app, req, &id, &action).await)
        }
        _ => Err(ApiError::not_found(format!(
            "There is no console page {path}."
        ))),
    };
    result.unwrap_or_else(|e| error_page(None, &e))
}

async fn get_page<B>(app: &App, req: &Request<B>, segments: &[&str]) -> Response<Body> {
    let s = match signed_in(app, req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let q = match query(req) {
        Ok(q) => q,
        Err(e) => return error_page(Some(&s.viewer), &e),
    };
    let viewer = &s.viewer;
    if segments == ["console", "me"] {
        return match portal(app, &s).await {
            Ok(p) => html(StatusCode::OK, pages::portal(viewer, &p)),
            Err(e) => error_page(Some(viewer), &e),
        };
    }
    // The console's start: the overview for admins, their apps for others.
    if segments == ["console", ""] && !s.viewer.admin {
        return see_other("/console/me");
    }
    if let Err(resp) = require_admin(&s) {
        return *resp;
    }
    let page = match segments {
        ["console", ""] => overview(app, viewer)
            .await
            .map(|o| pages::overview(viewer, &o)),
        ["console", "users"] => users(app)
            .await
            .map(|(u, g)| pages::users(viewer, &u, &g, flash(&q, "user").as_ref())),
        ["console", "devices"] => {
            let status = param(&q, "status")
                .filter(|s| matches!(*s, "pending" | "approved" | "disabled" | "revoked"));
            devices(app)
                .await
                .map(|d| pages::devices(viewer, &d, status, flash(&q, "device").as_ref()))
        }
        ["console", "apps"] => apps(app).await.map(|(a, g)| pages::apps(viewer, &a, &g)),
        ["console", "policies"] => policies(app).await.map(|p| pages::policies(viewer, &p)),
        ["console", "decisions"] => {
            let denied = param(&q, "denied") == Some("1");
            decisions(app, denied)
                .await
                .map(|d| pages::decisions(viewer, &d, denied, app.recent.capacity()))
        }
        ["console", "decisions", id] => match explain(app, id).await {
            Ok(Some(e)) => Ok(pages::explanation(viewer, &e)),
            Ok(None) => Err(ApiError::not_found(
                "That decision is not among the recent ones the console keeps. Find it in the audit log by its decision ID.",
            )),
            Err(e) => Err(e),
        },
        _ => Err(ApiError::not_found("There is no such console page.")),
    };
    match page {
        Ok(page) => html(StatusCode::OK, page),
        Err(e) => error_page(Some(viewer), &e),
    }
}

/// The notice after an action, from the query of the page it returns to.
fn flash(q: &[(String, String)], what: &str) -> Option<Flash> {
    let done = param(q, "done")?;
    let id = param(q, "id").unwrap_or("");
    let text = match (what, done) {
        ("user", "disable") => format!("User {id} disabled. Their access is being cut now."),
        ("user", "enable") => format!("User {id} enabled."),
        ("user", "unchanged") => format!("User {id} was already in that state."),
        ("device", "approve") => format!("Device {id} approved."),
        ("device", "revoke") => {
            format!("Device {id} revoked. Its connections are being cut now.")
        }
        ("device", "unchanged") => format!("Device {id} was already in that state."),
        _ => return None,
    };
    Some(Flash { ok: true, text })
}

/// Checks an admin change request: signed in, an admin whose sign-in may
/// make changes, and a valid form from this origin.
async fn change_request(app: &App, req: Request<Incoming>) -> Result<Signed, Stop> {
    let s = signed_in(app, &req).await?;
    require_admin(&s)?;
    let (title, text) = match s.viewer.changes {
        Changes::Allowed => {
            check_post(app, &s, req).await?;
            return Ok(s);
        }
        Changes::NeedMfa => (
            "Multi-factor sign-in required",
            format!("{} Nothing was changed.", pages::NEED_MFA),
        ),
        Changes::NeedRecentSignIn | Changes::NotAdmin => (
            "Sign in again to make changes",
            format!(
                "Changes need a sign-in from the last {}. Nothing was changed.",
                duration_words(app.config.console.change_max_age.as_secs() as i64)
            ),
        ),
    };
    let again = warren_console::html!(
        "<p><a class=\"btn primary\" href=\"{}\">Sign in again</a></p>",
        pages::start_url(&return_to(&req), true)
    );
    Err(Box::new(html(
        StatusCode::FORBIDDEN,
        pages::message(Some(&s.viewer), title, &text, Some(again)),
    )))
}

fn console_actor(s: &Signed) -> Actor {
    Actor::Console {
        id: s.user.id.clone(),
        email: s.user.email.clone(),
    }
}

fn after_action(page: &str, done: &str, id: &str) -> Response<Body> {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    ser.append_pair("done", done).append_pair("id", id);
    see_other(&format!("{page}?{}", ser.finish()))
}

async fn user_action(app: &App, req: Request<Incoming>, id: &str, action: &str) -> Response<Body> {
    let s = match change_request(app, req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if id == s.user.id {
        return html(
            StatusCode::CONFLICT,
            pages::message(
                Some(&s.viewer),
                "Not on yourself",
                "You cannot disable or enable your own account from the console. Ask another admin, or use the admin API on the control plane's host.",
                None,
            ),
        );
    }
    // Only an exact user ID: the admin API's lookup by email or subject is
    // for people typing commands, not for links.
    match app.store.user(id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_page(
                Some(&s.viewer),
                &ApiError::not_found(format!("There is no user {id}.")),
            );
        }
        Err(e) => return error_page(Some(&s.viewer), &e.into()),
    }
    match crate::admin::set_user_disabled(app, id, action == "disable", &console_actor(&s)).await {
        Ok((id, true)) => after_action("/console/users", action, &id),
        Ok((id, false)) => after_action("/console/users", "unchanged", &id),
        Err(e) => error_page(Some(&s.viewer), &e),
    }
}

async fn device_action(
    app: &App,
    req: Request<Incoming>,
    id: &str,
    action: &str,
) -> Response<Body> {
    let s = match change_request(app, req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    match crate::admin::device_action(app, id, action, &console_actor(&s)).await {
        Ok(true) => after_action("/console/devices", action, id),
        Ok(false) => after_action("/console/devices", "unchanged", id),
        Err(e) => error_page(Some(&s.viewer), &e),
    }
}

// What the pages show.

fn latest_certificates(
    certs: &[crate::store::CurrentCertificate],
    kind: &str,
) -> HashMap<String, i64> {
    let mut out: HashMap<String, i64> = HashMap::new();
    for c in certs.iter().filter(|c| c.kind == kind) {
        let t = out.entry(c.subject_id.clone()).or_default();
        *t = (*t).max(c.not_after);
    }
    out
}

async fn node_rows(app: &App) -> Result<Vec<NodeRow>, ApiError> {
    let nodes = app.store.nodes().await?;
    let presence = app.presence.snapshot();
    let acks: HashMap<String, i64> = app.store.node_last_acks().await?.into_iter().collect();
    let certs = latest_certificates(&app.store.current_certificates().await?, "node");
    Ok(nodes
        .into_iter()
        .filter(|n| n.revoked_at.is_none())
        .map(|n| {
            let p = presence.get(&n.id).copied().unwrap_or_default();
            let ack = acks.get(&n.id).map(|ms| ms / 1000).unwrap_or(0);
            let last_seen = p.last_seen.max(ack);
            NodeRow {
                connected: p.open > 0,
                connected_since: (p.open > 0).then_some(p.since),
                last_seen: (last_seen > 0).then_some(last_seen),
                cert_not_after: certs.get(&n.id).copied(),
                id: n.id,
                role: n.role,
                name: n.name,
                group: n.group,
                dns_names: n.dns_names,
                joined_at: n.created_at,
            }
        })
        .collect())
}

fn policy_summary(app: &App, bundle_version: Option<u64>) -> PolicySummary {
    let status = app.policy();
    match &status.compiled {
        Some(c) => PolicySummary {
            loaded: true,
            digest: c.policy.digest.clone(),
            rules: c.policy.rules.len(),
            apps: c.apps.len(),
            loaded_at: status.loaded_at,
            errors: status.errors.clone(),
            warnings: status.warnings.clone(),
            bundle_version,
        },
        None => PolicySummary {
            errors: status.errors.clone(),
            ..PolicySummary::default()
        },
    }
}

fn users_by_id(users: &[User]) -> HashMap<String, String> {
    users
        .iter()
        .map(|u| (u.id.clone(), display_name(u)))
        .collect()
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter()
        .fold(v, |v, k| &v[*k])
        .as_str()
        .unwrap_or_default()
}

fn endpoint(v: &Value) -> String {
    let ip = v["ip"].as_str().unwrap_or("?");
    let port = v["port"].as_u64().unwrap_or(0);
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn decision_row(v: &Value, names: &HashMap<String, String>) -> DecisionRow {
    let user_id = str_at(v, &["actor", "user", "uid"]).to_owned();
    let dst = &v["dst_endpoint"];
    let destination = match dst["hostname"].as_str() {
        Some(h) => format!("{h}:{}", dst["port"].as_u64().unwrap_or(0)),
        None => endpoint(dst),
    };
    DecisionRow {
        id: audit::decision_id(v).unwrap_or_default().to_owned(),
        time_ms: v["time"].as_i64().unwrap_or(0),
        allowed: v["action_id"] == 1,
        user: names
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| user_id.clone()),
        user_id,
        device: str_at(v, &["device", "uid"]).to_owned(),
        app: str_at(v, &["unmapped", "warren", "app"]).to_owned(),
        destination,
        protocol: str_at(v, &["connection_info", "protocol_name"]).to_owned(),
        reason: str_at(v, &["unmapped", "warren", "reason"]).to_owned(),
        message: str_at(v, &["status_detail"]).to_owned(),
        connector: match str_at(v, &["observer", "name"]) {
            "" => str_at(v, &["metadata", "log_provider"]).to_owned(),
            name => name.to_owned(),
        },
    }
}

async fn overview(app: &App, viewer: &Viewer) -> Result<Overview, ApiError> {
    let users = app.store.users().await?;
    let devices = app.store.devices().await?;
    let certs = app.store.current_certificates().await?;
    let bundle = app.store.latest_bundle().await?;
    let latency = app
        .store
        .latency_summary(warren_core::params::REVOCATION_DEADLINE.as_millis() as i64)
        .await?;
    let names = users_by_id(&users);
    let recent = app.recent.newest_first();
    let since_ms = (viewer.now - 15 * 60) * 1000;
    let devices_recent: BTreeSet<&str> = recent
        .iter()
        .filter(|v| v["action_id"] == 1 && v["time"].as_i64().unwrap_or(0) >= since_ms)
        .map(|v| str_at(v, &["device", "uid"]))
        .filter(|d| !d.is_empty())
        .collect();
    let count = |status: &str| {
        devices
            .iter()
            .filter(|d| d.status.as_str() == status)
            .count()
    };
    let certified: BTreeSet<&str> = certs
        .iter()
        .filter(|c| c.kind == "client")
        .map(|c| c.subject_id.as_str())
        .collect();
    Ok(Overview {
        trust_domain: app.config.trust_domain.clone(),
        public_url: app.config.public_url.clone(),
        users: users.len(),
        users_disabled: users.iter().filter(|u| u.disabled).count(),
        devices: DeviceCounts {
            approved: count("approved"),
            pending: count("pending"),
            disabled: count("disabled"),
            revoked: count("revoked"),
        },
        devices_certified: devices
            .iter()
            .filter(|d| d.status.as_str() == "approved" && certified.contains(d.id.as_str()))
            .count(),
        devices_recent: devices_recent.len(),
        nodes: node_rows(app).await?,
        policy: policy_summary(app, bundle.map(|b| b.version)),
        recent_denies: recent
            .iter()
            .filter(|v| v["action_id"] != 1)
            .take(5)
            .map(|v| decision_row(v, &names))
            .collect(),
        revocation: Some(Latency {
            count: latency.count,
            p50_ms: latency.p50_ms,
            p99_ms: latency.p99_ms,
            deadline_ms: warren_core::params::REVOCATION_DEADLINE.as_millis() as i64,
            over_deadline: latency.over_deadline,
        }),
    })
}

/// Rule IDs (`<policy>/<rule>`) by the groups they name.
fn rules_by_group(app: &App) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(c) = app.compiled() {
        for p in &c.objects.policies {
            for r in &p.rules {
                for g in &r.who.groups {
                    out.entry(g.clone())
                        .or_default()
                        .push(format!("{}/{}", p.meta.name, r.name));
                }
            }
        }
    }
    out
}

async fn users(app: &App) -> Result<(Vec<UserRow>, Vec<GroupRow>), ApiError> {
    let users = app.store.users().await?;
    let devices = app.store.devices().await?;
    let rows = users
        .iter()
        .map(|u| UserRow {
            id: u.id.clone(),
            email: u.email.clone(),
            subject: u.subject.clone(),
            issuer: u.issuer.clone(),
            groups: u.groups.clone(),
            disabled: u.disabled,
            last_auth_at: u.last_auth_at,
            devices: devices.iter().filter(|d| d.users.contains(&u.id)).count(),
            admin: is_admin(app, u),
        })
        .collect();
    let mut members: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for u in &users {
        for g in &u.groups {
            members.entry(g.clone()).or_default().push(display_name(u));
        }
    }
    let rules = rules_by_group(app);
    for g in rules.keys() {
        members.entry(g.clone()).or_default();
    }
    let groups = members
        .into_iter()
        .map(|(name, members)| GroupRow {
            rules: rules.get(&name).cloned().unwrap_or_default(),
            name,
            members,
        })
        .collect();
    Ok((rows, groups))
}

fn device_row(d: &Device, names: &HashMap<String, String>, certified: Option<i64>) -> DeviceRow {
    let os = [d.platform.os.as_str(), d.platform.os_version.as_str()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    DeviceRow {
        id: d.id.clone(),
        status: d.status.as_str().into(),
        users: d
            .users
            .iter()
            .map(|u| names.get(u).cloned().unwrap_or_else(|| u.clone()))
            .collect(),
        hostname: d.platform.hostname.clone(),
        os,
        model: d.platform.model.clone(),
        key_storage: d.key_storage.clone(),
        trust_class: d.trust_class,
        tunnel: format!("{} {}", d.tunnel_v4, d.tunnel_v6),
        created_at: d.created_at,
        certified_until: certified,
    }
}

async fn devices(app: &App) -> Result<Vec<DeviceRow>, ApiError> {
    let users = app.store.users().await?;
    let names = users_by_id(&users);
    let certs = latest_certificates(&app.store.current_certificates().await?, "client");
    let mut devices = app.store.devices().await?;
    // Pending first: they are what an admin comes here to act on.
    devices.sort_by_key(|d| (d.status.as_str() != "pending", -d.created_at));
    Ok(devices
        .iter()
        .map(|d| device_row(d, &names, certs.get(&d.id).copied()))
        .collect())
}

fn ports(list: &[warren_core::policy_bundle::PortRange]) -> String {
    list.iter()
        .map(|p| {
            if p.from == p.to {
                p.from.to_string()
            } else {
                format!("{}-{}", p.from, p.to)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn destination_rows(app: &model::App) -> Vec<DestinationRow> {
    app.destinations
        .iter()
        .map(|d| DestinationRow {
            target: match &d.kind {
                DestinationKind::Host {
                    host,
                    target: Some(t),
                } => format!("{host} → {t}"),
                DestinationKind::Host { host, target: None } => host.to_string(),
                DestinationKind::Cidr(c) => c.to_string(),
            },
            protocol: d.protocol.as_str().into(),
            ports: ports(&d.ports),
        })
        .collect()
}

async fn apps(app: &App) -> Result<(Vec<AppRow>, Vec<GroupScope>), ApiError> {
    let Some(compiled) = app.compiled() else {
        return Ok((Vec::new(), Vec::new()));
    };
    let nodes = node_rows(app).await?;
    let objects = &compiled.objects;
    let rows = objects
        .apps
        .iter()
        .map(|a| AppRow {
            name: a.meta.name.clone(),
            labels: a
                .meta
                .labels
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect(),
            connector_group: a.connector_group.clone(),
            destinations: destination_rows(a),
            discoverable: a.discoverable,
            server_initiated: a.server_initiated_flows,
            source: a.meta.source.to_string(),
            rules: objects
                .policies
                .iter()
                .flat_map(|p| {
                    p.rules
                        .iter()
                        .filter(|r| what_matches(&r.what, a))
                        .map(move |r| format!("{}/{}", p.meta.name, r.name))
                })
                .collect(),
        })
        .collect();
    let groups = objects
        .groups
        .iter()
        .map(|g| GroupScope {
            name: g.meta.name.clone(),
            domains: g
                .destination_domains
                .iter()
                .map(|d| d.to_string())
                .collect(),
            cidrs: g.destination_cidrs.iter().map(|c| c.to_string()).collect(),
            client_names: g.client_names.iter().map(|d| d.to_string()).collect(),
            connectors: nodes
                .iter()
                .filter(|n| n.role == "connector" && n.group.as_deref() == Some(&g.meta.name))
                .cloned()
                .collect(),
            source: g.meta.source.to_string(),
        })
        .collect();
    Ok((rows, groups))
}

fn duration_words(secs: i64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

fn conditions(w: &model::When) -> Vec<String> {
    let mut out = Vec::new();
    if !w.posture.is_empty() {
        out.push(format!("device passes {}", w.posture.join(", ")));
    }
    if let Some(age) = w.auth.max_age {
        out.push(format!("signed in within {}", duration_words(age)));
    }
    if w.auth.mfa {
        out.push("signed in with MFA".into());
    }
    if let Some(via) = &w.via {
        let names: Vec<&str> = via
            .iter()
            .map(|v| match v {
                model::Via::Client => "the warren app",
                model::Via::Browser => "a browser",
            })
            .collect();
        out.push(format!("through {}", names.join(" or ")));
    }
    if let Some(s) = &w.schedule {
        out.push(format!("during {} ({})", s.text, s.timezone));
    }
    if !w.network.is_empty() {
        let nets: Vec<String> = w.network.iter().map(|n| n.to_string()).collect();
        out.push(format!("from {}", nets.join(", ")));
    }
    out
}

async fn policies(app: &App) -> Result<PolicyPage, ApiError> {
    let bundle = app.store.latest_bundle().await?;
    let status = app.policy();
    let mut page = PolicyPage {
        dir: app.config.policy_dir.display().to_string(),
        summary: policy_summary(app, bundle.map(|b| b.version)),
        attempted_at: status.attempted_at,
        ..PolicyPage::default()
    };
    if let Some(c) = &status.compiled {
        page.cedar = c.policy.policies.clone();
        page.policies = c
            .objects
            .policies
            .iter()
            .map(|p| PolicyDoc {
                name: p.meta.name.clone(),
                source: p.meta.source.to_string(),
                rules: p
                    .rules
                    .iter()
                    .map(|r| RuleRow {
                        id: format!("{}/{}", p.meta.name, r.name),
                        name: r.name.clone(),
                        deny: r.deny,
                        who: r
                            .who
                            .users
                            .iter()
                            .cloned()
                            .chain(r.who.groups.iter().map(|g| format!("group:{g}")))
                            .collect(),
                        what: r
                            .what
                            .apps
                            .iter()
                            .cloned()
                            .chain(
                                r.what
                                    .match_labels
                                    .iter()
                                    .map(|(k, v)| format!("label:{k}={v}")),
                            )
                            .collect(),
                        when: conditions(&r.when),
                        source: format!("{}:{}", p.meta.source.file, r.line),
                    })
                    .collect(),
            })
            .collect();
    }
    Ok(page)
}

async fn decisions(app: &App, denied_only: bool) -> Result<Vec<DecisionRow>, ApiError> {
    let names = users_by_id(&app.store.users().await?);
    Ok(app
        .recent
        .newest_first()
        .iter()
        .filter(|v| !denied_only || v["action_id"] != 1)
        .map(|v| decision_row(v, &names))
        .collect())
}

/// What a reason code means, for an admin.
fn reason_text(code: &str, allowed: bool) -> String {
    if allowed {
        return "A rule allowed this flow and all of its conditions held.".into();
    }
    match code {
        "no_rule" => "No rule allows this user to reach this app, or a deny rule blocks it. Anything no rule allows is denied.",
        "request_access" => "No rule allows it, but the app is discoverable: the user can request access.",
        "posture_failed" => "The device failed a posture check a rule requires.",
        "reauth_required" => "The user's sign-in is older than a rule allows; they need to sign in again.",
        "mfa_required" => "A rule requires a multi-factor sign-in, and this one was not.",
        "outside_schedule" => "A rule allows access only at certain times, and this was outside them.",
        "network_not_allowed" => "A rule allows access only from certain networks, and the device was elsewhere.",
        "device_not_approved" => "The device is not approved.",
        "revoked" => "The user, device, sign-in or certificate was revoked.",
        "grant_expired" => "A just-in-time grant had expired.",
        "out_of_scope" => "The destination is outside every app, or outside the connector group's scope.",
        "name_not_in_app" => "The client used a name that does not belong to the app.",
        "server_initiated_blocked" => "A server tried to open a flow toward the client, which this app does not allow.",
        _ => "The connector refused this flow.",
    }
    .into()
}

async fn explain(app: &App, id: &str) -> Result<Option<Explanation>, ApiError> {
    let Some(record) = app.recent.find(id) else {
        return Ok(None);
    };
    let names = users_by_id(&app.store.users().await?);
    let decision = decision_row(&record, &names);
    let w = &record["unmapped"]["warren"];
    let failed = w["failed_condition"].as_str().map(str::to_owned);
    let compiled = app.compiled();
    let rules = w["rules"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|rule_id| {
            let info = compiled
                .as_ref()
                .and_then(|c| c.policy.rules.iter().find(|r| r.id == rule_id));
            match info {
                Some(info) => RuleExplanation {
                    id: rule_id.to_owned(),
                    found: true,
                    effect: info.effect.clone(),
                    source: info.source.clone(),
                    conditions: info
                        .conditions
                        .iter()
                        .map(|c| ConditionRow {
                            kind: c.kind.clone(),
                            message: c.message.replace("{app}", &decision.app),
                            expression: c.expression.clone(),
                            failed: failed.as_deref() == Some(c.kind.as_str()),
                        })
                        .collect(),
                },
                None => RuleExplanation {
                    id: rule_id.to_owned(),
                    ..RuleExplanation::default()
                },
            }
        })
        .collect();
    let translated = match &w["translated_dst"] {
        Value::Object(_) => Some(endpoint(&w["translated_dst"])),
        _ => None,
    };
    let current = app.store.latest_bundle().await?.map(|b| b.version);
    Ok(Some(Explanation {
        reason_text: reason_text(&decision.reason, decision.allowed),
        failed_condition: failed,
        policy_version: w["policy_version"].as_u64(),
        current_version: current,
        rules,
        source: endpoint(&record["src_endpoint"]),
        translated,
        record: serde_json::to_string_pretty(&record).unwrap_or_default(),
        decision,
    }))
}

async fn portal(app: &App, s: &Signed) -> Result<Portal, ApiError> {
    let names = users_by_id(std::slice::from_ref(&s.user));
    let certs = latest_certificates(&app.store.current_certificates().await?, "client");
    let devices = app
        .store
        .devices()
        .await?
        .iter()
        .filter(|d| d.users.contains(&s.user.id))
        .map(|d| device_row(d, &names, certs.get(&d.id).copied()))
        .collect();
    let compiled = app.compiled();
    let apps = match &compiled {
        Some(c) => {
            let access = c.entitlements(&App::user_entity(&s.user));
            c.objects
                .apps
                .iter()
                .filter_map(|a| {
                    access.get(&a.meta.name).map(|level| PortalApp {
                        name: a.meta.name.clone(),
                        requestable: *level == Access::Requestable,
                        destinations: destination_rows(a)
                            .into_iter()
                            .map(|mut d| {
                                // Users see the names they type, not where
                                // the connector sends them.
                                if let Some((host, _)) = d.target.split_once(" → ") {
                                    d.target = host.to_owned();
                                }
                                d
                            })
                            .collect(),
                    })
                })
                .collect()
        }
        None => Vec::new(),
    };
    Ok(Portal {
        apps,
        devices,
        public_url: app.config.public_url.clone(),
        policy_loaded: compiled.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_console_paths_are_followed_after_sign_in() {
        for good in ["/console/", "/console/devices?status=pending", "/console"] {
            assert_eq!(safe_next(Some(good)), good);
        }
        for bad in [
            "https://evil.example/",
            "//evil.example/console/",
            "/console//evil",
            "/console/\\evil",
            "/v1/admin/users",
            "/consolex",
            "/console/a b",
        ] {
            assert_eq!(safe_next(Some(bad)), "/console/", "{bad}");
        }
        assert_eq!(safe_next(None), "/console/");
    }

    #[test]
    fn cookies_are_read_from_every_header() {
        let req = Request::builder()
            .header("cookie", "a=1; __Host-warren-console=tok")
            .header("cookie", "b=2")
            .body(())
            .unwrap();
        assert_eq!(read_cookie(&req, SESSION_COOKIE).as_deref(), Some("tok"));
        assert_eq!(read_cookie(&req, "b").as_deref(), Some("2"));
        assert_eq!(read_cookie(&req, LOGIN_COOKIE), None);
    }

    #[test]
    fn form_tokens_depend_on_the_session() {
        assert_eq!(csrf_token("a"), csrf_token("a"));
        assert_ne!(csrf_token("a"), csrf_token("b"));
        assert_eq!(csrf_token("a").len(), 43);
    }

    #[test]
    fn console_paths() {
        assert!(is_console_path("/"));
        assert!(is_console_path("/console"));
        assert!(is_console_path("/console/users"));
        assert!(!is_console_path("/consoles"));
        assert!(!is_console_path("/v1/auth/callback"));
    }
}
