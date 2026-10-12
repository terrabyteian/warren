//! The HTTPS API: link D for clients and link E for relays and connectors
//! (docs/protocol.md section 11). Every path is under the versioned `/v1`
//! prefix except discovery.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;
use warren_core::api::{
    CertificateRequest, CertificateResponse, DeviceInfo, Discovery, EnrollRequest, EntitledApp,
    EntitledDestination, Entitlements, Relay, SESSION_REQUEST_TYP, Session as SessionInfo,
    SessionRequest, UserInfo,
};
use warren_core::cert;
use warren_core::clock;
use warren_core::events::AckRequest;
use warren_core::identity::{AUTH_TIME_UNKNOWN, NodeRole, TrustClass, WarrenIdentity, WarrenUri};
use warren_core::join::{self, BundleJson, JoinRequest, JoinResponse, JoinToken, sha256_hex};
use warren_core::jose::{self, b64url};
use warren_core::keys::sha256;
use warren_core::params::{INFRA_CERT_LIFETIME, PROTOCOL_VERSION, REVOCATION_DEADLINE};
use warren_core::pki::NodeIdentity;
use warren_policy::compile::Access;
use warren_policy::names::{DomainPattern, is_host_name};

use crate::app::{App, new_secret, secret_hash};
use crate::audit::{self, Activity, Actor};
use crate::config::Approval;
use crate::store::{AuthCode, AuthRequest, Device, DeviceStatus, Enrollment, Node, Session};
use crate::stream;
use crate::web::{
    self, ApiError, Body, Handler, MAX_BODY, Peer, check_protocol, json, page, param, problem,
    query, read_body, read_json, redirect,
};

/// How long a sign-in may take at the IdP.
const AUTH_REQUEST_LIFETIME: i64 = 600;
/// How long the one-time code handed to the client is valid.
const AUTH_CODE_LIFETIME: i64 = 120;
/// The largest body read before the caller is authenticated.
const PREAUTH_BODY: usize = 16 << 10;

/// Every route the HTTPS API serves, as (method, path). The OpenAPI
/// description in `docs/api/openapi.yaml` is tested against this list.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/.well-known/warren"),
    ("GET", "/v1/auth/authorize"),
    ("GET", "/v1/auth/callback"),
    ("POST", "/v1/auth/token"),
    ("POST", "/v1/devices"),
    ("GET", "/v1/devices/current"),
    ("POST", "/v1/certificates"),
    ("GET", "/v1/entitlements"),
    ("POST", "/v1/join"),
    ("GET", "/v1/node/bundle"),
    ("GET", "/v1/node/events"),
    ("POST", "/v1/node/events/ack"),
    ("POST", "/v1/node/audit"),
    ("POST", "/v1/node/certificate"),
    ("GET", "/v1/node/policy-key"),
];

/// The HTTPS API handler.
pub struct Api(pub Arc<App>);

impl Handler for Api {
    async fn handle(self: Arc<Self>, req: Request<Incoming>, peer: Arc<Peer>) -> Response<Body> {
        let app = self.0.clone();
        match route(app, req, peer).await {
            Ok(resp) => resp,
            Err(e) => problem(&e),
        }
    }
}

async fn route(
    app: Arc<App>,
    req: Request<Incoming>,
    peer: Arc<Peer>,
) -> Result<Response<Body>, ApiError> {
    check_protocol(&req)?;
    let path = req.uri().path().to_owned();
    if crate::console::is_console_path(&path) {
        return Ok(crate::console::route(&app, req).await);
    }
    let method = req.method().clone();
    // Besides the console, the operator's certificate serves sign-in and
    // enrollment only; every other call goes where the trust bundle verifies
    // the control plane.
    let pinned_only = !matches!(
        path.as_str(),
        "/.well-known/warren"
            | "/v1/auth/authorize"
            | "/v1/auth/callback"
            | "/v1/auth/token"
            | "/v1/devices"
            | "/v1/devices/current"
    );
    if pinned_only
        && !app
            .config
            .presents_own_certificate(peer.server_name.as_deref())
    {
        return Err(ApiError::new(
            StatusCode::MISDIRECTED_REQUEST,
            "misdirected_request",
            format!(
                "Make this call at {}/v1, where the control plane presents the certificate the deployment trust bundle verifies.",
                app.config.internal_url()
            ),
        ));
    }
    match (method, path.as_str()) {
        (Method::GET, "/.well-known/warren") => Ok(discovery(&app)),
        (Method::GET, "/v1/auth/authorize") => authorize(&app, &req).await,
        (Method::GET, "/v1/auth/callback") => callback(&app, &req).await,
        (Method::POST, "/v1/auth/token") => token(&app, req).await,
        (Method::POST, "/v1/devices") => enroll(&app, req).await,
        (Method::GET, "/v1/devices/current") => current_device(&app, &req).await,
        (Method::POST, "/v1/certificates") => client_certificate(&app, req).await,
        (Method::GET, "/v1/entitlements") => entitlements(&app, &req).await,
        (Method::POST, "/v1/join") => join(&app, req).await,
        (Method::GET, "/v1/node/bundle") => node_bundle(&app, &peer).await,
        (Method::GET, "/v1/node/events") => node_events(app, &req, &peer).await,
        (Method::POST, "/v1/node/events/ack") => node_ack(&app, req, &peer).await,
        (Method::POST, "/v1/node/audit") => node_audit(&app, req, &peer).await,
        (Method::POST, "/v1/node/certificate") => node_certificate(&app, req, &peer).await,
        (Method::GET, "/v1/node/policy-key") => node_policy_key(&app, &peer).await,
        _ => Err(ApiError::not_found(format!("no endpoint {path}"))),
    }
}

fn discovery(app: &App) -> Response<Body> {
    let base = &app.config.public_url;
    json(
        StatusCode::OK,
        &Discovery {
            trust_domain: app.config.trust_domain.clone(),
            api_base: format!("{base}/v1"),
            authorize_endpoint: format!("{base}/v1/auth/authorize"),
            token_endpoint: format!("{base}/v1/auth/token"),
            trust_bundle: app.authority.trust_bundle(),
            protocol_versions: vec![PROTOCOL_VERSION],
        },
    )
}

/// Whether a native app may receive the sign-in code at `uri`: an http
/// loopback redirect on an IP literal with any port (RFC 8252 section 7.3),
/// or a URI the operator configured exactly.
fn redirect_allowed(app: &App, uri: &str) -> bool {
    if app.config.redirect_uris.iter().any(|u| u == uri) {
        return true;
    }
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.parse::<u16>().is_ok() => h,
        Some(_) => return false,
        None => authority,
    };
    matches!(host, "127.0.0.1" | "[::1]") && !uri.contains('#')
}

/// RFC 7636 section 4.1: 43 to 128 unreserved characters.
fn pkce_value_ok(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
}

pub(crate) fn s256(verifier: &str) -> String {
    b64url(&sha256(verifier.as_bytes()))
}

fn with_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{}", ser.finish())
}

async fn authorize<B>(app: &App, req: &Request<B>) -> Result<Response<Body>, ApiError> {
    let q = query(req)?;
    let bad = |text: &str| {
        Ok(page(
            StatusCode::BAD_REQUEST,
            "Sign-in could not start",
            text,
        ))
    };
    let Some(redirect_uri) = param(&q, "redirect_uri") else {
        return bad(
            "The warren app did not say where to return. Start sign-in again from the app.",
        );
    };
    if !redirect_allowed(app, redirect_uri) {
        return bad("The sign-in request names a return address this deployment does not accept.");
    }
    let challenge = param(&q, "code_challenge").unwrap_or("");
    if param(&q, "code_challenge_method") != Some("S256") || !pkce_value_ok(challenge) {
        return bad("The sign-in request must use PKCE with S256. Update the warren app.");
    }
    let client_state = param(&q, "state").unwrap_or("");
    if client_state.is_empty() || client_state.len() > 512 {
        return bad("The sign-in request has no valid state. Start sign-in again from the app.");
    }
    // `prompt=login` is the client's "sign in again": the IdP must
    // authenticate the user afresh rather than reuse its own session.
    let login = match param(&q, "prompt") {
        None => false,
        Some("login") => true,
        Some(_) => {
            return bad("The sign-in request asks for an unknown prompt. Update the warren app.");
        }
    };
    // Ask the IdP for a sign-in recent enough for every freshness rule.
    let max_age = app.compiled().and_then(|c| c.shortest_max_age());
    let state = new_secret()?;
    let nonce = new_secret()?;
    let verifier = new_secret()?;
    app.store
        .insert_auth_request(
            &secret_hash(&state),
            &AuthRequest {
                client_redirect_uri: redirect_uri.into(),
                client_state: client_state.into(),
                client_challenge: challenge.into(),
                nonce: nonce.clone(),
                idp_verifier: verifier.clone(),
                created_at: clock::now_secs(),
                login,
            },
            clock::now_secs() + AUTH_REQUEST_LIFETIME,
        )
        .await?;
    let callback = format!("{}/v1/auth/callback", app.config.public_url);
    match app
        .idp
        .authorize_url(&callback, &state, &nonce, &s256(&verifier), max_age, login)
        .await
    {
        Ok(url) => Ok(redirect(&url)),
        Err(e) => {
            crate::log::error("idp", &e.to_string());
            Ok(page(
                StatusCode::BAD_GATEWAY,
                "Sign-in is unavailable",
                "warren cannot reach your identity provider right now. Try again in a minute.",
            ))
        }
    }
}

/// How a sign-in at the IdP ended, once its callback arrived.
pub(crate) enum IdpSignIn {
    /// The IdP refused it or the user cancelled.
    Refused,
    /// The IdP's answer could not be verified.
    Unverified,
    /// The user is disabled in warren.
    Disabled,
    /// Signed in.
    Done {
        /// The user, as the IdP now describes them.
        user: crate::store::User,
        /// IdP authentication time, Unix seconds.
        auth_time: i64,
        /// When the IdP issued the ID token, Unix seconds.
        issued_at: i64,
        /// Whether the sign-in used MFA.
        mfa: bool,
    },
}

/// Finishes a sign-in at the IdP for `pending`: verifies the IdP's answer
/// in the callback query `q`, records the user, and audits every refusal.
/// The caller audits success, since what was signed in to differs.
pub(crate) async fn finish_idp_sign_in(
    app: &App,
    q: &[(String, String)],
    pending: &AuthRequest,
) -> Result<IdpSignIn, ApiError> {
    let fail = |message: &str| {
        let mut r = audit::record(Activity::Logon, false, &Actor::Anonymous, message);
        r.insert("auth_protocol".into(), "OIDC".into());
        app.audit(r);
    };
    if let Some(error) = param(q, "error") {
        fail(&format!("the IdP refused the sign-in: {error}"));
        return Ok(IdpSignIn::Refused);
    }
    let callback = format!("{}/v1/auth/callback", app.config.public_url);
    let signin = match app
        .idp
        .exchange(
            param(q, "code").unwrap_or(""),
            &pending.idp_verifier,
            &callback,
            &pending.nonce,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            crate::log::error("idp", &e.to_string());
            fail("the IdP's answer could not be verified");
            return Ok(IdpSignIn::Unverified);
        }
    };
    let auth_time = signin.auth_time.unwrap_or_else(|| {
        crate::log::warn(
            "idp",
            "the ID token has no auth_time, so how recently the user authenticated is unknown and rules with auth.maxAge will ask them to sign in again",
        );
        AUTH_TIME_UNKNOWN as i64
    });
    let (user, changed) = app
        .store
        .record_sign_in(
            &app.config.idp.issuer,
            &signin.subject,
            &signin.email,
            &signin.groups,
            auth_time,
        )
        .await?;
    if changed {
        app.request_publish();
    }
    if user.disabled {
        let mut r = audit::record(
            Activity::Logon,
            false,
            &Actor::User {
                id: user.id.clone(),
                email: user.email.clone(),
            },
            "sign-in refused: the user is disabled",
        );
        r.insert("auth_protocol".into(), "OIDC".into());
        app.audit(r);
        return Ok(IdpSignIn::Disabled);
    }
    Ok(IdpSignIn::Done {
        user,
        auth_time,
        issued_at: signin.issued_at,
        mfa: signin.mfa,
    })
}

async fn callback<B>(app: &App, req: &Request<B>) -> Result<Response<Body>, ApiError> {
    let q = query(req)?;
    let Some(pending) = app
        .store
        .take_auth_request(&secret_hash(param(&q, "state").unwrap_or("")))
        .await?
    else {
        return Ok(page(
            StatusCode::BAD_REQUEST,
            "This sign-in link has expired",
            "It was already used or is too old. Start sign-in again from the warren app.",
        ));
    };
    if pending.client_redirect_uri == crate::console::REDIRECT {
        return crate::console::finish_sign_in(app, req, &q, &pending).await;
    }
    let back = |pairs: &[(&str, &str)]| {
        let mut all = pairs.to_vec();
        all.push(("state", pending.client_state.as_str()));
        Ok(redirect(&with_query(&pending.client_redirect_uri, &all)))
    };
    let (user, auth_time, mfa) = match finish_idp_sign_in(app, &q, &pending).await? {
        IdpSignIn::Refused => {
            return back(&[
                ("error", "access_denied"),
                (
                    "error_description",
                    "Your identity provider did not complete the sign-in.",
                ),
            ]);
        }
        IdpSignIn::Unverified => {
            return back(&[
                ("error", "server_error"),
                (
                    "error_description",
                    "warren could not verify the sign-in with your identity provider.",
                ),
            ]);
        }
        IdpSignIn::Disabled => {
            return back(&[
                ("error", "access_denied"),
                (
                    "error_description",
                    "Your warren account is disabled. Contact your administrator.",
                ),
            ]);
        }
        IdpSignIn::Done {
            user,
            auth_time,
            mfa,
            ..
        } => (user, auth_time, mfa),
    };
    let actor = Actor::User {
        id: user.id.clone(),
        email: user.email.clone(),
    };
    let code = new_secret()?;
    app.store
        .insert_auth_code(
            &secret_hash(&code),
            &AuthCode {
                user_id: user.id.clone(),
                client_challenge: pending.client_challenge.clone(),
                client_redirect_uri: pending.client_redirect_uri.clone(),
                auth_time,
                mfa,
            },
            clock::now_secs() + AUTH_CODE_LIFETIME,
        )
        .await?;
    let mut r = audit::record(Activity::Logon, true, &actor, "signed in at the IdP");
    r.insert("auth_protocol".into(), "OIDC".into());
    r.insert("is_mfa".into(), mfa.into());
    r.insert(
        "user".into(),
        json!({ "uid": user.id, "email_addr": user.email, "groups": user.groups.iter().map(|g| json!({ "name": g })).collect::<Vec<_>>() }),
    );
    app.audit(r);
    back(&[("code", &code)])
}

async fn token(app: &App, req: Request<Incoming>) -> Result<Response<Body>, ApiError> {
    let body = read_body(req, PREAUTH_BODY).await?;
    let text = std::str::from_utf8(&body)
        .map_err(|_| ApiError::bad_request("the request must be a JWS"))?;
    let (key, payload) = jose::Unverified::parse(text.trim(), SESSION_REQUEST_TYP)
        .and_then(jose::Unverified::verify_embedded)
        .map_err(|e| {
            ApiError::bad_request(format!("the session request is not validly signed: {e}"))
        })?;
    let request: SessionRequest = serde_json::from_slice(&payload)
        .map_err(|e| ApiError::bad_request(format!("malformed session request: {e}")))?;
    let skew = app.config.clock_skew.as_secs() as i64;
    if request.iat.abs_diff(clock::now_secs()) > skew.unsigned_abs() {
        return Err(ApiError::bad_request(
            "the session request's time is off; check this device's clock",
        ));
    }
    let invalid = || {
        let mut r = audit::record(
            Activity::Create,
            false,
            &Actor::Anonymous,
            "session refused: the sign-in code is unknown, used, expired or its PKCE verifier is wrong",
        );
        r.insert("entity".into(), audit::entity("session", ""));
        app.audit(r);
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "The sign-in code has expired or was already used. Sign in again.",
        )
    };
    let code = app
        .store
        .take_auth_code(&secret_hash(&request.code))
        .await?
        .ok_or_else(invalid)?;
    if code.client_redirect_uri != request.redirect_uri
        || !pkce_value_ok(&request.code_verifier)
        || s256(&request.code_verifier) != code.client_challenge
    {
        return Err(invalid());
    }
    let user = app.store.user(&code.user_id).await?.ok_or_else(invalid)?;
    if user.disabled {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "user_disabled",
            "Your warren account is disabled. Contact your administrator.",
        ));
    }
    let token = format!("wst_{}", new_secret()?);
    let session = Session {
        id: crate::store::new_id("s")?,
        user_id: user.id.clone(),
        public_key: b64url(key.point()),
        auth_time: code.auth_time,
        mfa: code.mfa,
        expires_at: clock::now_secs() + app.config.session_max_lifetime.as_secs() as i64,
        revoked_at: None,
    };
    app.store
        .insert_session(&session, &secret_hash(&token))
        .await?;
    let mut r = audit::record(
        Activity::Create,
        true,
        &Actor::User {
            id: user.id.clone(),
            email: user.email.clone(),
        },
        "session created, bound to a device key",
    );
    r.insert("entity".into(), audit::entity("session", &session.id));
    r.insert(
        "unmapped".into(),
        json!({ "device_key": jose::thumbprint(&key) }),
    );
    app.audit(r);
    Ok(json(
        StatusCode::OK,
        &SessionInfo {
            session_id: session.id,
            token,
            expires_at: session.expires_at,
            user: UserInfo {
                id: user.id,
                email: (!user.email.is_empty()).then_some(user.email),
                groups: user.groups,
            },
            auth_time: session.auth_time,
            mfa: session.mfa,
        },
    ))
}

fn device_info(app: &App, d: &Device) -> DeviceInfo {
    DeviceInfo {
        id: d.id.clone(),
        status: d.status.as_str().into(),
        tunnel_v4: d.tunnel_v4.clone(),
        tunnel_v6: d.tunnel_v6.clone(),
        trust_class: d.trust_class,
        api_base: format!("{}/v1", app.config.internal_url()),
    }
}

/// The key of a verified certificate request.
struct CsrKey {
    /// Its SubjectPublicKeyInfo, DER, which the certificate carries as is.
    spki: Vec<u8>,
    /// Its point, base64url: what sessions and nodes are bound to.
    point: String,
}

/// Parses a base64 PKCS#10 request, verifies its signature, and checks it
/// is signed by `expected` (a base64url point) when given.
fn csr_key(csr: &str, expected: Option<&str>) -> Result<CsrKey, ApiError> {
    let der = STANDARD
        .decode(csr.trim())
        .map_err(|_| ApiError::bad_request("csr must be base64 DER"))?;
    let spki =
        join::verify_certificate_request(&der).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let point =
        b64url(cert::spki_key_bits(&spki).map_err(|e| ApiError::bad_request(e.to_string()))?);
    if let Some(expected) = expected
        && point != expected
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "key_mismatch",
            "The request is not signed by the key this sign-in is bound to. Sign in again from this device.",
        ));
    }
    Ok(CsrKey { spki, point })
}

fn clip(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

async fn enroll(app: &App, req: Request<Incoming>) -> Result<Response<Body>, ApiError> {
    let (session, user) = app
        .credential_session(&req, Activity::Enroll, "device")
        .await?;
    let result = enroll_device(app, req, &session, &user).await;
    if let Err(e) = &result {
        let mut r = audit::record(
            Activity::Enroll,
            false,
            &Actor::User {
                id: user.id.clone(),
                email: user.email.clone(),
            },
            &format!("device refused: {}", e.reason),
        );
        r.insert("entity".into(), audit::entity("device", ""));
        r.insert("unmapped".into(), json!({ "session_id": session.id }));
        app.audit(r);
    }
    result
}

async fn enroll_device(
    app: &App,
    req: Request<Incoming>,
    session: &Session,
    user: &crate::store::User,
) -> Result<Response<Body>, ApiError> {
    let body: EnrollRequest = read_json(req).await?;
    csr_key(&body.csr, Some(&session.public_key))?;
    if !matches!(body.key_storage.as_str(), "secure-enclave" | "software") {
        return Err(ApiError::bad_request(
            "key_storage must be secure-enclave or software",
        ));
    }
    let mut platform = body.platform.clone();
    platform.os = clip(&platform.os);
    platform.os_version = clip(&platform.os_version);
    platform.model = clip(&platform.model);
    platform.hostname = clip(&platform.hostname);
    let status = match app.config.device_approval {
        Approval::Automatic => DeviceStatus::Approved,
        Approval::Manual => DeviceStatus::Pending,
    };
    let (pool_v4, pool_v6) = (app.config.device_pool_v4, app.config.device_pool_v6);
    let (device, enrollment) = app
        .store
        .enroll_device(
            &user.id,
            &session.public_key,
            status,
            &body.key_storage,
            &platform,
            |index| {
                let (v4, v6) = crate::authority::tunnel_addresses(&pool_v4, &pool_v6, index)?;
                Ok((v4.to_string(), v6.to_string()))
            },
        )
        .await?;
    let message = match enrollment {
        Enrollment::Revoked => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "device_revoked",
                "This device has been revoked and cannot be enrolled again.",
            ));
        }
        Enrollment::Created => "device enrolled",
        Enrollment::BoundUser => "enrolled device bound to another user",
        Enrollment::Again => "device enrolled again by the same user",
    };
    let actor = Actor::User {
        id: user.id.clone(),
        email: user.email.clone(),
    };
    let mut r = audit::record(Activity::Enroll, true, &actor, message);
    r.insert("entity".into(), audit::entity("device", &device.id));
    r.insert(
        "unmapped".into(),
        json!({ "key_storage": body.key_storage, "platform": platform, "status": device.status.as_str() }),
    );
    app.audit(r);
    let created = enrollment == Enrollment::Created;
    if created && device.status == DeviceStatus::Approved {
        let mut r = audit::record(
            Activity::Activate,
            true,
            &Actor::System,
            "device approved automatically",
        );
        r.insert("entity".into(), audit::entity("device", &device.id));
        app.audit(r);
    }
    if device.status == DeviceStatus::Approved {
        app.request_publish();
    }
    Ok(json(
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        &device_info(app, &device),
    ))
}

async fn current_device<B>(app: &App, req: &Request<B>) -> Result<Response<Body>, ApiError> {
    let (session, user) = app.session(req).await?;
    match app.store.device_by_key(&session.public_key).await? {
        Some(d) if d.users.contains(&user.id) => Ok(json(StatusCode::OK, &device_info(app, &d))),
        _ => Err(ApiError::not_found("This device is not enrolled yet.")),
    }
}

fn device_refusal(status: DeviceStatus) -> Option<ApiError> {
    let (reason, detail) = match status {
        DeviceStatus::Approved => return None,
        DeviceStatus::Pending => (
            "device_not_approved",
            "This device is waiting for an administrator to approve it.",
        ),
        DeviceStatus::Disabled => (
            "device_disabled",
            "This device has been disabled by an administrator.",
        ),
        DeviceStatus::Revoked => ("device_revoked", "This device has been revoked."),
    };
    Some(ApiError::new(StatusCode::FORBIDDEN, reason, detail))
}

async fn client_certificate(app: &App, req: Request<Incoming>) -> Result<Response<Body>, ApiError> {
    let (session, user) = app
        .credential_session(&req, Activity::Create, "certificate")
        .await?;
    let result = issue_client_certificate(app, req, &session, &user).await;
    if let Err(e) = &result {
        let mut r = audit::record(
            Activity::Create,
            false,
            &Actor::User {
                id: user.id.clone(),
                email: user.email.clone(),
            },
            &format!("user+device certificate refused: {}", e.reason),
        );
        r.insert("entity".into(), audit::entity("certificate", ""));
        r.insert("unmapped".into(), json!({ "session_id": session.id }));
        app.audit(r);
    }
    result
}

async fn issue_client_certificate(
    app: &App,
    req: Request<Incoming>,
    session: &Session,
    user: &crate::store::User,
) -> Result<Response<Body>, ApiError> {
    let body: CertificateRequest = read_json(req).await?;
    let key = csr_key(&body.csr, Some(&session.public_key))?;
    let device = app
        .store
        .device_by_key(&session.public_key)
        .await?
        .filter(|d| d.users.contains(&user.id))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "device_not_enrolled",
                "Enroll this device before requesting a certificate.",
            )
        })?;
    if let Some(e) = device_refusal(device.status) {
        return Err(e);
    }
    // One clock reading for both ends, so notAfter never passes the end of
    // the session (docs/protocol.md section 10.2).
    let now = clock::now_secs();
    let not_after =
        (now + app.config.client_cert_lifetime.as_secs() as i64).min(session.expires_at);
    if not_after - now < 60 {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "reauth_required",
            "Your sign-in is about to end. Sign in again.",
        ));
    }
    let identity = WarrenIdentity {
        session_id: session.id.clone(),
        // A time before the epoch says no more than an unknown one.
        auth_time: u64::try_from(session.auth_time).unwrap_or(AUTH_TIME_UNKNOWN),
        mfa: session.mfa,
        trust_class: TrustClass::from_u64(u64::from(device.trust_class))
            .ok_or_else(ApiError::internal)?,
        tunnel_v4: device.tunnel_v4.parse().map_err(|_| ApiError::internal())?,
        tunnel_v6: device.tunnel_v6.parse().map_err(|_| ApiError::internal())?,
    };
    let issued = app.authority.issue_client(
        &key.spki,
        &user.id,
        &device.id,
        &identity,
        now - app.config.clock_skew.as_secs() as i64,
        not_after,
    )?;
    app.store
        .insert_certificate(
            &issued.serial,
            "client",
            &device.id,
            Some(&user.id),
            Some(&session.id),
            issued.not_before,
            issued.not_after,
        )
        .await?;
    let mut r = audit::record(
        Activity::Create,
        true,
        &Actor::User {
            id: user.id.clone(),
            email: user.email.clone(),
        },
        "user+device certificate issued",
    );
    r.insert(
        "entity".into(),
        audit::entity("certificate", &issued.serial),
    );
    r.insert(
        "unmapped".into(),
        json!({ "device_id": device.id, "session_id": session.id, "not_after": issued.not_after }),
    );
    app.audit(r);
    Ok(json(
        StatusCode::OK,
        &CertificateResponse {
            certificate_chain: app.authority.chain_pem(&issued.der, &app.authority.client),
            serial: issued.serial,
            not_before: issued.not_before,
            not_after: issued.not_after,
            renew_at: issued.renew_at,
        },
    ))
}

/// The DNS names split DNS claims for a set of host patterns: exact names
/// and wildcard base domains, without any that another already covers.
pub fn dns_suffixes(hosts: &[DomainPattern]) -> Vec<String> {
    let mut names: Vec<String> = hosts.iter().map(|h| h.dns_suffix().to_owned()).collect();
    names.sort();
    names.dedup();
    let covered = |n: &str, by: &str| n != by && n.ends_with(&format!(".{by}"));
    names
        .iter()
        .filter(|n| !names.iter().any(|other| covered(n, other)))
        .cloned()
        .collect()
}

async fn entitlements<B>(app: &App, req: &Request<B>) -> Result<Response<Body>, ApiError> {
    let (_, user) = app.session(req).await?;
    let compiled = app.compiled().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "No policy is loaded yet.",
        )
    })?;
    let access = compiled.entitlements(&App::user_entity(&user));
    let mut apps = Vec::new();
    let mut hosts = Vec::new();
    for app_obj in compiled
        .objects
        .apps
        .iter()
        .filter(|a| access.contains_key(&a.meta.name))
    {
        let destinations = app_obj
            .destinations
            .iter()
            .map(|d| {
                let (host, cidr) = match &d.kind {
                    warren_policy::model::DestinationKind::Host { host, .. } => {
                        hosts.push(host.clone());
                        (Some(host.to_string()), None)
                    }
                    warren_policy::model::DestinationKind::Cidr(c) => (None, Some(c.to_string())),
                };
                EntitledDestination {
                    host,
                    cidr,
                    protocol: d.protocol.as_str().into(),
                    ports: d.ports.clone(),
                }
            })
            .collect();
        apps.push(EntitledApp {
            name: app_obj.meta.name.clone(),
            access: match access[&app_obj.meta.name] {
                Access::Allowed => "allowed",
                Access::Requestable => "requestable",
            }
            .into(),
            connector_group: app_obj.connector_group.clone(),
            destinations,
        });
    }
    let relays = app
        .store
        .nodes()
        .await?
        .into_iter()
        .filter(|n| n.role == "relay" && n.revoked_at.is_none())
        .map(|n| Relay {
            id: n.id,
            name: n.name,
            dns_names: n.dns_names,
        })
        .collect();
    let version = app
        .store
        .latest_bundle()
        .await?
        .map(|b| b.version)
        .unwrap_or(0);
    Ok(json(
        StatusCode::OK,
        &Entitlements {
            version,
            apps,
            dns_suffixes: dns_suffixes(&hosts),
            relays,
        },
    ))
}

/// Checks the DNS names a relay will listen on: at most 16 host names,
/// none of them warren's own (a relay certificate naming the control plane
/// or the IdP could stand in for them) or claimed by an app.
pub(crate) fn check_relay_names(app: &App, names: &[String]) -> Result<(), ApiError> {
    if names.len() > 16 || !names.iter().all(|n| is_host_name(n)) {
        return Err(ApiError::bad_request(
            "dns_names must be at most 16 lowercase host names",
        ));
    }
    let reserved = app.config.reserved();
    if let Some(name) = names
        .iter()
        .find(|n| reserved.iter().any(|r| r.eq_ignore_ascii_case(n)))
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "name_reserved",
            format!("{name} is reserved for the control plane or the identity provider"),
        ));
    }
    if let Some(compiled) = app.compiled() {
        for name in names {
            let claimed = compiled.objects.apps.iter().any(|a| {
                a.destinations.iter().any(|d| {
                    matches!(&d.kind, warren_policy::model::DestinationKind::Host { host, .. } if host.matches(name))
                })
            });
            if claimed {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "name_claimed",
                    format!("{name} is claimed by an app"),
                ));
            }
        }
    }
    Ok(())
}

/// The join exchange (docs/protocol.md section 10.3): a single-use token
/// and a signed certificate request for the node's first certificate.
async fn join(app: &App, req: Request<Incoming>) -> Result<Response<Body>, ApiError> {
    let body: JoinRequest = serde_json::from_slice(&read_body(req, PREAUTH_BODY).await?)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON body: {e}")))?;
    let invalid = || {
        let mut r = audit::record(
            Activity::Enroll,
            false,
            &Actor::Anonymous,
            "join refused: the token is unknown, expired, already used or for another deployment",
        );
        r.insert("entity".into(), audit::entity("node", ""));
        app.audit(r);
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "The join token is unknown, expired or already used. Ask an admin for a new one.",
        )
    };
    let token =
        JoinToken::parse(&body.token, clock::now_secs().unsigned_abs()).map_err(|_| invalid())?;
    if token.td != app.config.trust_domain || token.root != sha256_hex(&app.authority.root.der) {
        return Err(invalid());
    }
    let key = csr_key(&body.csr, None)?;
    let token_hash = secret_hash(&token.secret);
    let dns_names = app
        .store
        .minted_dns_names(&token_hash)
        .await?
        .ok_or_else(invalid)?;
    check_relay_names(app, &dns_names)?;
    let draft = Node {
        id: crate::store::new_id("n")?,
        role: String::new(),
        group: None,
        name: String::new(),
        dns_names: Vec::new(),
        public_key: key.point,
        created_at: 0,
        revoked_at: None,
    };
    let node = app
        .store
        .join(&token_hash, &token, &draft)
        .await?
        .ok_or_else(invalid)?;
    let role = token.node_role();
    let dns = match role {
        NodeRole::Relay => node.dns_names.clone(),
        _ => Vec::new(),
    };
    let issued = app.authority.issue_node(
        &key.spki,
        &role,
        &node.id,
        &dns,
        INFRA_CERT_LIFETIME.as_secs() as i64,
        app.config.clock_skew.as_secs() as i64,
    )?;
    app.store
        .insert_certificate(
            &issued.serial,
            "node",
            &node.id,
            None,
            None,
            issued.not_before,
            issued.not_after,
        )
        .await?;
    let mut r = audit::record(
        Activity::Enroll,
        true,
        &Actor::Node {
            id: node.id.clone(),
        },
        "node joined with a join token",
    );
    r.insert("entity".into(), audit::entity(&node.role, &node.id));
    r.insert(
        "unmapped".into(),
        json!({ "name": node.name, "group": node.group, "dns_names": node.dns_names, "token_id": token.id }),
    );
    app.audit(r);
    app.request_publish();
    let authority = &app.authority;
    Ok(json(
        StatusCode::OK,
        &JoinResponse {
            chain: vec![
                STANDARD.encode(&issued.der),
                STANDARD.encode(&authority.infra.der),
            ],
            trust_bundle: BundleJson {
                root: STANDARD.encode(&authority.root.der),
                client_cas: vec![STANDARD.encode(&authority.client.der)],
                infra_cas: vec![STANDARD.encode(&authority.infra.der)],
            },
        },
    ))
}

/// The policy-signing key, for a joined node to verify bundles with. It is
/// served on link E, where the node has already verified the control plane
/// against the trust bundle its join pinned.
async fn node_policy_key(app: &App, peer: &Peer) -> Result<Response<Body>, ApiError> {
    app.node(peer).await?;
    Ok(json(StatusCode::OK, &app.authority.policy_jwk()))
}

async fn node_bundle(app: &App, peer: &Peer) -> Result<Response<Body>, ApiError> {
    let (node, _) = app.node(peer).await?;
    let bundle = app.store.latest_bundle().await?.ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "No bundle has been published yet.",
        )
    })?;
    let jws = if node.role == "relay" {
        bundle.relay_jws
    } else {
        bundle.connector_jws
    };
    let mut resp = web::body(StatusCode::OK, "application/jose", Bytes::from(jws));
    if let Ok(v) = http::HeaderValue::from_str(&format!("\"{}\"", bundle.version)) {
        resp.headers_mut().insert(http::header::ETAG, v);
    }
    Ok(resp)
}

async fn node_events<B>(
    app: Arc<App>,
    req: &Request<B>,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    let (node, identity) = app.node(peer).await?;
    let q = query(req)?;
    let after = match param(&q, "after") {
        Some(a) => Some(
            a.parse::<u64>()
                .map_err(|_| ApiError::bad_request("after must be a sequence number"))?,
        ),
        None => None,
    };
    Ok(stream::open(
        app,
        node,
        after,
        stream::StreamCert {
            serial: identity.serial,
            not_after: identity
                .not_after
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64),
        },
    ))
}

async fn node_ack(
    app: &App,
    req: Request<Incoming>,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    let (node, _) = app.node(peer).await?;
    let body: AckRequest = read_json(req).await?;
    let latencies = app.store.record_acks(&node.id, &body.acks).await?;
    let deadline = REVOCATION_DEADLINE.as_millis() as i64;
    for (seq, ms) in latencies {
        let seq_text = seq.to_string();
        let ms_text = ms.to_string();
        let fields = [
            ("node", node.id.as_str()),
            ("seq", seq_text.as_str()),
            ("commit_to_cut_ms", ms_text.as_str()),
        ];
        if ms > deadline {
            crate::log::info_with(
                "revocation",
                "an event took effect after the revocation deadline",
                &fields,
            );
        } else {
            crate::log::info_with("revocation", "event took effect", &fields);
        }
    }
    Ok(json(
        StatusCode::OK,
        &json!({ "recorded": body.acks.len() }),
    ))
}

async fn node_audit(
    app: &App,
    req: Request<Incoming>,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    let (node, identity) = app.node(peer).await?;
    let body = read_body(req, 4 * MAX_BODY).await?;
    let reporter = WarrenUri::Node {
        td: identity.trust_domain,
        role: identity.role,
        id: identity.id,
    }
    .to_string();
    let records =
        audit::accept_node_records(&body, &reporter, &node.role).map_err(ApiError::bad_request)?;
    for r in &records {
        app.audit.write(r);
        app.recent.remember(r);
    }
    Ok(json(
        StatusCode::ACCEPTED,
        &json!({ "accepted": records.len() }),
    ))
}

async fn node_certificate(
    app: &App,
    req: Request<Incoming>,
    peer: &Peer,
) -> Result<Response<Body>, ApiError> {
    let (node, identity) = app.node(peer).await?;
    let result = renew_node_certificate(app, req, &node, &identity).await;
    if let Err(e) = &result {
        let mut r = audit::record(
            Activity::Create,
            false,
            &Actor::Node {
                id: node.id.clone(),
            },
            &format!("infrastructure certificate refused: {}", e.reason),
        );
        r.insert("entity".into(), audit::entity("certificate", ""));
        app.audit(r);
    }
    result
}

async fn renew_node_certificate(
    app: &App,
    req: Request<Incoming>,
    node: &Node,
    identity: &NodeIdentity,
) -> Result<Response<Body>, ApiError> {
    let body: CertificateRequest = read_json(req).await?;
    let key = csr_key(&body.csr, Some(&node.public_key))?;
    let dns = if node.role == "relay" {
        node.dns_names.clone()
    } else {
        Vec::new()
    };
    let issued = app.authority.issue_node(
        &key.spki,
        &identity.role,
        &identity.id,
        &dns,
        INFRA_CERT_LIFETIME.as_secs() as i64,
        app.config.clock_skew.as_secs() as i64,
    )?;
    app.store
        .insert_certificate(
            &issued.serial,
            "node",
            &node.id,
            None,
            None,
            issued.not_before,
            issued.not_after,
        )
        .await?;
    let mut r = audit::record(
        Activity::Create,
        true,
        &Actor::Node {
            id: node.id.clone(),
        },
        "infrastructure certificate renewed",
    );
    r.insert(
        "entity".into(),
        audit::entity("certificate", &issued.serial),
    );
    app.audit(r);
    Ok(json(
        StatusCode::OK,
        &CertificateResponse {
            certificate_chain: app.authority.chain_pem(&issued.der, &app.authority.infra),
            serial: issued.serial,
            not_before: issued.not_before,
            not_after: issued.not_after,
            renew_at: issued.renew_at,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_suffixes_drop_covered_names() {
        let hosts: Vec<DomainPattern> = [
            "grafana.lab.example.com",
            "*.lab.example.com",
            "nas.example.internal",
            "*.lab.example.com",
        ]
        .iter()
        .map(|h| DomainPattern::parse(h).unwrap())
        .collect();
        assert_eq!(
            dns_suffixes(&hosts),
            ["lab.example.com", "nas.example.internal"]
        );
    }

    #[test]
    fn pkce_values() {
        assert!(pkce_value_ok(&"a".repeat(43)));
        assert!(!pkce_value_ok(&"a".repeat(42)));
        assert!(!pkce_value_ok(&"a".repeat(129)));
        assert!(!pkce_value_ok(&format!("{}+", "a".repeat(43))));
        // RFC 7636 appendix B.
        assert_eq!(
            s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
