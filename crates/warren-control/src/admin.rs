//! The admin API, served on a local Unix socket created mode 0600.
//!
//! In M1 the admin API is reachable only from the control plane's own host
//! (or pod), where an operator already holds everything the socket could
//! grant, keys included. Remote admin access, authenticated with a recent
//! MFA sign-in at the IdP (threat model T5), arrives with the console in M3.
//! The endpoints are versioned and described in `docs/api/openapi.yaml`.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::json;
use warren_core::clock;
use warren_core::identity::{Role, is_valid_name};
use warren_core::jose::b64url;
use warren_core::keys::sha256;
use warren_core::params::{JOIN_TOKEN_LIFETIME, REVOCATION_DEADLINE};

use crate::Error;
use crate::app::{App, new_secret, secret_hash};
use crate::audit::{self, Activity, Actor};
use crate::store::{DeviceAction, DeviceStatus};
use crate::web::{ApiError, Body, Handler, Peer, json, problem, read_json};

/// Every admin route, as (method, path template). The OpenAPI description
/// in `docs/api/openapi.yaml` is tested against this list.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/admin/users"),
    ("POST", "/v1/admin/users/{user}/disable"),
    ("POST", "/v1/admin/users/{user}/enable"),
    ("GET", "/v1/admin/users/{user}/sessions"),
    ("POST", "/v1/admin/sessions/{session}/revoke"),
    ("GET", "/v1/admin/devices"),
    ("POST", "/v1/admin/devices/{device}/approve"),
    ("POST", "/v1/admin/devices/{device}/enable"),
    ("POST", "/v1/admin/devices/{device}/disable"),
    ("POST", "/v1/admin/devices/{device}/revoke"),
    ("POST", "/v1/admin/certificates/{serial}/revoke"),
    ("GET", "/v1/admin/policy"),
    ("POST", "/v1/admin/policy/reload"),
    ("POST", "/v1/admin/join-tokens"),
    ("GET", "/v1/admin/nodes"),
    ("POST", "/v1/admin/nodes/{node}/revoke"),
    ("GET", "/v1/admin/revocation-latency"),
];

/// The admin API handler.
pub struct Admin(pub Arc<App>);

impl Handler for Admin {
    async fn handle(self: Arc<Self>, req: Request<Incoming>, _peer: Arc<Peer>) -> Response<Body> {
        match route(&self.0, req).await {
            Ok(resp) => resp,
            Err(e) => problem(&e),
        }
    }
}

#[derive(Serialize)]
struct UserView {
    id: String,
    email: String,
    subject: String,
    groups: Vec<String>,
    disabled: bool,
    last_auth_at: i64,
}

#[derive(Serialize)]
struct DeviceView {
    id: String,
    status: String,
    users: Vec<String>,
    tunnel_v4: String,
    tunnel_v6: String,
    trust_class: u8,
    key_storage: String,
    platform: warren_core::api::Platform,
    created_at: i64,
}

#[derive(Serialize)]
struct SessionView {
    id: String,
    user_id: String,
    auth_time: i64,
    mfa: bool,
    expires_at: i64,
    revoked: bool,
}

#[derive(Deserialize)]
struct JoinTokenRequest {
    role: String,
    #[serde(default)]
    group: Option<String>,
}

fn changed(what: &str, id: &str, changed: bool) -> Response<Body> {
    json(
        StatusCode::OK,
        &json!({ "id": id, "changed": changed, "what": what }),
    )
}

async fn route(app: &App, req: Request<Incoming>) -> Result<Response<Body>, ApiError> {
    let path = req.uri().path().to_owned();
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let method = req.method().clone();
    match (method, segments.as_slice()) {
        (Method::GET, ["v1", "admin", "users"]) => {
            let users: Vec<UserView> = app
                .store
                .users()
                .await?
                .into_iter()
                .map(|u| UserView {
                    id: u.id,
                    email: u.email,
                    subject: u.subject,
                    groups: u.groups,
                    disabled: u.disabled,
                    last_auth_at: u.last_auth_at,
                })
                .collect();
            Ok(json(StatusCode::OK, &users))
        }
        (Method::POST, ["v1", "admin", "users", key, action @ ("disable" | "enable")]) => {
            let user = app
                .store
                .find_user(key)
                .await?
                .ok_or_else(|| ApiError::not_found(format!("no user {key}")))?;
            let disable = *action == "disable";
            let (did, event) = app.store.set_user_disabled(&user.id, disable).await?;
            app.announce(event.as_ref());
            if did {
                let mut r = audit::record(
                    if disable {
                        Activity::Disable
                    } else {
                        Activity::Enable
                    },
                    true,
                    &Actor::LocalAdmin,
                    if disable {
                        "user disabled"
                    } else {
                        "user enabled"
                    },
                );
                r.insert(
                    "user".into(),
                    json!({ "uid": user.id, "email_addr": user.email }),
                );
                app.audit(r);
                app.request_publish();
            }
            Ok(changed("user", &user.id, did))
        }
        (Method::GET, ["v1", "admin", "users", key, "sessions"]) => {
            let user = app
                .store
                .find_user(key)
                .await?
                .ok_or_else(|| ApiError::not_found(format!("no user {key}")))?;
            let sessions: Vec<SessionView> = app
                .store
                .sessions_of(&user.id)
                .await?
                .into_iter()
                .map(|s| SessionView {
                    id: s.id,
                    user_id: s.user_id,
                    auth_time: s.auth_time,
                    mfa: s.mfa,
                    expires_at: s.expires_at,
                    revoked: s.revoked_at.is_some(),
                })
                .collect();
            Ok(json(StatusCode::OK, &sessions))
        }
        (Method::POST, ["v1", "admin", "sessions", id, "revoke"]) => {
            let event = app.store.revoke_session(id).await?;
            app.announce(event.as_ref());
            if event.is_some() {
                let mut r = audit::record(
                    Activity::Delete,
                    true,
                    &Actor::LocalAdmin,
                    "session revoked",
                );
                r.insert("entity".into(), audit::entity("session", id));
                app.audit(r);
                app.request_publish();
            }
            Ok(changed("session", id, event.is_some()))
        }
        (Method::GET, ["v1", "admin", "devices"]) => {
            let devices: Vec<DeviceView> = app
                .store
                .devices()
                .await?
                .into_iter()
                .map(|d| DeviceView {
                    id: d.id,
                    status: d.status.as_str().into(),
                    users: d.users,
                    tunnel_v4: d.tunnel_v4,
                    tunnel_v6: d.tunnel_v6,
                    trust_class: d.trust_class,
                    key_storage: d.key_storage,
                    platform: d.platform,
                    created_at: d.created_at,
                })
                .collect();
            Ok(json(StatusCode::OK, &devices))
        }
        (
            Method::POST,
            [
                "v1",
                "admin",
                "devices",
                id,
                action @ ("approve" | "enable" | "disable" | "revoke"),
            ],
        ) => {
            let device = app
                .store
                .device(id)
                .await?
                .ok_or_else(|| ApiError::not_found(format!("no device {id}")))?;
            let (transition, done, activity, message) = match *action {
                "approve" => (
                    DeviceAction::Approve,
                    DeviceStatus::Approved,
                    Activity::Activate,
                    "device approved",
                ),
                "enable" => (
                    DeviceAction::Enable,
                    DeviceStatus::Approved,
                    Activity::Activate,
                    "device enabled",
                ),
                "disable" => (
                    DeviceAction::Disable,
                    DeviceStatus::Disabled,
                    Activity::Suspend,
                    "device disabled",
                ),
                _ => (
                    DeviceAction::Revoke,
                    DeviceStatus::Revoked,
                    Activity::Unenroll,
                    "device revoked",
                ),
            };
            let (status, event) = app.store.transition_device(id, transition).await?;
            app.announce(event.as_ref());
            match status {
                Some(status) => {
                    let mut r = audit::record(activity, true, &Actor::LocalAdmin, message);
                    r.insert("entity".into(), audit::entity("device", id));
                    r.insert("unmapped".into(), json!({ "status": status.as_str() }));
                    app.audit(r);
                    app.request_publish();
                    Ok(changed("device", id, true))
                }
                // Already where the action leads: nothing to do.
                None if device.status == done => Ok(changed("device", id, false)),
                None => {
                    let current = app
                        .store
                        .device(id)
                        .await?
                        .map(|d| d.status)
                        .unwrap_or(device.status);
                    let mut r = audit::record(
                        activity,
                        false,
                        &Actor::LocalAdmin,
                        &format!("refused: the device is {}", current.as_str()),
                    );
                    r.insert("entity".into(), audit::entity("device", id));
                    app.audit(r);
                    Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "conflict",
                        format!(
                            "device {id} is {}; it cannot be {action}d",
                            current.as_str()
                        ),
                    ))
                }
            }
        }
        (Method::POST, ["v1", "admin", "certificates", serial, "revoke"]) => {
            let serial = serial.to_ascii_lowercase();
            let event = app.store.revoke_certificate(&serial).await?;
            app.announce(event.as_ref());
            if event.is_some() {
                let mut r = audit::record(
                    Activity::Delete,
                    true,
                    &Actor::LocalAdmin,
                    "certificate revoked",
                );
                r.insert("entity".into(), audit::entity("certificate", &serial));
                app.audit(r);
                app.request_publish();
            }
            Ok(changed("certificate", &serial, event.is_some()))
        }
        (Method::GET, ["v1", "admin", "policy"]) => {
            Ok(json(StatusCode::OK, &policy_view(app).await?))
        }
        (Method::POST, ["v1", "admin", "policy", "reload"]) => {
            match app.load_policy(&Actor::LocalAdmin).await {
                Ok(_) => Ok(json(StatusCode::OK, &policy_view(app).await?)),
                Err(errors) => Ok(json(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &json!({ "reason": "policy_rejected", "detail": "The policy did not compile; the previous policy stays in force.", "errors": errors }),
                )),
            }
        }
        (Method::POST, ["v1", "admin", "join-tokens"]) => {
            let body: JoinTokenRequest = read_json(req).await?;
            let role = Role::parse(&body.role)
                .filter(|r| *r != Role::ControlPlane)
                .ok_or_else(|| ApiError::bad_request("role must be relay or connector"))?;
            match (role, &body.group) {
                (Role::Connector, Some(g)) => {
                    let known = app
                        .compiled()
                        .is_some_and(|c| c.groups.iter().any(|x| &x.name == g));
                    if !is_valid_name(g) || !known {
                        return Err(ApiError::bad_request(format!(
                            "connector group {g} is not defined in policy"
                        )));
                    }
                }
                (Role::Connector, None) => {
                    return Err(ApiError::bad_request(
                        "a connector join token needs a group",
                    ));
                }
                (_, Some(_)) => {
                    return Err(ApiError::bad_request(
                        "only connector join tokens name a group",
                    ));
                }
                _ => {}
            }
            let secret = new_secret()?;
            let fingerprint = b64url(&sha256(&app.authority.root.der));
            let token = format!("wj1.{secret}.{fingerprint}");
            let expires_at = clock::now_secs() + JOIN_TOKEN_LIFETIME.as_secs() as i64;
            app.store
                .insert_join_token(
                    &secret_hash(&secret),
                    role.as_str(),
                    body.group.as_deref(),
                    expires_at,
                )
                .await?;
            let mut r = audit::record(
                Activity::Create,
                true,
                &Actor::LocalAdmin,
                "join token created",
            );
            r.insert(
                "entity".into(),
                audit::entity("join-token", &secret_hash(&secret)[..16]),
            );
            r.insert(
                "unmapped".into(),
                json!({ "role": role.as_str(), "group": body.group, "expires_at": expires_at }),
            );
            app.audit(r);
            Ok(json(
                StatusCode::CREATED,
                &json!({
                    "token": token,
                    "role": role.as_str(),
                    "group": body.group,
                    "expires_at": expires_at,
                    "control_plane": app.config.public_url,
                }),
            ))
        }
        (Method::GET, ["v1", "admin", "nodes"]) => {
            let nodes: Vec<serde_json::Value> = app
                .store
                .nodes()
                .await?
                .into_iter()
                .map(|n| {
                    json!({
                        "id": n.id, "role": n.role, "group": n.group, "name": n.name,
                        "dns_names": n.dns_names, "created_at": n.created_at, "revoked": n.revoked_at.is_some(),
                    })
                })
                .collect();
            Ok(json(StatusCode::OK, &nodes))
        }
        (Method::POST, ["v1", "admin", "nodes", id, "revoke"]) => {
            let event = app.store.revoke_node(id).await?;
            app.announce(event.as_ref());
            if event.is_some() {
                let mut r =
                    audit::record(Activity::Unenroll, true, &Actor::LocalAdmin, "node revoked");
                r.insert("entity".into(), audit::entity("node", id));
                app.audit(r);
                app.request_publish();
            }
            Ok(changed("node", id, event.is_some()))
        }
        (Method::GET, ["v1", "admin", "revocation-latency"]) => {
            let summary = app
                .store
                .latency_summary(REVOCATION_DEADLINE.as_millis() as i64)
                .await?;
            Ok(json(
                StatusCode::OK,
                &json!({ "deadline_ms": REVOCATION_DEADLINE.as_millis() as u64, "commit_to_cut": summary }),
            ))
        }
        _ => Err(ApiError::not_found(format!("no admin endpoint {path}"))),
    }
}

async fn policy_view(app: &App) -> Result<serde_json::Value, Error> {
    let status = app.policy();
    let bundle = app.store.latest_bundle().await?;
    Ok(json!({
        "policy_dir": app.config.policy_dir.display().to_string(),
        "digest": status.compiled.as_ref().map(|c| c.policy.digest.clone()),
        "rules": status.compiled.as_ref().map(|c| c.policy.rules.len()).unwrap_or(0),
        "apps": status.compiled.as_ref().map(|c| c.apps.len()).unwrap_or(0),
        "loaded_at": status.loaded_at,
        "attempted_at": status.attempted_at,
        "errors": status.errors,
        "warnings": status.warnings,
        "bundle_version": bundle.as_ref().map(|b| b.version),
    }))
}

/// How long `warren admin` waits for the control plane.
const ADMIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Sends one request to the admin socket and returns the status and body.
/// This is what `warren admin` uses; it gives up after `ADMIN_TIMEOUT`.
#[cfg(unix)]
pub async fn request(
    socket: &std::path::Path,
    method: Method,
    path: &str,
    body: Option<String>,
) -> Result<(u16, String), Error> {
    tokio::time::timeout(ADMIN_TIMEOUT, request_inner(socket, method, path, body))
        .await
        .map_err(|_| {
            Error::Unavailable("the control plane did not answer on its admin socket".into())
        })?
}

#[cfg(unix)]
async fn request_inner(
    socket: &std::path::Path,
    method: Method,
    path: &str,
    body: Option<String>,
) -> Result<(u16, String), Error> {
    let stream = tokio::net::UnixStream::connect(socket).await.map_err(|e| {
        Error::Unavailable(format!(
            "cannot reach the admin socket {}: {e}",
            socket.display()
        ))
    })?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| Error::Unavailable(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let has_body = body.is_some();
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, "localhost");
    if has_body {
        req = req.header(http::header::CONTENT_TYPE, "application/json");
    }
    let req = req
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|e| Error::BadRequest(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Unavailable(e.to_string()))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| Error::Unavailable(e.to_string()))?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}
