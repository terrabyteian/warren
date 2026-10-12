//! The admin API, served on a local Unix socket created mode 0600.
//!
//! The admin API is reachable only from the control plane's own host (or
//! pod), where an operator already holds everything the socket could grant,
//! keys included. The web console (`crate::console`) offers a few of its
//! changes remotely, to admins with a recent MFA sign-in at the IdP (threat
//! model T5), through `set_user_disabled` and `device_action` here. The
//! endpoints are versioned and described in `docs/api/openapi.yaml`.
//!
//! Built-in accounts and warren's own groups are managed here too. Accounts
//! and groups declared in the policy directory (`LocalUser`, `LocalGroup`)
//! are changed only there; disabling, resetting and unlocking work on any
//! account, since they are how an operator responds to an incident.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::json;
use warren_core::clock;
use warren_core::identity::valid_id;
use warren_core::join::{JoinToken, sha256_hex};
use warren_core::params::{JOIN_TOKEN_LIFETIME, REVOCATION_DEADLINE};

use std::collections::{BTreeMap, BTreeSet};

use crate::Error;
use crate::accounts::SETUP_LINK_LIFETIME;
use crate::app::{App, new_secret, secret_hash};
use crate::audit::{self, Activity, Actor};
use crate::store::{DeviceAction, DeviceStatus, LocalAccount, MANAGED_BY_CONFIG, User};
use crate::web::{ApiError, Body, Handler, Peer, json, problem, read_json};
use warren_policy::model::LOCAL_PREFIX;

/// Every admin route, as (method, path template). The OpenAPI description
/// in `docs/api/openapi.yaml` is tested against this list.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/admin/users"),
    ("POST", "/v1/admin/users"),
    ("DELETE", "/v1/admin/users/{user}"),
    ("POST", "/v1/admin/users/{user}/disable"),
    ("POST", "/v1/admin/users/{user}/enable"),
    ("POST", "/v1/admin/users/{user}/reset"),
    ("POST", "/v1/admin/users/{user}/unlock"),
    ("PUT", "/v1/admin/users/{user}/groups"),
    ("GET", "/v1/admin/users/{user}/sessions"),
    ("GET", "/v1/admin/groups"),
    ("GET", "/v1/admin/invites"),
    ("PUT", "/v1/admin/invites/{email}"),
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
    ("GET", "/v1/admin/deployment"),
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
    issuer: String,
    email: String,
    subject: String,
    groups: Vec<String>,
    disabled: bool,
    last_auth_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<LocalView>,
}

/// A built-in account's state, never its secrets.
#[derive(Serialize)]
struct LocalView {
    username: String,
    display_name: String,
    password_set: bool,
    authenticator: bool,
    recovery_codes: i64,
    locked_until: Option<i64>,
    managed_by: String,
}

fn user_view(u: User, local: Option<&LocalAccount>) -> UserView {
    let now = clock::now_secs();
    UserView {
        local: local.map(|a| LocalView {
            username: a.username.clone(),
            display_name: a.display_name.clone(),
            password_set: a.password_hash.is_some(),
            authenticator: a.totp_secret.is_some(),
            recovery_codes: a.recovery_codes,
            locked_until: (a.locked_until > now).then_some(a.locked_until),
            managed_by: a.managed_by.clone(),
        }),
        id: u.id,
        issuer: u.issuer,
        email: u.email,
        subject: u.subject,
        groups: u.groups,
        disabled: u.disabled,
        last_auth_at: u.last_auth_at,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUserRequest {
    username: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupsRequest {
    groups: Vec<String>,
}

/// Local group names as given, with or without `local:`, checked.
fn group_names(groups: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out = BTreeSet::new();
    for g in groups {
        let name = g.strip_prefix(LOCAL_PREFIX).unwrap_or(g);
        if !valid_id(name) {
            return Err(ApiError::bad_request(format!(
                "{g} is not a local group name: 1 to 63 lowercase letters, digits and '-'"
            )));
        }
        out.insert(name.to_owned());
    }
    Ok(out.into_iter().collect())
}

/// Groups the policy directory declares, which only it changes.
fn declared_groups(app: &App) -> BTreeSet<String> {
    app.compiled()
        .map(|c| {
            c.objects
                .local_groups
                .iter()
                .map(|g| g.meta.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn refuse_declared(app: &App, groups: &[String]) -> Result<(), ApiError> {
    let declared = declared_groups(app);
    match groups.iter().find(|g| declared.contains(*g)) {
        Some(g) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "managed_in_config",
            format!(
                "group {g} is declared as a LocalGroup in the policy directory; change its members there"
            ),
        )),
        None => Ok(()),
    }
}

/// A one-time setup link for a built-in account.
async fn setup_link(app: &App) -> Result<(String, String, i64), ApiError> {
    let token = new_secret()?;
    let expires_at = clock::now_secs() + SETUP_LINK_LIFETIME;
    let url = format!("{}/v1/auth/setup?token={token}", app.config.public_url);
    Ok((url, secret_hash(&token), expires_at))
}

fn account_record(
    activity: Activity,
    message: &str,
    user: &User,
) -> serde_json::Map<String, serde_json::Value> {
    let mut r = audit::record(activity, true, &Actor::LocalAdmin, message);
    r.insert(
        "user".into(),
        json!({ "uid": user.id, "name": user.subject, "email_addr": user.email }),
    );
    r
}

async fn local_user(app: &App, key: &str) -> Result<(User, LocalAccount), ApiError> {
    let user = app
        .store
        .find_user(key)
        .await?
        .filter(|u| !u.deleted)
        .ok_or_else(|| ApiError::not_found(format!("no user {key}")))?;
    let account = app.store.local_account(&user.id).await?.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "not_local",
            format!("{key} signs in through the identity provider, which owns their credentials"),
        )
    })?;
    Ok((user, account))
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
#[serde(deny_unknown_fields)]
struct JoinTokenRequest {
    role: String,
    #[serde(default)]
    group: Option<String>,
    name: String,
    #[serde(default)]
    dns_names: Vec<String>,
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
            let locals: BTreeMap<String, LocalAccount> = app
                .store
                .local_accounts()
                .await?
                .into_iter()
                .map(|a| (a.user_id.clone(), a))
                .collect();
            let users: Vec<UserView> = app
                .store
                .users()
                .await?
                .into_iter()
                .filter(|u| !u.deleted)
                .map(|u| {
                    let local = locals.get(&u.id);
                    user_view(u, local)
                })
                .collect();
            Ok(json(StatusCode::OK, &users))
        }
        (Method::POST, ["v1", "admin", "users"]) => {
            if !app.config.local_accounts.enabled {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "local_accounts_disabled",
                    "built-in accounts are turned off (localAccounts.enabled: false)",
                ));
            }
            let body: CreateUserRequest = read_json(req).await?;
            if !valid_id(&body.username) {
                return Err(ApiError::bad_request(
                    "username must be 1 to 63 lowercase letters, digits and '-'",
                ));
            }
            let email = body.email.map(|e| e.trim().to_ascii_lowercase());
            if email.as_ref().is_some_and(|e| !e.contains('@')) {
                return Err(ApiError::bad_request("email is not an email address"));
            }
            let groups = group_names(&body.groups)?;
            refuse_declared(app, &groups)?;
            let (url, hash, expires_at) = setup_link(app).await?;
            let user = app
                .store
                .create_local_user(
                    &body.username,
                    email.as_deref(),
                    body.display_name.as_deref(),
                    &groups,
                    None,
                    Some((&hash, expires_at)),
                )
                .await?;
            app.audit(account_record(
                Activity::AccountCreate,
                "built-in account created",
                &user,
            ));
            if !groups.is_empty() {
                app.request_publish();
            }
            let account = app.store.local_account(&user.id).await?;
            Ok(json(
                StatusCode::CREATED,
                &json!({ "user": user_view(user, account.as_ref()), "setup_url": url, "setup_expires_at": expires_at }),
            ))
        }
        (Method::DELETE, ["v1", "admin", "users", key]) => {
            let (user, account) = local_user(app, key).await?;
            if account.managed_by == MANAGED_BY_CONFIG {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "managed_in_config",
                    format!(
                        "{} is declared as a LocalUser in the policy directory; remove it there",
                        account.username
                    ),
                ));
            }
            let (deleted, event) = app.store.delete_local_user(&user.id).await?;
            app.announce(event.as_ref());
            if deleted {
                app.audit(account_record(
                    Activity::AccountDelete,
                    "built-in account deleted",
                    &user,
                ));
                app.request_publish();
            }
            Ok(changed("user", &user.id, deleted))
        }
        (Method::POST, ["v1", "admin", "users", key, "reset"]) => {
            let (user, _) = local_user(app, key).await?;
            let (url, hash, expires_at) = setup_link(app).await?;
            let events = app
                .store
                .reset_local_credentials(&user.id, &hash, expires_at)
                .await?
                .ok_or_else(|| ApiError::not_found(format!("no user {key}")))?;
            for event in &events {
                app.announce(Some(event));
            }
            let mut r = account_record(
                Activity::PasswordReset,
                "built-in account credentials reset: password, authenticator and recovery codes cleared, sessions revoked",
                &user,
            );
            r.insert(
                "unmapped".into(),
                json!({ "sessions_revoked": events.len() }),
            );
            app.audit(r);
            if !events.is_empty() {
                app.request_publish();
            }
            Ok(json(
                StatusCode::OK,
                &json!({ "id": user.id, "setup_url": url, "setup_expires_at": expires_at, "sessions_revoked": events.len() }),
            ))
        }
        (Method::POST, ["v1", "admin", "users", key, "unlock"]) => {
            let (user, _) = local_user(app, key).await?;
            let did = app.store.unlock_local_account(&user.id).await?;
            if did {
                app.audit(account_record(
                    Activity::Unlock,
                    "built-in account unlocked",
                    &user,
                ));
            }
            Ok(changed("user", &user.id, did))
        }
        (Method::PUT, ["v1", "admin", "users", key, "groups"]) => {
            let user = app
                .store
                .find_user(key)
                .await?
                .filter(|u| !u.deleted)
                .ok_or_else(|| ApiError::not_found(format!("no user {key}")))?;
            let body: GroupsRequest = read_json(req).await?;
            let groups = group_names(&body.groups)?;
            refuse_declared(app, &groups)?;
            let did = app.store.set_user_groups(&user.id, &groups).await?;
            if did {
                let mut r = account_record(Activity::Update, "local group memberships set", &user);
                r.insert("unmapped".into(), json!({ "groups": groups }));
                app.audit(r);
                app.request_publish();
            }
            Ok(changed("user", &user.id, did))
        }
        (Method::GET, ["v1", "admin", "groups"]) => {
            let declared = declared_groups(app);
            let mut groups: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            let entry = |groups: &mut BTreeMap<String, serde_json::Value>, name: &str| {
                groups.entry(name.to_owned()).or_insert_with(|| {
                    json!({
                        "name": name,
                        "policy_name": format!("{LOCAL_PREFIX}{name}"),
                        "managed_by": if declared.contains(name) { "config" } else { "api" },
                        "members": [],
                        "invites": [],
                    })
                });
            };
            for name in &declared {
                entry(&mut groups, name);
            }
            for m in app.store.memberships().await? {
                entry(&mut groups, &m.group);
                if let Some(g) = groups.get_mut(&m.group)
                    && let Some(members) = g["members"].as_array_mut()
                {
                    members.push(json!(m));
                }
            }
            for i in app.store.invites().await? {
                entry(&mut groups, &i.group);
                if let Some(g) = groups.get_mut(&i.group)
                    && let Some(invites) = g["invites"].as_array_mut()
                {
                    invites.push(json!(i));
                }
            }
            Ok(json(
                StatusCode::OK,
                &groups.into_values().collect::<Vec<_>>(),
            ))
        }
        (Method::GET, ["v1", "admin", "invites"]) => {
            Ok(json(StatusCode::OK, &app.store.invites().await?))
        }
        (Method::PUT, ["v1", "admin", "invites", email]) => {
            let email = email.to_ascii_lowercase();
            if !email.contains('@') {
                return Err(ApiError::bad_request(format!(
                    "{email} is not an email address"
                )));
            }
            let body: GroupsRequest = read_json(req).await?;
            let groups = group_names(&body.groups)?;
            refuse_declared(app, &groups)?;
            app.store.set_invites(&email, &groups).await?;
            let mut r = audit::record(
                Activity::Update,
                true,
                &Actor::LocalAdmin,
                "local group invites set",
            );
            r.insert("entity".into(), audit::entity("invite", &email));
            r.insert("unmapped".into(), json!({ "groups": groups }));
            app.audit(r);
            Ok(json(
                StatusCode::OK,
                &json!({ "email": email, "groups": groups }),
            ))
        }
        (Method::POST, ["v1", "admin", "users", key, action @ ("disable" | "enable")]) => {
            let (id, did) =
                set_user_disabled(app, key, *action == "disable", &Actor::LocalAdmin).await?;
            Ok(changed("user", &id, did))
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
            let did = device_action(app, id, action, &Actor::LocalAdmin).await?;
            Ok(changed("device", id, did))
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
            match (body.role.as_str(), &body.group) {
                ("connector", Some(g)) => {
                    let known = app
                        .compiled()
                        .is_some_and(|c| c.groups.iter().any(|x| &x.name == g));
                    if !valid_id(g) || !known {
                        return Err(ApiError::bad_request(format!(
                            "connector group {g} is not defined in policy"
                        )));
                    }
                    if !body.dns_names.is_empty() {
                        return Err(ApiError::bad_request(
                            "connectors listen on no DNS names; only relay join tokens take them",
                        ));
                    }
                }
                ("connector", None) => {
                    return Err(ApiError::bad_request(
                        "a connector join token needs a group",
                    ));
                }
                ("relay", None) => crate::api::check_relay_names(app, &body.dns_names)?,
                ("relay", Some(_)) => {
                    return Err(ApiError::bad_request(
                        "only connector join tokens name a group",
                    ));
                }
                _ => return Err(ApiError::bad_request("role must be relay or connector")),
            }
            if !valid_id(&body.name) {
                return Err(ApiError::bad_request(
                    "name must be 1 to 63 lowercase letters, digits and '-'",
                ));
            }
            let id = crate::store::new_id("jt")?;
            let secret = new_secret()?;
            let exp = clock::now_secs() + JOIN_TOKEN_LIFETIME.as_secs() as i64;
            let taken = app
                .store
                .nodes()
                .await?
                .into_iter()
                .any(|n| n.revoked_at.is_none() && n.role == body.role && n.name == body.name);
            if taken {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "name_taken",
                    format!(
                        "a {} named {} has already joined; revoke it first or choose another name",
                        body.role, body.name
                    ),
                ));
            }
            let token = JoinToken {
                td: app.config.trust_domain.clone(),
                cp: app.config.internal_endpoint(),
                role: body.role.clone(),
                group: body.group.clone(),
                root: sha256_hex(&app.authority.root.der),
                id: id.clone(),
                secret: secret.clone(),
                exp: exp.unsigned_abs(),
            };
            app.store
                .insert_join_token(&secret_hash(&secret), &token, &body.name, &body.dns_names)
                .await?;
            let mut r = audit::record(
                Activity::Create,
                true,
                &Actor::LocalAdmin,
                "join token created",
            );
            r.insert("entity".into(), audit::entity("join-token", &id));
            r.insert(
                "unmapped".into(),
                json!({ "role": body.role, "group": body.group, "name": body.name, "dns_names": body.dns_names, "expires_at": exp }),
            );
            app.audit(r);
            Ok(json(
                StatusCode::CREATED,
                &json!({
                    "token": token.encode(),
                    "role": body.role,
                    "group": body.group,
                    "name": body.name,
                    "dns_names": body.dns_names,
                    "expires_at": exp,
                    "control_plane": app.config.internal_url(),
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
        (Method::GET, ["v1", "admin", "deployment"]) => Ok(json(
            StatusCode::OK,
            &json!({
                "trust_domain": app.config.trust_domain,
                "public_url": app.config.public_url,
                "root_fingerprint": format!("sha256:{}", sha256_hex(&app.authority.root.der)),
            }),
        )),
        _ => Err(ApiError::not_found(format!("no admin endpoint {path}"))),
    }
}

/// Disables or enables the user `key` (an ID, email or IdP subject) on
/// behalf of `actor`. Disabling pushes a revocation that cuts the user's
/// live access. Returns the user's ID and whether anything changed.
pub(crate) async fn set_user_disabled(
    app: &App,
    key: &str,
    disable: bool,
    actor: &Actor,
) -> Result<(String, bool), ApiError> {
    let user = app
        .store
        .find_user(key)
        .await?
        .filter(|u| !u.deleted)
        .ok_or_else(|| ApiError::not_found(format!("no user {key}")))?;
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
            actor,
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
    Ok((user.id, did))
}

/// Applies `action` (`approve`, `enable`, `disable` or `revoke`) to device
/// `id` on behalf of `actor`. Disabling and revoking push a revocation that
/// cuts the device's live connections. Returns whether anything changed; an
/// action the device's state does not allow is refused with a conflict.
pub(crate) async fn device_action(
    app: &App,
    id: &str,
    action: &str,
    actor: &Actor,
) -> Result<bool, ApiError> {
    let device = app
        .store
        .device(id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no device {id}")))?;
    let (transition, done, activity, message) = match action {
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
        "revoke" => (
            DeviceAction::Revoke,
            DeviceStatus::Revoked,
            Activity::Unenroll,
            "device revoked",
        ),
        _ => return Err(ApiError::not_found(format!("no device action {action}"))),
    };
    let (status, event) = app.store.transition_device(id, transition).await?;
    app.announce(event.as_ref());
    match status {
        Some(status) => {
            let mut r = audit::record(activity, true, actor, message);
            r.insert("entity".into(), audit::entity("device", id));
            r.insert("unmapped".into(), json!({ "status": status.as_str() }));
            app.audit(r);
            app.request_publish();
            Ok(true)
        }
        // Already where the action leads: nothing to do.
        None if device.status == done => Ok(false),
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
                actor,
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
