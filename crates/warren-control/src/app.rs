//! The control plane's shared state and the operations every API uses:
//! loading policy, publishing bundles, announcing events, and recognizing
//! sessions and nodes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use http::StatusCode;
use serde_json::json;
use tokio::sync::{Mutex, Notify, watch};
use warren_core::clock;
use warren_core::events::Event;
use warren_core::identity::NodeRole;
use warren_core::jose::{Jwk, b64url};
use warren_core::keys::{hex, sha256};
use warren_core::pki::{self, NodeIdentity};
use warren_core::policy_bundle::{self, BUNDLE_FORMAT, Bundle, View};
use warren_policy::compile::{self, Compiled, UserEntity};
use warren_policy::model;

use crate::Error;
use crate::audit::{self, Activity, Actor};
use crate::authority::Authority;
use crate::config::Config;
use crate::oidc::Provider;
use crate::store::{BundleState, DeviceStatus, Node, Session, Store, StoredBundle, User};
use crate::web::{ApiError, Peer};

/// The outcome of the last policy load.
#[derive(Debug, Clone, Default)]
pub struct PolicyStatus {
    /// The policy in force: the last one that compiled.
    pub compiled: Option<Arc<Compiled>>,
    /// When the policy in force was loaded, Unix seconds.
    pub loaded_at: i64,
    /// When loading was last attempted, Unix seconds.
    pub attempted_at: i64,
    /// Errors from the last attempt; empty if it succeeded.
    pub errors: Vec<String>,
    /// Warnings from the policy in force.
    pub warnings: Vec<String>,
}

/// Which relays and connectors have their revocation event stream open:
/// the control plane's view of their health. Kept in memory, so it starts
/// empty when the control plane does.
#[derive(Default)]
pub struct Presence {
    nodes: std::sync::Mutex<HashMap<String, NodePresence>>,
}

/// One node's event streams.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodePresence {
    /// Streams open now.
    pub open: usize,
    /// When the oldest open stream started, Unix seconds.
    pub since: i64,
    /// When a stream last ended, Unix seconds; 0 if none has.
    pub last_seen: i64,
}

impl Presence {
    /// Counts a stream for `node` as open until the guard is dropped.
    pub fn connect(self: &Arc<Self>, node: &str) -> PresenceGuard {
        if let Ok(mut nodes) = self.nodes.lock() {
            let p = nodes.entry(node.to_owned()).or_default();
            if p.open == 0 {
                p.since = clock::now_secs();
            }
            p.open += 1;
        }
        PresenceGuard {
            presence: self.clone(),
            node: node.to_owned(),
        }
    }

    /// Every node seen since the control plane started.
    pub fn snapshot(&self) -> HashMap<String, NodePresence> {
        self.nodes.lock().map(|n| n.clone()).unwrap_or_default()
    }
}

/// An open event stream; see [`Presence::connect`].
pub struct PresenceGuard {
    presence: Arc<Presence>,
    node: String,
}

impl Drop for PresenceGuard {
    fn drop(&mut self) {
        if let Ok(mut nodes) = self.presence.nodes.lock()
            && let Some(p) = nodes.get_mut(&self.node)
        {
            p.open = p.open.saturating_sub(1);
            p.last_seen = clock::now_secs();
        }
    }
}

/// How many recent access decisions the console can show.
pub const RECENT_DECISIONS: usize = 2000;

/// Shared state.
pub struct App {
    /// Configuration.
    pub config: Config,
    /// The database.
    pub store: Store,
    /// Keys and CAs.
    pub authority: Authority,
    /// The IdP.
    pub idp: Provider,
    /// The audit sink.
    pub audit: audit::Sink,
    /// The control plane's own node ID.
    pub id: String,
    /// The newest access decisions, for the console.
    pub recent: audit::Recent,
    /// Which nodes are connected.
    pub presence: Arc<Presence>,
    policy: RwLock<PolicyStatus>,
    events: watch::Sender<u64>,
    publish_wanted: Notify,
    publish_lock: Mutex<()>,
}

/// Hashes a secret (token, code, state) for storage: lowercase hex SHA-256.
pub fn secret_hash(secret: &str) -> String {
    hex(&sha256(secret.as_bytes()))
}

/// A random secret: base64url of 32 bytes from the CSPRNG.
pub fn new_secret() -> Result<String, Error> {
    let bytes: [u8; 32] =
        warren_core::keys::random_bytes().map_err(|e| Error::Internal(e.to_string()))?;
    Ok(b64url(&bytes))
}

impl App {
    /// Assembles the state. Policy is loaded separately.
    pub fn new(
        config: Config,
        store: Store,
        authority: Authority,
        idp: Provider,
        audit: audit::Sink,
        id: String,
        latest_seq: u64,
    ) -> App {
        App {
            config,
            store,
            authority,
            idp,
            audit,
            id,
            recent: audit::Recent::new(RECENT_DECISIONS),
            presence: Arc::default(),
            policy: RwLock::new(PolicyStatus::default()),
            events: watch::Sender::new(latest_seq),
            publish_wanted: Notify::new(),
            publish_lock: Mutex::new(()),
        }
    }

    /// The policy in force and the outcome of the last load.
    pub fn policy(&self) -> PolicyStatus {
        self.policy.read().map(|p| p.clone()).unwrap_or_default()
    }

    /// The compiled policy in force.
    pub fn compiled(&self) -> Option<Arc<Compiled>> {
        self.policy.read().ok().and_then(|p| p.compiled.clone())
    }

    /// Writes one audit record.
    pub fn audit(&self, record: serde_json::Map<String, serde_json::Value>) {
        self.audit.write(&serde_json::Value::Object(record));
    }

    /// Reads and compiles the policy directory. On success the new policy
    /// takes effect and a bundle is published; on failure the previous
    /// policy stays in force (fail closed: a broken change never ships) and
    /// the errors are returned.
    pub async fn load_policy(&self, actor: &Actor) -> Result<PolicyStatus, Vec<String>> {
        let now = clock::now_secs();
        match self.compile_policy().await {
            Ok(compiled) => {
                let digest = compiled.policy.digest.clone();
                let rules = compiled.policy.rules.len();
                let warnings = compiled.warnings.iter().map(|w| w.to_string()).collect();
                if let Ok(mut p) = self.policy.write() {
                    *p = PolicyStatus {
                        compiled: Some(Arc::new(compiled)),
                        loaded_at: now,
                        attempted_at: now,
                        errors: Vec::new(),
                        warnings,
                    };
                }
                let mut r = audit::record(Activity::Update, true, actor, "policy loaded");
                r.insert("entity".into(), audit::entity("policy", &digest));
                r.insert(
                    "unmapped".into(),
                    json!({ "policy_dir": self.config.policy_dir.display().to_string(), "rules": rules }),
                );
                self.audit(r);
                self.request_publish();
                Ok(self.policy())
            }
            Err(errors) => {
                if let Ok(mut p) = self.policy.write() {
                    p.attempted_at = now;
                    p.errors = errors.clone();
                }
                let mut r = audit::record(
                    Activity::Update,
                    false,
                    actor,
                    "policy rejected; the previous policy stays in force",
                );
                r.insert("unmapped".into(), json!({ "errors": errors }));
                self.audit(r);
                Err(errors)
            }
        }
    }

    /// Compiles the policy directory with the relays' names reserved, and
    /// flags groups no known user has at the IdP. Refuses to compile when
    /// the store cannot say which names are taken.
    async fn compile_policy(&self) -> Result<Compiled, Vec<String>> {
        let unreadable = |e: Error| {
            vec![format!(
                "cannot read the relays and users policy is checked against: {e}"
            )]
        };
        let mut reserved = self.config.reserved();
        for n in self
            .store
            .nodes()
            .await
            .map_err(unreadable)?
            .iter()
            .filter(|n| n.role == "relay" && n.revoked_at.is_none())
        {
            reserved.extend(n.dns_names.iter().cloned());
        }
        let known_groups: BTreeSet<String> = self
            .store
            .users()
            .await
            .map_err(unreadable)?
            .into_iter()
            .flat_map(|u| u.groups)
            .collect();
        let (objects, diags) = model::load_dir(&self.config.policy_dir)
            .map_err(|e| vec![format!("{}: {e}", self.config.policy_dir.display())])?;
        let mut compiled = compile::compile(objects, diags, &reserved)
            .map_err(|d| d.iter().map(|d| d.to_string()).collect::<Vec<_>>())?;
        let unknown = compile::unknown_groups(&compiled.objects, &known_groups);
        compiled.warnings.extend(unknown);
        Ok(compiled)
    }

    /// Announces committed events to every event stream.
    pub fn announce(&self, event: Option<&Event>) {
        if let Some(e) = event {
            self.events.send_modify(|seq| *seq = (*seq).max(e.seq));
        }
    }

    /// A receiver that changes when events are committed.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.events.subscribe()
    }

    /// Asks the publisher for a new bundle. Requests made while one is
    /// being built coalesce into one more build.
    pub fn request_publish(&self) {
        self.publish_wanted.notify_one();
    }

    /// Runs the publisher until the task is aborted.
    pub async fn publisher(self: Arc<Self>) {
        loop {
            self.publish_wanted.notified().await;
            if let Err(e) = self.publish().await {
                crate::log::error("publisher", &format!("cannot publish a bundle: {e}"));
            }
        }
    }

    /// Builds, signs and stores a new bundle version from the current state,
    /// and announces it. The state is read in the same transaction that
    /// stores the bundle (see [`Store::publish_bundle`]).
    pub async fn publish(&self) -> Result<u64, Error> {
        let _guard = self.publish_lock.lock().await;
        let Some(compiled) = self.compiled() else {
            return Err(Error::Unavailable("no policy has been loaded".into()));
        };
        let event = self
            .store
            .publish_bundle(|state, version| self.build_bundle(&compiled, state, version))
            .await?;
        self.announce(Some(&event));
        match event.body {
            warren_core::events::EventBody::BundleUpdated { version, .. } => Ok(version),
            _ => Err(Error::Internal(
                "publishing committed an unexpected event".into(),
            )),
        }
    }

    fn build_bundle(
        &self,
        compiled: &Compiled,
        state: BundleState,
        version: u64,
    ) -> Result<StoredBundle, Error> {
        let enabled: Vec<UserEntity> = state
            .users
            .iter()
            .filter(|u| !u.disabled)
            .map(user_entity)
            .collect();
        let enabled_ids: Vec<&str> = enabled.iter().map(|u| u.id.as_str()).collect();
        let bundle_devices = state
            .devices
            .iter()
            .filter(|d| d.status == DeviceStatus::Approved)
            .map(|d| policy_bundle::Device {
                id: d.id.clone(),
                users: d
                    .users
                    .iter()
                    .filter(|u| enabled_ids.contains(&u.as_str()))
                    .cloned()
                    .collect(),
                tunnel_v4: d.tunnel_v4.clone(),
                tunnel_v6: d.tunnel_v6.clone(),
                trust_class: d.trust_class,
            })
            .collect();
        let bundle_nodes: Vec<policy_bundle::Node> = state
            .nodes
            .iter()
            .filter(|n| n.revoked_at.is_none())
            .map(|n| policy_bundle::Node {
                id: n.id.clone(),
                role: n.role.clone(),
                group: n.group.clone(),
                name: n.name.clone(),
                dns_names: n.dns_names.clone(),
            })
            .collect();
        let mut keys = BTreeMap::new();
        keys.insert(
            "posture".to_owned(),
            Jwk::from_key(self.authority.posture_key.public_key()),
        );
        keys.insert(
            "session-assertion".to_owned(),
            Jwk::from_key(self.authority.assertion_key.public_key()),
        );
        let connector = Bundle {
            format: BUNDLE_FORMAT.into(),
            trust_domain: self.config.trust_domain.clone(),
            version,
            issued_at: clock::now_secs(),
            view: View::Connector,
            policy: Some(compiled.policy.clone()),
            entities: Some(compile::entities(&enabled, &compiled.apps)),
            apps: compiled.apps.clone(),
            connector_groups: compiled.groups.clone(),
            devices: bundle_devices,
            nodes: bundle_nodes,
            revocations: state.revocations,
            keys,
        };
        let relay = Bundle {
            view: View::Relay,
            policy: None,
            entities: None,
            apps: Vec::new(),
            devices: Vec::new(),
            keys: BTreeMap::new(),
            ..connector.clone()
        };
        let sign = |b: &Bundle| {
            b.sign(&self.authority.policy_key)
                .map_err(|e| Error::Internal(e.to_string()))
        };
        Ok(StoredBundle {
            version,
            digest: compiled.policy.digest.clone(),
            connector_jws: sign(&connector)?,
            relay_jws: sign(&relay)?,
        })
    }

    /// The session presenting `Authorization: Bearer <token>`, with its
    /// user. Revoked, expired and disabled ones are refused with a reason
    /// the client can show.
    pub async fn session<B>(&self, req: &http::Request<B>) -> Result<(Session, User), ApiError> {
        self.check_session(req).await.map_err(|(e, _)| e)
    }

    /// Like [`App::session`], for requests that yield a credential: a
    /// refusal is audited as `activity` on an `entity` failing, naming the
    /// session's user when the token is known.
    pub async fn credential_session<B>(
        &self,
        req: &http::Request<B>,
        activity: Activity,
        entity: &str,
    ) -> Result<(Session, User), ApiError> {
        self.check_session(req).await.map_err(|(e, user_id)| {
            let actor = match user_id {
                Some(id) => Actor::User {
                    id,
                    email: String::new(),
                },
                None => Actor::Anonymous,
            };
            let mut r = audit::record(
                activity,
                false,
                &actor,
                &format!("{entity} refused: {}", e.reason),
            );
            r.insert("entity".into(), audit::entity(entity, ""));
            self.audit(r);
            e
        })
    }

    /// The session and user, or the refusal with the user it concerns
    /// when the token named a session.
    async fn check_session<B>(
        &self,
        req: &http::Request<B>,
    ) -> Result<(Session, User), (ApiError, Option<String>)> {
        let token = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| (ApiError::unauthenticated("Sign in to warren first."), None))?;
        let session = self
            .store
            .session_by_token(&secret_hash(token))
            .await
            .map_err(|e| (e.into(), None))?
            .ok_or_else(|| {
                (
                    ApiError::new(
                        StatusCode::UNAUTHORIZED,
                        "reauth_required",
                        "Your sign-in is not valid. Sign in again.",
                    ),
                    None,
                )
            })?;
        let refuse = |e: ApiError| Err((e, Some(session.user_id.clone())));
        if session.revoked_at.is_some() {
            return refuse(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "revoked",
                "Your sign-in was revoked by an administrator. Sign in again.",
            ));
        }
        if session.expires_at <= clock::now_secs() {
            return refuse(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "reauth_required",
                "Your sign-in has ended. Sign in again.",
            ));
        }
        let user = match self.store.user(&session.user_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return refuse(ApiError::internal()),
            Err(e) => return refuse(e.into()),
        };
        if user.disabled {
            return refuse(ApiError::new(
                StatusCode::FORBIDDEN,
                "user_disabled",
                "Your warren account is disabled. Contact your administrator.",
            ));
        }
        Ok((session, user))
    }

    /// The relay or connector presenting the TLS client certificate in
    /// `peer`: issued by the infrastructure CA, naming a node of this
    /// deployment that is still enabled, and not itself revoked. Refusals
    /// are audited with the identity the certificate claimed.
    pub async fn node(&self, peer: &Peer) -> Result<(Node, NodeIdentity), ApiError> {
        let result = self.check_node(peer).await;
        if let Err(e) = &result {
            let claimed = peer.certificates.first().and_then(|der| {
                let c = pki::parse_cert(der).ok()?;
                let serial = hex(c.serial.strip_prefix(&[0]).unwrap_or(c.serial));
                Some((serial, c.subject_alt_names().ok()?.uris))
            });
            let mut r = audit::record(
                Activity::Logon,
                false,
                &Actor::Anonymous,
                &format!("relay or connector refused: {}", e.detail),
            );
            r.insert("auth_protocol".into(), "mTLS".into());
            r.insert(
                "unmapped".into(),
                json!({
                    "source": peer.addr.map(|a| a.to_string()),
                    "certificate_uris": claimed.as_ref().map(|c| &c.1),
                    "certificate_serial": claimed.as_ref().map(|c| &c.0),
                }),
            );
            self.audit(r);
        }
        result
    }

    async fn check_node(&self, peer: &Peer) -> Result<(Node, NodeIdentity), ApiError> {
        let denied =
            |why: &str| ApiError::new(StatusCode::FORBIDDEN, "node_not_allowed", why.to_owned());
        let leaf = peer.certificates.first().ok_or_else(|| {
            ApiError::unauthenticated("A relay or connector certificate is required.")
        })?;
        self.authority
            .bundle
            .verify_chain(
                leaf,
                pki::Issuer::Infrastructure,
                false,
                pki::unix_time(SystemTime::now()),
            )
            .map_err(|_| denied("not a valid infrastructure certificate"))?;
        let identity = pki::check_infra_profile(leaf, &self.config.trust_domain)
            .map_err(|_| denied("the certificate must name exactly one node of this deployment"))?;
        let (role, group) = match &identity.role {
            NodeRole::Relay => ("relay", None),
            NodeRole::Connector { group } => ("connector", Some(group.clone())),
            NodeRole::ControlPlane => return Err(denied("not a relay or connector")),
        };
        let node = self
            .store
            .node(&identity.id)
            .await?
            .ok_or_else(|| denied("unknown node"))?;
        if node.revoked_at.is_some() || node.role != role || node.group != group {
            return Err(denied("this node has been revoked"));
        }
        if self.store.certificate_revoked(&identity.serial).await? {
            return Err(denied("this certificate has been revoked"));
        }
        Ok((node, identity))
    }

    /// The user as policy sees them.
    pub fn user_entity(user: &User) -> UserEntity {
        user_entity(user)
    }
}

fn user_entity(u: &User) -> UserEntity {
    UserEntity {
        id: u.id.clone(),
        email: u.email.clone(),
        subject: u.subject.clone(),
        groups: u.groups.clone(),
    }
}
