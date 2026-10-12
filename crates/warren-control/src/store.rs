//! The control plane's state, behind the one SQL layer (sqlx).
//!
//! SQLite is embedded today; PostgreSQL follows for high availability with
//! the same queries and the same migration set, so the SQL here keeps to
//! what both engines accept (see `migrations/0001_initial.sql`). Changes
//! that reduce access commit together with the revocation event that
//! announces them, so an event exists exactly when the change does.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlSafeStr, Sqlite, SqliteConnection, SqlitePool, Transaction};
use warren_core::api::Platform;
use warren_core::clock;
use warren_core::events::{Event, EventBody};
use warren_core::join::JoinToken;
use warren_core::keys::{hex, random_bytes};
use warren_core::policy_bundle::{Revocations, RevokedCertificate};
use warren_policy::model::LOCAL_PREFIX;

use crate::Error;
use crate::accounts::{LOCAL_ISSUER, LOCKOUT_SECONDS, MAX_FAILED_ATTEMPTS};

type Tx<'a> = Transaction<'a, Sqlite>;

fn db(e: sqlx::Error) -> Error {
    Error::Store(e.to_string())
}

/// A built-in account's row with its username and unused recovery codes,
/// followed by `$rest`.
macro_rules! local_account_select {
    ($rest:literal) => {
        concat!(
            "SELECT a.*, u.subject AS username, \
             (SELECT COUNT(*) FROM recovery_codes r WHERE r.user_id = a.user_id) AS recovery_codes \
             FROM local_accounts a JOIN users u ON u.id = a.user_id ",
            $rest
        )
    };
}

/// A new random ID with a type prefix, for example `u-3f9c0d2a71b4e8a6c5d1`.
pub fn new_id(prefix: &str) -> Result<String, Error> {
    let bytes: [u8; 10] = random_bytes().map_err(|e| Error::Internal(e.to_string()))?;
    Ok(format!("{prefix}-{}", hex(&bytes)))
}

/// A user: as the IdP last described them, or a built-in account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The warren user ID.
    pub id: String,
    /// The IdP's issuer, or `local` for a built-in account.
    pub issuer: String,
    /// The IdP's subject identifier, or a built-in account's username.
    pub subject: String,
    /// The verified email (for a built-in account, the one an admin set),
    /// or empty.
    pub email: String,
    /// The groups policy sees: the IdP's, then warren's own as
    /// `local:<group>`.
    pub groups: Vec<String>,
    /// Disabled users can do nothing.
    pub disabled: bool,
    /// When the user last signed in, Unix seconds.
    pub last_auth_at: i64,
    /// Whether this built-in account was deleted; it stays disabled.
    pub deleted: bool,
}

impl User {
    /// Whether this is a built-in account.
    pub fn is_local(&self) -> bool {
        self.issuer == LOCAL_ISSUER
    }
}

/// Who manages a built-in account, a membership or an invite.
pub const MANAGED_BY_API: &str = "api";
/// Declared in the policy directory, and changed only there.
pub const MANAGED_BY_CONFIG: &str = "config";

/// A built-in account's credentials and state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAccount {
    /// The user.
    pub user_id: String,
    /// The username.
    pub username: String,
    /// A name to show.
    pub display_name: String,
    /// The password hash, once a password is set.
    pub password_hash: Option<String>,
    /// The authenticator secret, sealed, once one is enrolled.
    pub totp_secret: Option<String>,
    /// The last authenticator time step accepted.
    pub totp_last_step: i64,
    /// Consecutive failed sign-ins.
    pub failed_attempts: i64,
    /// Locked until this time, Unix seconds (0 when not locked).
    pub locked_until: i64,
    /// `api` or `config`.
    pub managed_by: String,
    /// Unused recovery codes.
    pub recovery_codes: i64,
}

/// A membership in one of warren's own groups.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Membership {
    /// The group, without the `local:` prefix.
    pub group: String,
    /// The member.
    pub user_id: String,
    /// `api` or `config`.
    pub managed_by: String,
    /// The invite it came from, if any.
    pub invited_email: Option<String>,
}

/// An invite to one of warren's own groups, waiting for its email.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Invite {
    /// The group.
    pub group: String,
    /// The verified email it binds to.
    pub email: String,
    /// `api` or `config`.
    pub managed_by: String,
}

/// Built-in accounts and groups as the policy directory declares them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredAccounts {
    /// `LocalUser` objects: username, email, display name.
    pub users: Vec<(String, Option<String>, Option<String>)>,
    /// `LocalGroup` objects: name, member usernames, member emails.
    pub groups: Vec<(String, Vec<String>, Vec<String>)>,
}

/// What bringing the store in line with the policy directory did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Events committed (deleted users).
    pub events: Vec<Event>,
    /// Built-in accounts created.
    pub created: Vec<String>,
    /// Built-in accounts deleted.
    pub deleted: Vec<String>,
    /// Built-in accounts the policy directory took over from the API.
    pub adopted: Vec<String>,
    /// Whether anything a bundle carries changed.
    pub changed: bool,
    /// Problems worth an operator's attention.
    pub warnings: Vec<String>,
}

/// An admin's change to a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    /// Pending to approved.
    Approve,
    /// Disabled back to approved, or to pending if it was never approved.
    Enable,
    /// Pending or approved to disabled.
    Disable,
    /// Anything to revoked, for good.
    Revoke,
}

/// What enrolling a device key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enrollment {
    /// The key was new: a device was created for the user.
    Created,
    /// The device was enrolled already and is now bound to this user too.
    BoundUser,
    /// The device was enrolled already for this user.
    Again,
    /// The device is revoked; nothing changed.
    Revoked,
}

/// A device's approval state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Waiting for an admin.
    Pending,
    /// May be issued certificates.
    Approved,
    /// Temporarily refused; can be re-enabled.
    Disabled,
    /// Permanently refused.
    Revoked,
}

impl DeviceStatus {
    /// The status name.
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceStatus::Pending => "pending",
            DeviceStatus::Approved => "approved",
            DeviceStatus::Disabled => "disabled",
            DeviceStatus::Revoked => "revoked",
        }
    }

    fn parse(s: &str) -> DeviceStatus {
        match s {
            "approved" => DeviceStatus::Approved,
            "disabled" => DeviceStatus::Disabled,
            "revoked" => DeviceStatus::Revoked,
            _ => DeviceStatus::Pending,
        }
    }
}

/// An enrolled device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The device ID.
    pub id: String,
    /// Its key, as base64url of the uncompressed P-256 point.
    pub public_key: String,
    /// Approval state.
    pub status: DeviceStatus,
    /// Enrollment trust class, 1 to 3.
    pub trust_class: u8,
    /// Where the client says the key lives.
    pub key_storage: String,
    /// Platform facts from enrollment.
    pub platform: Platform,
    /// IPv4 tunnel address.
    pub tunnel_v4: String,
    /// IPv6 tunnel address.
    pub tunnel_v6: String,
    /// Users bound to the device.
    pub users: Vec<String>,
    /// When it enrolled, Unix seconds.
    pub created_at: i64,
}

/// A sign-in session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The session ID.
    pub id: String,
    /// The user.
    pub user_id: String,
    /// The device key the session is bound to (base64url point).
    pub public_key: String,
    /// IdP authentication time, Unix seconds.
    pub auth_time: i64,
    /// Whether the sign-in used MFA.
    pub mfa: bool,
    /// When the session ends, Unix seconds.
    pub expires_at: i64,
    /// When it was revoked, if it was.
    pub revoked_at: Option<i64>,
}

/// A relay or connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The node ID.
    pub id: String,
    /// `relay` or `connector`.
    pub role: String,
    /// The connector group, for connectors.
    pub group: Option<String>,
    /// The node's name.
    pub name: String,
    /// DNS names it listens on.
    pub dns_names: Vec<String>,
    /// Its key, base64url point.
    pub public_key: String,
    /// When it joined, Unix seconds.
    pub created_at: i64,
    /// When it was revoked, if it was.
    pub revoked_at: Option<i64>,
}

/// A sign-in waiting for the IdP's callback, or going through the
/// built-in account pages.
#[derive(Debug, Clone, Default)]
pub struct AuthRequest {
    /// Where the client wants the code.
    pub client_redirect_uri: String,
    /// The client's state, returned unchanged.
    pub client_state: String,
    /// The client's PKCE challenge.
    pub client_challenge: String,
    /// The nonce sent to the IdP.
    pub nonce: String,
    /// The control plane's own PKCE verifier toward the IdP.
    pub idp_verifier: String,
    /// When it was created, Unix seconds.
    pub created_at: i64,
    /// Whether the IdP was asked to authenticate the user afresh
    /// (`prompt=login`).
    pub login: bool,
    /// A hash of the cookie binding a built-in account sign-in to its
    /// browser.
    pub browser_hash: Option<String>,
    /// The built-in account, once its password checked out.
    pub local_user_id: Option<String>,
    /// How far the built-in account sign-in got.
    pub local_stage: Option<String>,
    /// An authenticator secret being enrolled, sealed.
    pub pending_secret: Option<String>,
}

/// A one-time sign-in code.
#[derive(Debug, Clone)]
pub struct AuthCode {
    /// The user.
    pub user_id: String,
    /// The client's PKCE challenge.
    pub client_challenge: String,
    /// The redirect URI the code was sent to.
    pub client_redirect_uri: String,
    /// IdP authentication time.
    pub auth_time: i64,
    /// Whether the sign-in used MFA.
    pub mfa: bool,
}

/// A browser's sign-in to the web console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleSession {
    /// The session ID.
    pub id: String,
    /// The user.
    pub user_id: String,
    /// IdP authentication time, Unix seconds.
    pub auth_time: i64,
    /// Whether the sign-in used MFA.
    pub mfa: bool,
    /// When the session ends, Unix seconds.
    pub expires_at: i64,
    /// When the user signed out, if they did.
    pub ended_at: Option<i64>,
}

/// The newest certificate still in force for one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentCertificate {
    /// `client` or `node`.
    pub kind: String,
    /// The device or node.
    pub subject_id: String,
    /// The user, for client certificates.
    pub user_id: Option<String>,
    /// When the newest one expires, Unix seconds.
    pub not_after: i64,
}

/// What a bundle is built from, read in the transaction that stores it.
#[derive(Debug, Clone)]
pub struct BundleState {
    /// Every user.
    pub users: Vec<User>,
    /// Every device.
    pub devices: Vec<Device>,
    /// Every node.
    pub nodes: Vec<Node>,
    /// The revocation state.
    pub revocations: Revocations,
}

/// A stored bundle version.
#[derive(Debug, Clone)]
pub struct StoredBundle {
    /// The version.
    pub version: u64,
    /// The policy digest.
    pub digest: String,
    /// The connector view, signed.
    pub connector_jws: String,
    /// The relay view, signed.
    pub relay_jws: String,
}

/// Commit-to-cut latency, from node acknowledgements.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct LatencySummary {
    /// How many acknowledgements were counted.
    pub count: u64,
    /// Median latency, milliseconds.
    pub p50_ms: i64,
    /// 99th percentile latency, milliseconds.
    pub p99_ms: i64,
    /// Largest latency, milliseconds.
    pub max_ms: i64,
    /// Acknowledgements slower than `REVOCATION_DEADLINE`.
    pub over_deadline: u64,
}

/// The database.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
}

fn migrator() -> Migrator {
    Migrator::with_migrations(vec![
        Migration::new(
            1,
            "initial".into(),
            MigrationType::Simple,
            include_str!("../migrations/0001_initial.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            2,
            "console".into(),
            MigrationType::Simple,
            include_str!("../migrations/0002_console.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            3,
            "accounts".into(),
            MigrationType::Simple,
            include_str!("../migrations/0003_accounts.sql").into_sql_str(),
            false,
        ),
    ])
}

impl Store {
    /// Opens (creating if needed) the SQLite database at `path` and applies
    /// migrations.
    pub async fn open(path: &Path) -> Result<Store, Error> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(db)?;
        migrator()
            .run(&pool)
            .await
            .map_err(|e| Error::Store(format!("migration failed: {e}")))?;
        Ok(Store { pool })
    }

    /// Begins a write transaction. SQLite takes its single write lock up
    /// front (`BEGIN IMMEDIATE`), so a transaction that reads before it
    /// writes waits for other writers instead of failing when another
    /// connection wrote in between; the PostgreSQL backend will use a plain
    /// `BEGIN` and row locks.
    async fn begin(&self) -> Result<Tx<'static>, Error> {
        self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)
    }

    // Settings and keys.

    /// Reads a setting.
    pub async fn setting(&self, name: &str) -> Result<Option<String>, Error> {
        sqlx::query_scalar("SELECT value FROM settings WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)
    }

    /// Writes a setting unless it exists; returns the stored value.
    pub async fn init_setting(&self, name: &str, value: &str) -> Result<String, Error> {
        sqlx::query(
            "INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT (name) DO NOTHING",
        )
        .bind(name)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(self.setting(name).await?.unwrap_or_default())
    }

    /// A sealed key and its certificate.
    pub async fn signing_key(&self, name: &str) -> Result<Option<(String, Option<String>)>, Error> {
        sqlx::query_as("SELECT sealed_key, certificate FROM signing_keys WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)
    }

    /// Stores a sealed key; refuses to replace one.
    pub async fn insert_signing_key(
        &self,
        name: &str,
        sealed: &str,
        certificate: Option<&str>,
    ) -> Result<(), Error> {
        sqlx::query("INSERT INTO signing_keys (name, sealed_key, certificate, created_at) VALUES (?, ?, ?, ?)")
            .bind(name)
            .bind(sealed)
            .bind(certificate)
            .bind(clock::now_secs())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn next_counter(tx: &mut Tx<'_>, name: &str) -> Result<i64, Error> {
        sqlx::query_scalar("UPDATE counters SET value = value + 1 WHERE name = ? RETURNING value")
            .bind(name)
            .fetch_one(&mut **tx)
            .await
            .map_err(db)
    }

    // Events.

    async fn append_event(tx: &mut Tx<'_>, body: EventBody) -> Result<Event, Error> {
        let seq = Self::next_counter(tx, "event_seq").await?;
        let committed_at_ms = clock::now_millis();
        let payload = serde_json::to_string(&body).map_err(|e| Error::Internal(e.to_string()))?;
        sqlx::query("INSERT INTO events (seq, kind, payload, committed_at_ms) VALUES (?, ?, ?, ?)")
            .bind(seq)
            .bind(body.kind())
            .bind(payload)
            .bind(committed_at_ms)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        Ok(Event {
            seq: seq as u64,
            committed_at_ms,
            body,
        })
    }

    /// Commits an event on its own.
    pub async fn emit(&self, body: EventBody) -> Result<Event, Error> {
        let mut tx = self.begin().await?;
        let event = Self::append_event(&mut tx, body).await?;
        tx.commit().await.map_err(db)?;
        Ok(event)
    }

    /// Events after `seq`, oldest first, at most `limit`.
    pub async fn events_after(&self, seq: u64, limit: i64) -> Result<Vec<Event>, Error> {
        let rows: Vec<(i64, String, i64)> = sqlx::query_as(
            "SELECT seq, payload, committed_at_ms FROM events WHERE seq > ? ORDER BY seq LIMIT ?",
        )
        .bind(seq as i64)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|(seq, payload, committed_at_ms)| {
                Ok(Event {
                    seq: seq as u64,
                    committed_at_ms,
                    body: serde_json::from_str(&payload)
                        .map_err(|e| Error::Internal(e.to_string()))?,
                })
            })
            .collect()
    }

    /// The latest committed sequence number and the oldest retained one
    /// (the latest plus one when the log is empty).
    pub async fn event_bounds(&self) -> Result<(u64, u64), Error> {
        let latest: i64 = sqlx::query_scalar("SELECT value FROM counters WHERE name = 'event_seq'")
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        let oldest: Option<i64> = sqlx::query_scalar("SELECT MIN(seq) FROM events")
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        Ok((latest as u64, oldest.unwrap_or(latest + 1) as u64))
    }

    /// Drops events up to the last one committed before `before_ms`, keeping
    /// at least the last one so resumption can tell how far back the log
    /// goes. Only a prefix of the log is ever dropped, so what remains has
    /// no gaps even if the clock stepped back between commits.
    pub async fn prune_events(&self, before_ms: i64) -> Result<u64, Error> {
        let r = sqlx::query(
            "DELETE FROM events WHERE seq <= (SELECT MAX(seq) FROM events WHERE committed_at_ms < ?) \
             AND seq < (SELECT MAX(seq) FROM events)",
        )
        .bind(before_ms)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM event_acks WHERE received_at_ms < ?")
            .bind(before_ms)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(r.rows_affected())
    }

    /// Records acknowledgements from a node and returns the commit-to-cut
    /// latency of each new one, in milliseconds.
    pub async fn record_acks(
        &self,
        node_id: &str,
        acks: &[warren_core::events::Ack],
    ) -> Result<Vec<(u64, i64)>, Error> {
        let mut tx = self.begin().await?;
        let mut out = Vec::new();
        let now = clock::now_millis();
        for ack in acks {
            let committed: Option<i64> =
                sqlx::query_scalar("SELECT committed_at_ms FROM events WHERE seq = ?")
                    .bind(ack.seq as i64)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db)?;
            let Some(committed) = committed else { continue };
            let inserted = sqlx::query(
                "INSERT INTO event_acks (seq, node_id, applied_at_ms, received_at_ms, connections_cut) \
                 VALUES (?, ?, ?, ?, ?) ON CONFLICT (seq, node_id) DO NOTHING",
            )
            .bind(ack.seq as i64)
            .bind(node_id)
            .bind(ack.applied_at_ms)
            .bind(now)
            .bind(i64::try_from(ack.connections_cut).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            if inserted.rows_affected() == 1 {
                // The node reports applied_at_ms; it never overflows the sum.
                out.push((ack.seq, ack.applied_at_ms.saturating_sub(committed)));
            }
        }
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    /// Commit-to-cut latency over every retained acknowledgement.
    pub async fn latency_summary(&self, deadline_ms: i64) -> Result<LatencySummary, Error> {
        let pairs: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT a.applied_at_ms, e.committed_at_ms FROM event_acks a JOIN events e ON e.seq = a.seq",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        // Subtract here rather than in SQL: applied_at_ms comes from nodes.
        let mut values: Vec<i64> = pairs
            .into_iter()
            .map(|(applied, committed)| applied.saturating_sub(committed))
            .collect();
        if values.is_empty() {
            return Ok(LatencySummary::default());
        }
        values.sort_unstable();
        let at = |q: f64| values[((values.len() - 1) as f64 * q).round() as usize];
        Ok(LatencySummary {
            count: values.len() as u64,
            p50_ms: at(0.5),
            p99_ms: at(0.99),
            max_ms: values[values.len() - 1],
            over_deadline: values.iter().filter(|v| **v > deadline_ms).count() as u64,
        })
    }

    // Users.

    fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<User, Error> {
        let groups: String = row.try_get("groups_json").map_err(db)?;
        Ok(User {
            id: row.try_get("id").map_err(db)?,
            issuer: row.try_get("issuer").map_err(db)?,
            subject: row.try_get("subject").map_err(db)?,
            email: row.try_get("email").map_err(db)?,
            groups: serde_json::from_str(&groups).unwrap_or_default(),
            disabled: row.try_get("disabled").map_err(db)?,
            last_auth_at: row.try_get("last_auth_at").map_err(db)?,
            deleted: row
                .try_get::<Option<i64>, _>("deleted_at")
                .map_err(db)?
                .is_some(),
        })
    }

    /// Adds warren's own groups to a user's IdP groups.
    fn add_local_groups(user: &mut User, local: impl IntoIterator<Item = String>) {
        user.groups
            .extend(local.into_iter().map(|g| format!("{LOCAL_PREFIX}{g}")));
    }

    async fn read_user(conn: &mut SqliteConnection, id: &str) -> Result<Option<User>, Error> {
        let row = sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db)?;
        let Some(row) = row else { return Ok(None) };
        let mut user = Self::user_from_row(&row)?;
        let local: Vec<String> = sqlx::query_scalar(
            "SELECT group_name FROM group_members WHERE user_id = ? ORDER BY group_name",
        )
        .bind(id)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        Self::add_local_groups(&mut user, local);
        Ok(Some(user))
    }

    /// Records a sign-in: creates the user or updates their email and
    /// groups. Returns the user and whether anything policy depends on
    /// changed. A sign-in that removes groups also emits `bundle_updated`
    /// later, through the publisher.
    ///
    /// Invites for the sign-in's verified email are claimed in the same
    /// transaction: their groups bind to this user's issuer and subject.
    pub async fn record_sign_in(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
        groups: &[String],
        auth_time: i64,
    ) -> Result<(User, bool), Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let groups_json =
            serde_json::to_string(groups).map_err(|e| Error::Internal(e.to_string()))?;
        let existing = sqlx::query("SELECT * FROM users WHERE issuer = ? AND subject = ?")
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let (id, changed) = match existing {
            Some(row) => {
                let user = Self::user_from_row(&row)?;
                let changed = user.email != email || user.groups != groups;
                sqlx::query("UPDATE users SET email = ?, groups_json = ?, updated_at = ?, last_auth_at = ? WHERE id = ?")
                    .bind(email)
                    .bind(&groups_json)
                    .bind(now)
                    .bind(auth_time)
                    .bind(&user.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
                (user.id, changed)
            }
            None => {
                let id = new_id("u")?;
                sqlx::query(
                    "INSERT INTO users (id, issuer, subject, email, groups_json, disabled, created_at, updated_at, last_auth_at) \
                     VALUES (?, ?, ?, ?, ?, FALSE, ?, ?, ?)",
                )
                .bind(&id)
                .bind(issuer)
                .bind(subject)
                .bind(email)
                .bind(&groups_json)
                .bind(now)
                .bind(now)
                .bind(auth_time)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                (id, true)
            }
        };
        let claimed = if issuer != LOCAL_ISSUER && !email.is_empty() {
            Self::claim_invites(&mut tx, &id, email).await?
        } else {
            false
        };
        tx.commit().await.map_err(db)?;
        let user = self
            .user(&id)
            .await?
            .ok_or_else(|| Error::Internal("user vanished".into()))?;
        Ok((user, changed || claimed))
    }

    /// Turns the invites for `email` into memberships of `user_id`.
    async fn claim_invites(tx: &mut Tx<'_>, user_id: &str, email: &str) -> Result<bool, Error> {
        let invites: Vec<(String, String)> = sqlx::query_as(
            "DELETE FROM group_invites WHERE email = ? RETURNING group_name, managed_by",
        )
        .bind(email)
        .fetch_all(&mut **tx)
        .await
        .map_err(db)?;
        let mut changed = false;
        for (group, managed_by) in invites {
            changed |= sqlx::query(
                "INSERT INTO group_members (group_name, user_id, managed_by, invited_email, created_at) \
                 VALUES (?, ?, ?, ?, ?) ON CONFLICT (group_name, user_id) DO NOTHING",
            )
            .bind(&group)
            .bind(user_id)
            .bind(&managed_by)
            .bind(email)
            .bind(clock::now_secs())
            .execute(&mut **tx)
            .await
            .map_err(db)?
            .rows_affected()
                > 0;
        }
        Ok(changed)
    }

    /// A user by ID.
    pub async fn user(&self, id: &str) -> Result<Option<User>, Error> {
        Self::read_user(&mut *self.pool.acquire().await.map_err(db)?, id).await
    }

    /// A user by ID, else by email, else by IdP subject or username;
    /// `local:<username>` names a built-in account. An email or subject
    /// shared by several users matches none of them. Deleted accounts are
    /// found by ID only.
    pub async fn find_user(&self, key: &str) -> Result<Option<User>, Error> {
        if let Some(user) = self.user(key).await? {
            return Ok(Some(user));
        }
        let unique = |ids: Vec<String>| match ids.as_slice() {
            [id] => Some(id.clone()),
            _ => None,
        };
        let id = if let Some(username) = key.strip_prefix(LOCAL_PREFIX) {
            unique(
                sqlx::query_scalar(
                    "SELECT id FROM users WHERE issuer = ? AND subject = ? AND deleted_at IS NULL",
                )
                .bind(LOCAL_ISSUER)
                .bind(username)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
            )
        } else {
            let by_email = sqlx::query_scalar(
                "SELECT id FROM users WHERE email = ? AND email <> '' AND deleted_at IS NULL LIMIT 2",
            )
            .bind(key.to_ascii_lowercase())
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            match unique(by_email) {
                Some(id) => Some(id),
                None => unique(
                    sqlx::query_scalar(
                        "SELECT id FROM users WHERE subject = ? AND deleted_at IS NULL LIMIT 2",
                    )
                    .bind(key)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(db)?,
                ),
            }
        };
        match id {
            Some(id) => self.user(&id).await,
            None => Ok(None),
        }
    }

    /// Deletes sign-ins and one-time codes that expired unused.
    pub async fn prune_auth(&self) -> Result<(), Error> {
        let now = clock::now_secs();
        for sql in [
            "DELETE FROM auth_requests WHERE expires_at <= ?",
            "DELETE FROM auth_codes WHERE expires_at <= ?",
            "DELETE FROM console_sessions WHERE expires_at <= ?",
            "DELETE FROM setup_tokens WHERE expires_at <= ?",
        ] {
            sqlx::query(sql)
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(db)?;
        }
        Ok(())
    }

    /// Every user.
    pub async fn users(&self) -> Result<Vec<User>, Error> {
        Self::read_users(&mut *self.pool.acquire().await.map_err(db)?).await
    }

    async fn read_users(conn: &mut SqliteConnection) -> Result<Vec<User>, Error> {
        let rows = sqlx::query("SELECT * FROM users ORDER BY id")
            .fetch_all(&mut *conn)
            .await
            .map_err(db)?;
        let links: Vec<(String, String)> = sqlx::query_as(
            "SELECT user_id, group_name FROM group_members ORDER BY user_id, group_name",
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        let mut local: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (user_id, group) in links {
            local.entry(user_id).or_default().push(group);
        }
        rows.iter()
            .map(|row| {
                let mut user = Self::user_from_row(row)?;
                if let Some(groups) = local.remove(&user.id) {
                    Self::add_local_groups(&mut user, groups);
                }
                Ok(user)
            })
            .collect()
    }

    /// Disables or enables a user. Disabling commits a `user_disabled`
    /// event in the same transaction. Returns the event, if one was
    /// emitted, and whether the user changed.
    pub async fn set_user_disabled(
        &self,
        id: &str,
        disabled: bool,
    ) -> Result<(bool, Option<Event>), Error> {
        let mut tx = self.begin().await?;
        let r = sqlx::query(
            "UPDATE users SET disabled = ?, updated_at = ? WHERE id = ? AND disabled <> ?",
        )
        .bind(disabled)
        .bind(clock::now_secs())
        .bind(id)
        .bind(disabled)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let changed = r.rows_affected() == 1;
        let event = if changed && disabled {
            Some(Self::append_event(&mut tx, EventBody::UserDisabled { user_id: id.into() }).await?)
        } else {
            None
        };
        tx.commit().await.map_err(db)?;
        Ok((changed, event))
    }

    // Built-in accounts.

    fn local_account_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<LocalAccount, Error> {
        Ok(LocalAccount {
            user_id: row.try_get("user_id").map_err(db)?,
            username: row.try_get("username").map_err(db)?,
            display_name: row.try_get("display_name").map_err(db)?,
            password_hash: row.try_get("password_hash").map_err(db)?,
            totp_secret: row.try_get("totp_secret").map_err(db)?,
            totp_last_step: row.try_get("totp_last_step").map_err(db)?,
            failed_attempts: row.try_get("failed_attempts").map_err(db)?,
            locked_until: row.try_get("locked_until").map_err(db)?,
            managed_by: row.try_get("managed_by").map_err(db)?,
            recovery_codes: row.try_get("recovery_codes").map_err(db)?,
        })
    }

    /// A built-in account by user ID.
    pub async fn local_account(&self, user_id: &str) -> Result<Option<LocalAccount>, Error> {
        let row = sqlx::query(local_account_select!("WHERE a.user_id = ?"))
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.as_ref().map(Self::local_account_from_row).transpose()
    }

    /// A built-in account by username.
    pub async fn local_account_named(&self, username: &str) -> Result<Option<LocalAccount>, Error> {
        let row = sqlx::query(local_account_select!(
            "WHERE u.issuer = ? AND u.subject = ? AND u.deleted_at IS NULL"
        ))
        .bind(LOCAL_ISSUER)
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.as_ref().map(Self::local_account_from_row).transpose()
    }

    /// Every built-in account.
    pub async fn local_accounts(&self) -> Result<Vec<LocalAccount>, Error> {
        let rows = sqlx::query(local_account_select!("ORDER BY u.subject"))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter().map(Self::local_account_from_row).collect()
    }

    /// Whether any built-in account exists.
    pub async fn has_local_accounts(&self) -> Result<bool, Error> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM local_accounts")
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        Ok(n > 0)
    }

    async fn insert_local_user(
        tx: &mut Tx<'_>,
        username: &str,
        email: Option<&str>,
        display_name: Option<&str>,
        managed_by: &str,
        password_hash: Option<&str>,
    ) -> Result<String, Error> {
        let taken: Option<String> = sqlx::query_scalar(
            "SELECT id FROM users WHERE issuer = ? AND subject = ? AND deleted_at IS NULL",
        )
        .bind(LOCAL_ISSUER)
        .bind(username)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?;
        if taken.is_some() {
            return Err(Error::Conflict(format!(
                "a built-in account named {username} already exists"
            )));
        }
        let id = new_id("u")?;
        let now = clock::now_secs();
        sqlx::query(
            "INSERT INTO users (id, issuer, subject, email, groups_json, disabled, created_at, updated_at, last_auth_at) \
             VALUES (?, ?, ?, ?, '[]', FALSE, ?, ?, 0)",
        )
        .bind(&id)
        .bind(LOCAL_ISSUER)
        .bind(username)
        .bind(email.unwrap_or(""))
        .bind(now)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        sqlx::query(
            "INSERT INTO local_accounts (user_id, display_name, password_hash, totp_secret, totp_last_step, failed_attempts, locked_until, managed_by, created_at, updated_at) \
             VALUES (?, ?, ?, NULL, 0, 0, 0, ?, ?, ?)",
        )
        .bind(&id)
        .bind(display_name.unwrap_or(""))
        .bind(password_hash)
        .bind(managed_by)
        .bind(now)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        Ok(id)
    }

    async fn insert_setup_token(
        tx: &mut Tx<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<(), Error> {
        sqlx::query("INSERT INTO setup_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
            .bind(token_hash)
            .bind(user_id)
            .bind(expires_at)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Creates a built-in account managed through the API, in warren's own
    /// groups `groups`, with either a password (the bootstrap admin) or a
    /// setup link's token hash and expiry.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_local_user(
        &self,
        username: &str,
        email: Option<&str>,
        display_name: Option<&str>,
        groups: &[String],
        password_hash: Option<&str>,
        setup: Option<(&str, i64)>,
    ) -> Result<User, Error> {
        let mut tx = self.begin().await?;
        let id = Self::insert_local_user(
            &mut tx,
            username,
            email,
            display_name,
            MANAGED_BY_API,
            password_hash,
        )
        .await?;
        for group in groups {
            Self::insert_membership(&mut tx, group, &id, MANAGED_BY_API, None).await?;
        }
        if let Some((hash, expires_at)) = setup {
            Self::insert_setup_token(&mut tx, &id, hash, expires_at).await?;
        }
        tx.commit().await.map_err(db)?;
        self.user(&id)
            .await?
            .ok_or_else(|| Error::Internal("user vanished".into()))
    }

    /// Deletes a built-in account inside `tx`: it stays as a disabled row,
    /// so its revocation stays in every bundle, with its username freed
    /// and its credentials, memberships, pending codes and sign-ins in
    /// progress gone. Commits a
    /// `user_disabled` event if it was enabled. Returns `None` if there is
    /// no such live account.
    async fn delete_local_user_tx(
        tx: &mut Tx<'_>,
        user_id: &str,
    ) -> Result<Option<Option<Event>>, Error> {
        let was_disabled: Option<bool> = sqlx::query_scalar(
            "SELECT disabled FROM users WHERE id = ? AND issuer = ? AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(LOCAL_ISSUER)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?;
        let Some(was_disabled) = was_disabled else {
            return Ok(None);
        };
        let now = clock::now_secs();
        sqlx::query(
            "UPDATE users SET disabled = TRUE, deleted_at = ?, updated_at = ?, \
             subject = 'deleted:' || id, email = '', groups_json = '[]' WHERE id = ?",
        )
        .bind(now)
        .bind(now)
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        for sql in [
            "DELETE FROM local_accounts WHERE user_id = ?",
            "DELETE FROM recovery_codes WHERE user_id = ?",
            "DELETE FROM setup_tokens WHERE user_id = ?",
            "DELETE FROM group_members WHERE user_id = ?",
            "DELETE FROM auth_codes WHERE user_id = ?",
            "DELETE FROM auth_requests WHERE local_user_id = ?",
        ] {
            sqlx::query(sql)
                .bind(user_id)
                .execute(&mut **tx)
                .await
                .map_err(db)?;
        }
        let event = if was_disabled {
            None
        } else {
            Some(
                Self::append_event(
                    tx,
                    EventBody::UserDisabled {
                        user_id: user_id.into(),
                    },
                )
                .await?,
            )
        };
        Ok(Some(event))
    }

    /// Deletes a built-in account (see [`Store::delete_local_user_tx`]).
    /// Returns whether it existed, and the event committed with it.
    pub async fn delete_local_user(&self, user_id: &str) -> Result<(bool, Option<Event>), Error> {
        let mut tx = self.begin().await?;
        let outcome = Self::delete_local_user_tx(&mut tx, user_id).await?;
        tx.commit().await.map_err(db)?;
        Ok(match outcome {
            Some(event) => (true, event),
            None => (false, None),
        })
    }

    /// Resets a built-in account's credentials: clears the password, the
    /// authenticator, recovery codes, setup links, sign-ins in progress and
    /// the lockout, revokes
    /// every live session with a `session_revoked` event each, and stores a
    /// new setup link. Returns `None` if there is no such account.
    pub async fn reset_local_credentials(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<Option<Vec<Event>>, Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let r = sqlx::query(
            "UPDATE local_accounts SET password_hash = NULL, totp_secret = NULL, totp_last_step = 0, \
             failed_attempts = 0, locked_until = 0, updated_at = ? WHERE user_id = ?",
        )
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Ok(None);
        }
        for sql in [
            "DELETE FROM recovery_codes WHERE user_id = ?",
            "DELETE FROM setup_tokens WHERE user_id = ?",
            "DELETE FROM auth_codes WHERE user_id = ?",
            "DELETE FROM auth_requests WHERE local_user_id = ?",
        ] {
            sqlx::query(sql)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        Self::insert_setup_token(&mut tx, user_id, token_hash, expires_at).await?;
        let sessions: Vec<String> = sqlx::query_scalar(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? RETURNING id",
        )
        .bind(now)
        .bind(user_id)
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut events = Vec::new();
        for session_id in sessions {
            events
                .push(Self::append_event(&mut tx, EventBody::SessionRevoked { session_id }).await?);
        }
        tx.commit().await.map_err(db)?;
        Ok(Some(events))
    }

    /// Lifts a built-in account's lockout. Returns whether it was locked.
    pub async fn unlock_local_account(&self, user_id: &str) -> Result<bool, Error> {
        let r = sqlx::query(
            "UPDATE local_accounts SET failed_attempts = 0, locked_until = 0, updated_at = ? \
             WHERE user_id = ? AND (locked_until > ? OR failed_attempts > 0)",
        )
        .bind(clock::now_secs())
        .bind(user_id)
        .bind(clock::now_secs())
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    /// Counts a sign-in attempt against a built-in account before it is
    /// checked, so concurrent attempts cannot outrun the lockout: the
    /// attempt counts as failed until [`Store::refund_local_attempt`] or a
    /// completed sign-in says otherwise, and the attempt that makes
    /// `MAX_FAILED_ATTEMPTS` in a row locks the account for
    /// `LOCKOUT_SECONDS`. Returns `None`, counting nothing, while the
    /// account is locked; otherwise the lock this attempt set (0 if none).
    pub async fn reserve_local_attempt(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Option<i64>, Error> {
        sqlx::query_scalar(
            "UPDATE local_accounts SET \
             failed_attempts = CASE WHEN failed_attempts + 1 >= ? THEN 0 ELSE failed_attempts + 1 END, \
             locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE 0 END, updated_at = ? \
             WHERE user_id = ? AND locked_until <= ? RETURNING locked_until",
        )
        .bind(MAX_FAILED_ATTEMPTS)
        .bind(MAX_FAILED_ATTEMPTS)
        .bind(now + LOCKOUT_SECONDS)
        .bind(now)
        .bind(user_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)
    }

    /// Takes back an attempt [`Store::reserve_local_attempt`] counted, once
    /// its step succeeded, lifting the lock it set (`lock`) if it set one.
    pub async fn refund_local_attempt(&self, user_id: &str, lock: i64) -> Result<(), Error> {
        sqlx::query(
            "UPDATE local_accounts SET \
             failed_attempts = CASE WHEN ? > 0 AND locked_until = ? THEN ? \
             WHEN failed_attempts > 0 THEN failed_attempts - 1 ELSE 0 END, \
             locked_until = CASE WHEN ? > 0 AND locked_until = ? THEN 0 ELSE locked_until END, \
             updated_at = ? WHERE user_id = ?",
        )
        .bind(lock)
        .bind(lock)
        .bind(MAX_FAILED_ATTEMPTS - 1)
        .bind(lock)
        .bind(lock)
        .bind(clock::now_secs())
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Records a completed sign-in with a built-in account: clears the
    /// failure count and lockout, records when, and, for an authenticator code, its
    /// time step, which must be later than the last one accepted. Returns
    /// false if it was not (the code was replayed).
    pub async fn record_local_success(
        &self,
        user_id: &str,
        totp_step: Option<i64>,
        now: i64,
    ) -> Result<bool, Error> {
        let mut tx = self.begin().await?;
        let r = match totp_step {
            Some(step) => sqlx::query(
                "UPDATE local_accounts SET totp_last_step = ?, failed_attempts = 0, locked_until = 0, updated_at = ? \
                 WHERE user_id = ? AND totp_last_step < ?",
            )
            .bind(step)
            .bind(now)
            .bind(user_id)
            .bind(step),
            None => sqlx::query(
                "UPDATE local_accounts SET failed_attempts = 0, locked_until = 0, updated_at = ? WHERE user_id = ?",
            )
            .bind(now)
            .bind(user_id),
        }
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Ok(false);
        }
        sqlx::query("UPDATE users SET last_auth_at = ?, updated_at = ? WHERE id = ?")
            .bind(now)
            .bind(now)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    /// Replaces a built-in account's password hash.
    pub async fn set_password_hash(&self, user_id: &str, hash: &str) -> Result<(), Error> {
        sqlx::query(
            "UPDATE local_accounts SET password_hash = ?, updated_at = ? WHERE user_id = ?",
        )
        .bind(hash)
        .bind(clock::now_secs())
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Enrolls an authenticator (its sealed secret, and the time step of
    /// the code that proved it) with new recovery codes, replacing any
    /// left, and clears the failure count and lockout. Refuses, returning
    /// false, if one was enrolled meanwhile or the password was reset.
    pub async fn enroll_totp(
        &self,
        user_id: &str,
        sealed_secret: &str,
        step: i64,
        recovery_hashes: &[String],
    ) -> Result<bool, Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let r = sqlx::query(
            "UPDATE local_accounts SET totp_secret = ?, totp_last_step = ?, failed_attempts = 0, locked_until = 0, updated_at = ? \
             WHERE user_id = ? AND totp_secret IS NULL AND password_hash IS NOT NULL",
        )
        .bind(sealed_secret)
        .bind(step)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Ok(false);
        }
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        for hash in recovery_hashes {
            sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)")
                .bind(user_id)
                .bind(hash)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        sqlx::query("UPDATE users SET last_auth_at = ?, updated_at = ? WHERE id = ?")
            .bind(now)
            .bind(now)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    /// Spends a recovery code. Returns how many are left, or `None` if the
    /// code is not one of the account's unused codes.
    pub async fn use_recovery_code(&self, user_id: &str, hash: &str) -> Result<Option<i64>, Error> {
        let mut tx = self.begin().await?;
        let used = sqlx::query("DELETE FROM recovery_codes WHERE user_id = ? AND code_hash = ?")
            .bind(user_id)
            .bind(hash)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected()
            == 1;
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(used.then_some(left))
    }

    /// The account an unexpired setup link is for: (user ID, username).
    pub async fn setup_link_account(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, String)>, Error> {
        sqlx::query_as(
            "SELECT t.user_id, u.subject FROM setup_tokens t JOIN users u ON u.id = t.user_id \
             JOIN local_accounts a ON a.user_id = t.user_id \
             WHERE t.token_hash = ? AND t.expires_at > ?",
        )
        .bind(token_hash)
        .bind(clock::now_secs())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)
    }

    /// Spends a setup link to set the account's password, and drops any
    /// other link for it. Returns the user ID, or `None` if the link is
    /// unknown, used or expired.
    pub async fn complete_setup(
        &self,
        token_hash: &str,
        password_hash: &str,
    ) -> Result<Option<String>, Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let user_id: Option<String> = sqlx::query_scalar(
            "DELETE FROM setup_tokens WHERE token_hash = ? AND expires_at > ? RETURNING user_id",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let Some(user_id) = user_id else {
            return Ok(None);
        };
        sqlx::query("DELETE FROM setup_tokens WHERE user_id = ?")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let r = sqlx::query(
            "UPDATE local_accounts SET password_hash = ?, failed_attempts = 0, locked_until = 0, updated_at = ? \
             WHERE user_id = ?",
        )
        .bind(password_hash)
        .bind(now)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Ok(None);
        }
        tx.commit().await.map_err(db)?;
        Ok(Some(user_id))
    }

    // Warren's own groups.

    async fn insert_membership(
        tx: &mut Tx<'_>,
        group: &str,
        user_id: &str,
        managed_by: &str,
        invited_email: Option<&str>,
    ) -> Result<bool, Error> {
        Ok(sqlx::query(
            "INSERT INTO group_members (group_name, user_id, managed_by, invited_email, created_at) \
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (group_name, user_id) DO NOTHING",
        )
        .bind(group)
        .bind(user_id)
        .bind(managed_by)
        .bind(invited_email)
        .bind(clock::now_secs())
        .execute(&mut **tx)
        .await
        .map_err(db)?
        .rows_affected()
            > 0)
    }

    /// Every membership in warren's own groups.
    pub async fn memberships(&self) -> Result<Vec<Membership>, Error> {
        let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT group_name, user_id, managed_by, invited_email FROM group_members ORDER BY group_name, user_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|(group, user_id, managed_by, invited_email)| Membership {
                group,
                user_id,
                managed_by,
                invited_email,
            })
            .collect())
    }

    /// Every pending invite.
    pub async fn invites(&self) -> Result<Vec<Invite>, Error> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT group_name, email, managed_by FROM group_invites ORDER BY email, group_name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|(group, email, managed_by)| Invite {
                group,
                email,
                managed_by,
            })
            .collect())
    }

    /// Sets the groups a user is in through the API to exactly `groups`;
    /// memberships the policy directory manages are left alone. Returns
    /// whether anything changed.
    pub async fn set_user_groups(&self, user_id: &str, groups: &[String]) -> Result<bool, Error> {
        let mut tx = self.begin().await?;
        let current: Vec<String> = sqlx::query_scalar(
            "SELECT group_name FROM group_members WHERE user_id = ? AND managed_by = ?",
        )
        .bind(user_id)
        .bind(MANAGED_BY_API)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut changed = false;
        for group in current.iter().filter(|g| !groups.contains(g)) {
            sqlx::query("DELETE FROM group_members WHERE group_name = ? AND user_id = ?")
                .bind(group)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            changed = true;
        }
        for group in groups {
            changed |=
                Self::insert_membership(&mut tx, group, user_id, MANAGED_BY_API, None).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(changed)
    }

    /// Brings built-in accounts and warren's own groups in line with the
    /// policy directory, in one transaction. Accounts it declares are
    /// created (without credentials: an admin issues each a setup link) or
    /// taken over from the API and updated; accounts it declared before and
    /// no longer does are deleted, with their revocation. Groups it
    /// declares are its alone: their members are exactly its usernames and
    /// the IdP users its emails have bound to, the rest of its emails wait
    /// as invites, and API memberships of those groups are removed.
    pub async fn reconcile_accounts(&self, desired: &DesiredAccounts) -> Result<Reconciled, Error> {
        let mut tx = self.begin().await?;
        let mut out = Reconciled::default();
        let existing: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT a.user_id, u.subject, a.managed_by FROM local_accounts a JOIN users u ON u.id = a.user_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let now = clock::now_secs();
        let mut ids: BTreeMap<String, String> = BTreeMap::new();
        for (username, email, display_name) in &desired.users {
            match existing.iter().find(|(_, name, _)| name == username) {
                Some((id, _, managed_by)) => {
                    if managed_by != MANAGED_BY_CONFIG {
                        out.adopted.push(username.clone());
                    }
                    sqlx::query(
                        "UPDATE local_accounts SET managed_by = ?, display_name = ?, updated_at = ? WHERE user_id = ?",
                    )
                    .bind(MANAGED_BY_CONFIG)
                    .bind(display_name.as_deref().unwrap_or(""))
                    .bind(now)
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
                    out.changed |= sqlx::query(
                        "UPDATE users SET email = ?, updated_at = ? WHERE id = ? AND email <> ?",
                    )
                    .bind(email.as_deref().unwrap_or(""))
                    .bind(now)
                    .bind(id)
                    .bind(email.as_deref().unwrap_or(""))
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?
                    .rows_affected()
                        > 0;
                    ids.insert(username.clone(), id.clone());
                }
                None => {
                    let id = Self::insert_local_user(
                        &mut tx,
                        username,
                        email.as_deref(),
                        display_name.as_deref(),
                        MANAGED_BY_CONFIG,
                        None,
                    )
                    .await?;
                    out.created.push(username.clone());
                    out.changed = true;
                    ids.insert(username.clone(), id);
                }
            }
        }
        for (id, username, managed_by) in &existing {
            if managed_by == MANAGED_BY_CONFIG && !ids.contains_key(username) {
                if let Some(event) = Self::delete_local_user_tx(&mut tx, id).await? {
                    out.events.extend(event);
                    out.deleted.push(username.clone());
                    out.changed = true;
                }
            } else if !ids.contains_key(username) {
                ids.insert(username.clone(), id.clone());
            }
        }

        let declared: BTreeSet<&str> = desired.groups.iter().map(|(g, _, _)| g.as_str()).collect();
        let memberships: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT group_name, user_id, managed_by, invited_email FROM group_members",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let invites: Vec<(String, String, String)> =
            sqlx::query_as("SELECT group_name, email, managed_by FROM group_invites")
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?;
        let mut keep: BTreeSet<(String, String)> = BTreeSet::new();
        let mut keep_invites: BTreeSet<(String, String)> = BTreeSet::new();
        for (group, usernames, emails) in &desired.groups {
            for username in usernames {
                match ids.get(username) {
                    Some(id) => {
                        keep.insert((group.clone(), id.clone()));
                    }
                    None => out.warnings.push(format!(
                        "LocalGroup {group} lists {username}, which is not a built-in account"
                    )),
                }
            }
            for email in emails {
                let bound = memberships.iter().find(|(g, _, m, e)| {
                    g == group && m == MANAGED_BY_CONFIG && e.as_deref() == Some(email.as_str())
                });
                if let Some((_, user_id, _, _)) = bound {
                    keep.insert((group.clone(), user_id.clone()));
                    continue;
                }
                let users: Vec<String> = sqlx::query_scalar(
                    "SELECT id FROM users WHERE email = ? AND issuer <> ? AND deleted_at IS NULL LIMIT 2",
                )
                .bind(email)
                .bind(LOCAL_ISSUER)
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?;
                match users.as_slice() {
                    [user_id] => {
                        // An API membership of a declared group gives way.
                        sqlx::query(
                            "DELETE FROM group_members WHERE group_name = ? AND user_id = ? AND managed_by <> ?",
                        )
                        .bind(group)
                        .bind(user_id)
                        .bind(MANAGED_BY_CONFIG)
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                        out.changed |= Self::insert_membership(
                            &mut tx,
                            group,
                            user_id,
                            MANAGED_BY_CONFIG,
                            Some(email),
                        )
                        .await?;
                        keep.insert((group.clone(), user_id.clone()));
                    }
                    [] => {
                        keep_invites.insert((group.clone(), email.clone()));
                    }
                    _ => {
                        out.warnings.push(format!(
                            "LocalGroup {group} lists {email}, which several IdP users have; it binds to none of them"
                        ));
                        keep_invites.insert((group.clone(), email.clone()));
                    }
                }
            }
        }
        // Remove memberships the policy directory no longer declares, and
        // any other membership of a group it declares.
        for (group, user_id, managed_by, _) in &memberships {
            let owned = managed_by == MANAGED_BY_CONFIG || declared.contains(group.as_str());
            if owned && !keep.contains(&(group.clone(), user_id.clone())) {
                out.changed |=
                    sqlx::query("DELETE FROM group_members WHERE group_name = ? AND user_id = ?")
                        .bind(group)
                        .bind(user_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?
                        .rows_affected()
                        > 0;
            }
        }
        for (group, user_id) in &keep {
            if !memberships
                .iter()
                .any(|(g, u, m, _)| g == group && u == user_id && m == MANAGED_BY_CONFIG)
            {
                sqlx::query(
                    "DELETE FROM group_members WHERE group_name = ? AND user_id = ? AND managed_by <> ?",
                )
                .bind(group)
                .bind(user_id)
                .bind(MANAGED_BY_CONFIG)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                out.changed |=
                    Self::insert_membership(&mut tx, group, user_id, MANAGED_BY_CONFIG, None)
                        .await?;
            }
        }
        for (group, email, managed_by) in &invites {
            let owned = managed_by == MANAGED_BY_CONFIG || declared.contains(group.as_str());
            if owned && !keep_invites.contains(&(group.clone(), email.clone())) {
                sqlx::query("DELETE FROM group_invites WHERE group_name = ? AND email = ?")
                    .bind(group)
                    .bind(email)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
        }
        for (group, email) in &keep_invites {
            sqlx::query(
                "INSERT INTO group_invites (group_name, email, managed_by, created_at) VALUES (?, ?, ?, ?) \
                 ON CONFLICT (group_name, email) DO UPDATE SET managed_by = excluded.managed_by",
            )
            .bind(group)
            .bind(email)
            .bind(MANAGED_BY_CONFIG)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    // Sign-in.

    /// Stores a sign-in in flight.
    pub async fn insert_auth_request(
        &self,
        state_hash: &str,
        r: &AuthRequest,
        expires_at: i64,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO auth_requests (state_hash, client_redirect_uri, client_state, client_challenge, nonce, idp_verifier, created_at, login, browser_hash, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(state_hash)
        .bind(&r.client_redirect_uri)
        .bind(&r.client_state)
        .bind(&r.client_challenge)
        .bind(&r.nonce)
        .bind(&r.idp_verifier)
        .bind(r.created_at)
        .bind(r.login)
        .bind(&r.browser_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    fn auth_request_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<AuthRequest, Error> {
        Ok(AuthRequest {
            client_redirect_uri: row.try_get("client_redirect_uri").map_err(db)?,
            client_state: row.try_get("client_state").map_err(db)?,
            client_challenge: row.try_get("client_challenge").map_err(db)?,
            nonce: row.try_get("nonce").map_err(db)?,
            idp_verifier: row.try_get("idp_verifier").map_err(db)?,
            created_at: row.try_get("created_at").map_err(db)?,
            login: row.try_get("login").map_err(db)?,
            browser_hash: row.try_get("browser_hash").map_err(db)?,
            local_user_id: row.try_get("local_user_id").map_err(db)?,
            local_stage: row.try_get("local_stage").map_err(db)?,
            pending_secret: row.try_get("pending_secret").map_err(db)?,
        })
    }

    /// Takes (and deletes) an unexpired sign-in in flight: each one is
    /// usable once.
    pub async fn take_auth_request(&self, state_hash: &str) -> Result<Option<AuthRequest>, Error> {
        let row = sqlx::query(
            "DELETE FROM auth_requests WHERE state_hash = ? AND expires_at > ? RETURNING *",
        )
        .bind(state_hash)
        .bind(clock::now_secs())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM auth_requests WHERE expires_at <= ?")
            .bind(clock::now_secs())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        row.as_ref().map(Self::auth_request_from_row).transpose()
    }

    /// An unexpired sign-in in flight, left in place.
    pub async fn auth_request(&self, state_hash: &str) -> Result<Option<AuthRequest>, Error> {
        let row =
            sqlx::query("SELECT * FROM auth_requests WHERE state_hash = ? AND expires_at > ?")
                .bind(state_hash)
                .bind(clock::now_secs())
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        row.as_ref().map(Self::auth_request_from_row).transpose()
    }

    /// Moves a built-in account sign-in from stage `from` to `to`, for
    /// `user_id`, with the authenticator secret being enrolled. Returns
    /// false when the sign-in is gone or is no longer at `from`, so each
    /// step happens once.
    pub async fn advance_auth_request(
        &self,
        state_hash: &str,
        from: Option<&str>,
        to: &str,
        user_id: &str,
        pending_secret: Option<&str>,
    ) -> Result<bool, Error> {
        let r = sqlx::query(
            "UPDATE auth_requests SET local_stage = ?, local_user_id = ?, pending_secret = ? \
             WHERE state_hash = ? AND expires_at > ? AND local_stage IS ?",
        )
        .bind(to)
        .bind(user_id)
        .bind(pending_secret)
        .bind(state_hash)
        .bind(clock::now_secs())
        .bind(from)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    /// Stores a one-time sign-in code.
    pub async fn insert_auth_code(
        &self,
        code_hash: &str,
        c: &AuthCode,
        expires_at: i64,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO auth_codes (code_hash, user_id, client_challenge, client_redirect_uri, auth_time, mfa, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(code_hash)
        .bind(&c.user_id)
        .bind(&c.client_challenge)
        .bind(&c.client_redirect_uri)
        .bind(c.auth_time)
        .bind(c.mfa)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Takes (and deletes) an unexpired one-time code.
    pub async fn take_auth_code(&self, code_hash: &str) -> Result<Option<AuthCode>, Error> {
        let row: Option<(String, String, String, i64, bool)> = sqlx::query_as(
            "DELETE FROM auth_codes WHERE code_hash = ? AND expires_at > ? \
             RETURNING user_id, client_challenge, client_redirect_uri, auth_time, mfa",
        )
        .bind(code_hash)
        .bind(clock::now_secs())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM auth_codes WHERE expires_at <= ?")
            .bind(clock::now_secs())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(row.map(
            |(user_id, client_challenge, client_redirect_uri, auth_time, mfa)| AuthCode {
                user_id,
                client_challenge,
                client_redirect_uri,
                auth_time,
                mfa,
            },
        ))
    }

    // Sessions.

    /// Creates a session.
    pub async fn insert_session(&self, s: &Session, token_hash: &str) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sessions (id, token_hash, user_id, public_key, auth_time, mfa, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&s.id)
        .bind(token_hash)
        .bind(&s.user_id)
        .bind(&s.public_key)
        .bind(s.auth_time)
        .bind(s.mfa)
        .bind(clock::now_secs())
        .bind(s.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    fn session_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Session, Error> {
        Ok(Session {
            id: row.try_get("id").map_err(db)?,
            user_id: row.try_get("user_id").map_err(db)?,
            public_key: row.try_get("public_key").map_err(db)?,
            auth_time: row.try_get("auth_time").map_err(db)?,
            mfa: row.try_get("mfa").map_err(db)?,
            expires_at: row.try_get("expires_at").map_err(db)?,
            revoked_at: row.try_get("revoked_at").map_err(db)?,
        })
    }

    /// A session by its token's hash.
    pub async fn session_by_token(&self, token_hash: &str) -> Result<Option<Session>, Error> {
        let row = sqlx::query("SELECT * FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.as_ref().map(Self::session_from_row).transpose()
    }

    /// Sessions of a user, newest first.
    pub async fn sessions_of(&self, user_id: &str) -> Result<Vec<Session>, Error> {
        let rows = sqlx::query("SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter().map(Self::session_from_row).collect()
    }

    /// Revokes a session, committing a `session_revoked` event with it.
    pub async fn revoke_session(&self, id: &str) -> Result<Option<Event>, Error> {
        let mut tx = self.begin().await?;
        let r =
            sqlx::query("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
                .bind(clock::now_secs())
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        let event = if r.rows_affected() == 1 {
            Some(
                Self::append_event(
                    &mut tx,
                    EventBody::SessionRevoked {
                        session_id: id.into(),
                    },
                )
                .await?,
            )
        } else {
            None
        };
        tx.commit().await.map_err(db)?;
        Ok(event)
    }

    // Console sessions.

    /// Creates a console session.
    pub async fn insert_console_session(
        &self,
        s: &ConsoleSession,
        token_hash: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO console_sessions (id, token_hash, user_id, auth_time, mfa, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&s.id)
        .bind(token_hash)
        .bind(&s.user_id)
        .bind(s.auth_time)
        .bind(s.mfa)
        .bind(clock::now_secs())
        .bind(s.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A console session by its token's hash.
    pub async fn console_session(&self, token_hash: &str) -> Result<Option<ConsoleSession>, Error> {
        let row = sqlx::query("SELECT * FROM console_sessions WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.as_ref()
            .map(|row| {
                Ok(ConsoleSession {
                    id: row.try_get("id").map_err(db)?,
                    user_id: row.try_get("user_id").map_err(db)?,
                    auth_time: row.try_get("auth_time").map_err(db)?,
                    mfa: row.try_get("mfa").map_err(db)?,
                    expires_at: row.try_get("expires_at").map_err(db)?,
                    ended_at: row.try_get("ended_at").map_err(db)?,
                })
            })
            .transpose()
    }

    /// Ends a console session (sign-out). Returns whether it was open.
    pub async fn end_console_session(&self, id: &str) -> Result<bool, Error> {
        let r = sqlx::query(
            "UPDATE console_sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL",
        )
        .bind(clock::now_secs())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    // Devices.

    fn device_from_row(row: &sqlx::sqlite::SqliteRow, users: Vec<String>) -> Result<Device, Error> {
        let status: String = row.try_get("status").map_err(db)?;
        let platform: String = row.try_get("platform_json").map_err(db)?;
        let trust_class: i64 = row.try_get("trust_class").map_err(db)?;
        Ok(Device {
            id: row.try_get("id").map_err(db)?,
            public_key: row.try_get("public_key").map_err(db)?,
            status: DeviceStatus::parse(&status),
            trust_class: u8::try_from(trust_class).unwrap_or(1),
            key_storage: row.try_get("key_storage").map_err(db)?,
            platform: serde_json::from_str(&platform).unwrap_or_default(),
            tunnel_v4: row.try_get("tunnel_v4").map_err(db)?,
            tunnel_v6: row.try_get("tunnel_v6").map_err(db)?,
            users,
            created_at: row.try_get("created_at").map_err(db)?,
        })
    }

    async fn device_users(&self, id: &str) -> Result<Vec<String>, Error> {
        sqlx::query_scalar("SELECT user_id FROM device_users WHERE device_id = ? ORDER BY user_id")
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }

    /// A device by ID.
    pub async fn device(&self, id: &str) -> Result<Option<Device>, Error> {
        let row = sqlx::query("SELECT * FROM devices WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        match row {
            Some(row) => {
                let users = self.device_users(id).await?;
                Ok(Some(Self::device_from_row(&row, users)?))
            }
            None => Ok(None),
        }
    }

    /// A device by its key.
    pub async fn device_by_key(&self, public_key: &str) -> Result<Option<Device>, Error> {
        let id: Option<String> = sqlx::query_scalar("SELECT id FROM devices WHERE public_key = ?")
            .bind(public_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        match id {
            Some(id) => self.device(&id).await,
            None => Ok(None),
        }
    }

    /// Every device.
    pub async fn devices(&self) -> Result<Vec<Device>, Error> {
        Self::read_devices(&mut *self.pool.acquire().await.map_err(db)?).await
    }

    async fn read_devices(conn: &mut SqliteConnection) -> Result<Vec<Device>, Error> {
        let rows = sqlx::query("SELECT * FROM devices ORDER BY id")
            .fetch_all(&mut *conn)
            .await
            .map_err(db)?;
        let links: Vec<(String, String)> = sqlx::query_as(
            "SELECT device_id, user_id FROM device_users ORDER BY device_id, user_id",
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let id: String = row.try_get("id").map_err(db)?;
                let users = links
                    .iter()
                    .filter(|(d, _)| *d == id)
                    .map(|(_, u)| u.clone())
                    .collect();
                Self::device_from_row(row, users)
            })
            .collect()
    }

    /// Enrolls a device for a user, or binds an already enrolled key to
    /// another user; a revoked device is left as it is. Addresses are
    /// allocated from the pools with `allocate`, given a fresh index.
    pub async fn enroll_device(
        &self,
        user_id: &str,
        public_key: &str,
        status: DeviceStatus,
        key_storage: &str,
        platform: &Platform,
        allocate: impl FnOnce(i64) -> Result<(String, String), Error>,
    ) -> Result<(Device, Enrollment), Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let existing: Option<(String, String)> =
            sqlx::query_as("SELECT id, status FROM devices WHERE public_key = ?")
                .bind(public_key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let (id, created) = match existing {
            Some((id, status)) if status == DeviceStatus::Revoked.as_str() => {
                drop(tx);
                let device = self
                    .device(&id)
                    .await?
                    .ok_or_else(|| Error::Internal("device vanished".into()))?;
                return Ok((device, Enrollment::Revoked));
            }
            Some((id, _)) => (id, false),
            None => {
                let id = new_id("d")?;
                let index = Self::next_counter(&mut tx, "device_address").await?;
                let (v4, v6) = allocate(index)?;
                let platform_json =
                    serde_json::to_string(platform).map_err(|e| Error::Internal(e.to_string()))?;
                sqlx::query(
                    "INSERT INTO devices (id, public_key, status, trust_class, key_storage, platform_json, address_index, tunnel_v4, tunnel_v6, approved_at, created_at, updated_at) \
                     VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&id)
                .bind(public_key)
                .bind(status.as_str())
                .bind(key_storage)
                .bind(platform_json)
                .bind(index)
                .bind(v4)
                .bind(v6)
                .bind((status == DeviceStatus::Approved).then_some(now))
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                (id, true)
            }
        };
        let bound = sqlx::query("INSERT INTO device_users (device_id, user_id, created_at) VALUES (?, ?, ?) ON CONFLICT (device_id, user_id) DO NOTHING")
            .bind(&id)
            .bind(user_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected()
            > 0;
        tx.commit().await.map_err(db)?;
        let device = self
            .device(&id)
            .await?
            .ok_or_else(|| Error::Internal("device vanished".into()))?;
        let enrollment = match (created, bound) {
            (true, _) => Enrollment::Created,
            (false, true) => Enrollment::BoundUser,
            (false, false) => Enrollment::Again,
        };
        Ok((device, enrollment))
    }

    /// Applies an admin's change to a device, atomically and only from a
    /// status that allows it: approve a pending device; enable a disabled
    /// one (back to approved if it ever was, otherwise to pending, so
    /// enabling never skips approval); disable a pending or approved one;
    /// revoke any device not yet revoked. Disabling and revoking commit a
    /// `device_disabled` event with the change. Returns the new status, or
    /// `None` when the device's status does not allow the change.
    pub async fn transition_device(
        &self,
        id: &str,
        action: DeviceAction,
    ) -> Result<(Option<DeviceStatus>, Option<Event>), Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let query = match action {
            DeviceAction::Approve => sqlx::query_scalar(
                "UPDATE devices SET status = 'approved', approved_at = ?, updated_at = ? \
                 WHERE id = ? AND status = 'pending' RETURNING status",
            )
            .bind(now),
            DeviceAction::Enable => sqlx::query_scalar(
                "UPDATE devices SET status = CASE WHEN approved_at IS NULL THEN 'pending' ELSE 'approved' END, \
                 updated_at = ? WHERE id = ? AND status = 'disabled' RETURNING status",
            ),
            DeviceAction::Disable => sqlx::query_scalar(
                "UPDATE devices SET status = 'disabled', updated_at = ? \
                 WHERE id = ? AND status IN ('pending', 'approved') RETURNING status",
            ),
            DeviceAction::Revoke => sqlx::query_scalar(
                "UPDATE devices SET status = 'revoked', updated_at = ? \
                 WHERE id = ? AND status <> 'revoked' RETURNING status",
            ),
        };
        let status: Option<String> = query
            .bind(now)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let status = status.map(|s| DeviceStatus::parse(&s));
        let event = match (action, status) {
            (DeviceAction::Disable | DeviceAction::Revoke, Some(_)) => Some(
                Self::append_event(
                    &mut tx,
                    EventBody::DeviceDisabled {
                        device_id: id.into(),
                        revoked: action == DeviceAction::Revoke,
                    },
                )
                .await?,
            ),
            _ => None,
        };
        tx.commit().await.map_err(db)?;
        Ok((status, event))
    }

    // Certificates.

    /// Records an issued certificate.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_certificate(
        &self,
        serial: &str,
        kind: &str,
        subject_id: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        not_before: i64,
        not_after: i64,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO certificates (serial, kind, subject_id, user_id, session_id, not_before, not_after) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(serial)
        .bind(kind)
        .bind(subject_id)
        .bind(user_id)
        .bind(session_id)
        .bind(not_before)
        .bind(not_after)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// For each device (and user) and each node, its newest certificate
    /// that is neither expired nor revoked.
    pub async fn current_certificates(&self) -> Result<Vec<CurrentCertificate>, Error> {
        let rows: Vec<(String, String, Option<String>, i64)> = sqlx::query_as(
            "SELECT kind, subject_id, user_id, MAX(not_after) FROM certificates \
             WHERE revoked_at IS NULL AND not_after > ? \
             GROUP BY kind, subject_id, user_id ORDER BY subject_id",
        )
        .bind(clock::now_secs())
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(
                |(kind, subject_id, user_id, not_after)| CurrentCertificate {
                    kind,
                    subject_id,
                    user_id,
                    not_after,
                },
            )
            .collect())
    }

    /// When each node last acknowledged an event, Unix milliseconds.
    pub async fn node_last_acks(&self) -> Result<Vec<(String, i64)>, Error> {
        sqlx::query_as("SELECT node_id, MAX(received_at_ms) FROM event_acks GROUP BY node_id")
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }

    /// Whether a certificate has been revoked.
    pub async fn certificate_revoked(&self, serial: &str) -> Result<bool, Error> {
        let revoked: Option<Option<i64>> =
            sqlx::query_scalar("SELECT revoked_at FROM certificates WHERE serial = ?")
                .bind(serial)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        // An unknown serial was not issued by this control plane.
        Ok(revoked.is_none_or(|r| r.is_some()))
    }

    /// Revokes a certificate, committing a `certificate_revoked` event with
    /// it.
    pub async fn revoke_certificate(&self, serial: &str) -> Result<Option<Event>, Error> {
        let mut tx = self.begin().await?;
        let not_after: Option<i64> = sqlx::query_scalar(
            "UPDATE certificates SET revoked_at = ? WHERE serial = ? AND revoked_at IS NULL RETURNING not_after",
        )
        .bind(clock::now_secs())
        .bind(serial)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let event = match not_after {
            Some(not_after) => Some(
                Self::append_event(
                    &mut tx,
                    EventBody::CertificateRevoked {
                        serial: serial.into(),
                        not_after,
                    },
                )
                .await?,
            ),
            None => None,
        };
        tx.commit().await.map_err(db)?;
        Ok(event)
    }

    // Nodes and join tokens.

    /// Stores a join token's hash.
    /// Stores a join token, by the hash of its secret, with the names the
    /// node it admits will have.
    pub async fn insert_join_token(
        &self,
        token_hash: &str,
        token: &JoinToken,
        name: &str,
        dns_names: &[String],
    ) -> Result<(), Error> {
        let dns = serde_json::to_string(dns_names).map_err(|e| Error::Internal(e.to_string()))?;
        let expires_at =
            i64::try_from(token.exp).map_err(|_| Error::Internal("token expiry".into()))?;
        sqlx::query("INSERT INTO join_tokens (token_hash, token_id, role, connector_group, name, dns_names_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(token_hash)
            .bind(&token.id)
            .bind(&token.role)
            .bind(&token.group)
            .bind(name)
            .bind(dns)
            .bind(clock::now_secs())
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    /// The DNS names an unused, unexpired join token was minted for.
    pub async fn minted_dns_names(&self, token_hash: &str) -> Result<Option<Vec<String>>, Error> {
        let dns: Option<String> = sqlx::query_scalar(
            "SELECT dns_names_json FROM join_tokens \
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(token_hash)
        .bind(clock::now_secs())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        dns.map(|d| serde_json::from_str(&d).map_err(|e| Error::Internal(e.to_string())))
            .transpose()
    }

    /// Spends a join token and creates the node it admits, atomically, so
    /// a token admits exactly one node. The token must be unused, unexpired
    /// and minted with this ID, role and group; the node gets the name and
    /// DNS names it was minted for. Returns `None` for any other token, and
    /// an error if the name is taken.
    pub async fn join(
        &self,
        token_hash: &str,
        token: &JoinToken,
        node: &Node,
    ) -> Result<Option<Node>, Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let minted: Option<(String, String)> = sqlx::query_as(
            "UPDATE join_tokens SET used_at = ?, used_by = ? \
             WHERE token_hash = ? AND token_id = ? AND role = ? AND connector_group IS ? \
             AND used_at IS NULL AND expires_at > ? RETURNING name, dns_names_json",
        )
        .bind(now)
        .bind(&node.id)
        .bind(token_hash)
        .bind(&token.id)
        .bind(&token.role)
        .bind(&token.group)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let Some((name, dns)) = minted else {
            return Ok(None);
        };
        let (role, group) = (token.role.clone(), token.group.clone());
        let node = Node {
            name,
            dns_names: serde_json::from_str(&dns).map_err(|e| Error::Internal(e.to_string()))?,
            ..node.clone()
        };
        let taken: Option<String> = sqlx::query_scalar(
            "SELECT id FROM nodes WHERE role = ? AND name = ? AND revoked_at IS NULL",
        )
        .bind(&role)
        .bind(&node.name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if taken.is_some() {
            return Err(Error::Conflict(format!(
                "a {role} named {} has already joined",
                node.name
            )));
        }
        // A revoked node's name may be reused by a new node; the revoked
        // node keeps its row, so its revocation stays in every bundle.
        let dns =
            serde_json::to_string(&node.dns_names).map_err(|e| Error::Internal(e.to_string()))?;
        sqlx::query(
            "INSERT INTO nodes (id, role, connector_group, name, dns_names_json, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&node.id)
        .bind(&role)
        .bind(&group)
        .bind(&node.name)
        .bind(dns)
        .bind(&node.public_key)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Some(Node {
            role,
            group,
            created_at: now,
            ..node.clone()
        }))
    }

    fn node_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Node, Error> {
        let dns: String = row.try_get("dns_names_json").map_err(db)?;
        Ok(Node {
            id: row.try_get("id").map_err(db)?,
            role: row.try_get("role").map_err(db)?,
            group: row.try_get("connector_group").map_err(db)?,
            name: row.try_get("name").map_err(db)?,
            dns_names: serde_json::from_str(&dns).unwrap_or_default(),
            public_key: row.try_get("public_key").map_err(db)?,
            created_at: row.try_get("created_at").map_err(db)?,
            revoked_at: row.try_get("revoked_at").map_err(db)?,
        })
    }

    /// A node by ID.
    pub async fn node(&self, id: &str) -> Result<Option<Node>, Error> {
        let row = sqlx::query("SELECT * FROM nodes WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.as_ref().map(Self::node_from_row).transpose()
    }

    /// Every node.
    pub async fn nodes(&self) -> Result<Vec<Node>, Error> {
        Self::read_nodes(&mut *self.pool.acquire().await.map_err(db)?).await
    }

    async fn read_nodes(conn: &mut SqliteConnection) -> Result<Vec<Node>, Error> {
        let rows = sqlx::query("SELECT * FROM nodes ORDER BY role, name, created_at")
            .fetch_all(&mut *conn)
            .await
            .map_err(db)?;
        rows.iter().map(Self::node_from_row).collect()
    }

    /// Revokes a node, committing a `node_revoked` event with it.
    pub async fn revoke_node(&self, id: &str) -> Result<Option<Event>, Error> {
        let mut tx = self.begin().await?;
        let now = clock::now_secs();
        let r = sqlx::query("UPDATE nodes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        // Its certificates are revoked too, so they appear in the revocation
        // state by serial until they expire.
        sqlx::query(
            "UPDATE certificates SET revoked_at = ? WHERE subject_id = ? AND kind = 'node' AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let event = if r.rows_affected() == 1 {
            Some(Self::append_event(&mut tx, EventBody::NodeRevoked { node_id: id.into() }).await?)
        } else {
            None
        };
        tx.commit().await.map_err(db)?;
        Ok(event)
    }

    // Revocation state and bundles.

    /// The full revocation state: disabled users, disabled or revoked
    /// devices, revoked unexpired sessions and certificates, revoked nodes.
    pub async fn revocations(&self) -> Result<Revocations, Error> {
        Self::read_revocations(&mut *self.pool.acquire().await.map_err(db)?).await
    }

    async fn read_revocations(conn: &mut SqliteConnection) -> Result<Revocations, Error> {
        let now = clock::now_secs();
        let users = sqlx::query_scalar("SELECT id FROM users WHERE disabled = TRUE ORDER BY id")
            .fetch_all(&mut *conn)
            .await
            .map_err(db)?;
        let devices = sqlx::query_scalar(
            "SELECT id FROM devices WHERE status IN ('disabled', 'revoked') ORDER BY id",
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        let sessions = sqlx::query_scalar(
            "SELECT id FROM sessions WHERE revoked_at IS NOT NULL AND expires_at > ? ORDER BY id",
        )
        .bind(now)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        let certificates: Vec<(String, i64)> = sqlx::query_as(
            "SELECT serial, not_after FROM certificates WHERE revoked_at IS NOT NULL AND not_after > ? ORDER BY serial",
        )
        .bind(now)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        let nodes =
            sqlx::query_scalar("SELECT id FROM nodes WHERE revoked_at IS NOT NULL ORDER BY id")
                .fetch_all(&mut *conn)
                .await
                .map_err(db)?;
        Ok(Revocations {
            users,
            devices,
            sessions,
            certificates: certificates
                .into_iter()
                .map(|(serial, not_after)| RevokedCertificate { serial, not_after })
                .collect(),
            nodes,
        })
    }

    /// Builds and stores the next bundle in one write transaction: reads
    /// the state, takes the next version, lets `build` sign the bundle, and
    /// commits it with its `bundle_updated` event. Holding the write lock
    /// throughout means no revocation can commit between the state read and
    /// the bundle's event, so a bundle never lacks a revocation whose event
    /// came before it. Keeps the latest few versions.
    pub async fn publish_bundle(
        &self,
        build: impl FnOnce(BundleState, u64) -> Result<StoredBundle, Error>,
    ) -> Result<Event, Error> {
        let mut tx = self.begin().await?;
        let state = BundleState {
            users: Self::read_users(&mut tx).await?,
            devices: Self::read_devices(&mut tx).await?,
            nodes: Self::read_nodes(&mut tx).await?,
            revocations: Self::read_revocations(&mut tx).await?,
        };
        let version = Self::next_counter(&mut tx, "bundle_version").await? as u64;
        let b = build(state, version)?;
        sqlx::query("INSERT INTO bundles (version, digest, connector_jws, relay_jws, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(b.version as i64)
            .bind(&b.digest)
            .bind(&b.connector_jws)
            .bind(&b.relay_jws)
            .bind(clock::now_secs())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let event = Self::append_event(
            &mut tx,
            EventBody::BundleUpdated {
                version: b.version,
                digest: b.digest.clone(),
            },
        )
        .await?;
        sqlx::query("DELETE FROM bundles WHERE version < ?")
            .bind(b.version as i64 - 4)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(event)
    }

    /// The latest signed bundle.
    pub async fn latest_bundle(&self) -> Result<Option<StoredBundle>, Error> {
        let row: Option<(i64, String, String, String)> = sqlx::query_as(
            "SELECT version, digest, connector_jws, relay_jws FROM bundles ORDER BY version DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(
            row.map(|(version, digest, connector_jws, relay_jws)| StoredBundle {
                version: version as u64,
                digest,
                connector_jws,
                relay_jws,
            }),
        )
    }

    /// Closes the pool.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

impl FromStr for DeviceStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" | "approved" | "disabled" | "revoked" => Ok(DeviceStatus::parse(s)),
            other => Err(Error::BadRequest(format!("unknown device status {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pruning_never_leaves_a_gap() {
        let dir = std::env::temp_dir().join(format!(
            "warren-store-{}",
            warren_core::keys::hex(&warren_core::keys::random_bytes::<6>().unwrap())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("warren.db")).await.unwrap();
        for i in 0..4 {
            store
                .emit(EventBody::UserDisabled {
                    user_id: format!("u-{i}"),
                })
                .await
                .unwrap();
        }
        // The clock stepped back between commits: event 2 looks newer than
        // event 3.
        for (seq, at) in [(1, 1_000), (2, 9_000), (3, 2_000), (4, 9_500)] {
            sqlx::query("UPDATE events SET committed_at_ms = ? WHERE seq = ?")
                .bind(at)
                .bind(seq)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        store.prune_events(5_000).await.unwrap();
        let left: Vec<u64> = store
            .events_after(0, 10)
            .await
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect();
        assert_eq!(left, [4]);
        assert_eq!(store.event_bounds().await.unwrap(), (4, 4));
        store.close().await;
        std::fs::remove_dir_all(dir).ok();
    }
}
