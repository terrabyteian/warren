//! The control plane's state, behind the one SQL layer (sqlx).
//!
//! SQLite is embedded today; PostgreSQL follows for high availability with
//! the same queries and the same migration set, so the SQL here keeps to
//! what both engines accept (see `migrations/0001_initial.sql`). Changes
//! that reduce access commit together with the revocation event that
//! announces them, so an event exists exactly when the change does.

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

use crate::Error;

type Tx<'a> = Transaction<'a, Sqlite>;

fn db(e: sqlx::Error) -> Error {
    Error::Store(e.to_string())
}

/// A new random ID with a type prefix, for example `u-3f9c0d2a71b4e8a6c5d1`.
pub fn new_id(prefix: &str) -> Result<String, Error> {
    let bytes: [u8; 10] = random_bytes().map_err(|e| Error::Internal(e.to_string()))?;
    Ok(format!("{prefix}-{}", hex(&bytes)))
}

/// A user, as the IdP last described them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The warren user ID.
    pub id: String,
    /// The IdP's issuer.
    pub issuer: String,
    /// The IdP's subject identifier.
    pub subject: String,
    /// The verified email, or empty.
    pub email: String,
    /// IdP groups.
    pub groups: Vec<String>,
    /// Disabled users can do nothing.
    pub disabled: bool,
    /// When the user last signed in, Unix seconds.
    pub last_auth_at: i64,
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

/// A sign-in waiting for the IdP's callback.
#[derive(Debug, Clone)]
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
        })
    }

    /// Records a sign-in: creates the user or updates their email and
    /// groups. Returns the user and whether anything policy depends on
    /// changed. A sign-in that removes groups also emits `bundle_updated`
    /// later, through the publisher.
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
        tx.commit().await.map_err(db)?;
        let user = self
            .user(&id)
            .await?
            .ok_or_else(|| Error::Internal("user vanished".into()))?;
        Ok((user, changed))
    }

    /// A user by ID.
    pub async fn user(&self, id: &str) -> Result<Option<User>, Error> {
        let row = sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.as_ref().map(Self::user_from_row).transpose()
    }

    /// A user by ID, else by email, else by IdP subject. An email or subject
    /// shared by several users matches none of them.
    pub async fn find_user(&self, key: &str) -> Result<Option<User>, Error> {
        if let Some(user) = self.user(key).await? {
            return Ok(Some(user));
        }
        let by_email = sqlx::query("SELECT * FROM users WHERE email = ? AND email <> '' LIMIT 2")
            .bind(key.to_ascii_lowercase())
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        if let [row] = by_email.as_slice() {
            return Self::user_from_row(row).map(Some);
        }
        let by_subject = sqlx::query("SELECT * FROM users WHERE subject = ? LIMIT 2")
            .bind(key)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        match by_subject.as_slice() {
            [row] => Self::user_from_row(row).map(Some),
            _ => Ok(None),
        }
    }

    /// Deletes sign-ins and one-time codes that expired unused.
    pub async fn prune_auth(&self) -> Result<(), Error> {
        let now = clock::now_secs();
        for sql in [
            "DELETE FROM auth_requests WHERE expires_at <= ?",
            "DELETE FROM auth_codes WHERE expires_at <= ?",
            "DELETE FROM console_sessions WHERE expires_at <= ?",
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
        rows.iter().map(Self::user_from_row).collect()
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

    // Sign-in.

    /// Stores a sign-in in flight.
    pub async fn insert_auth_request(
        &self,
        state_hash: &str,
        r: &AuthRequest,
        expires_at: i64,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO auth_requests (state_hash, client_redirect_uri, client_state, client_challenge, nonce, idp_verifier, created_at, login, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(state_hash)
        .bind(&r.client_redirect_uri)
        .bind(&r.client_state)
        .bind(&r.client_challenge)
        .bind(&r.nonce)
        .bind(&r.idp_verifier)
        .bind(r.created_at)
        .bind(r.login)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Takes (and deletes) an unexpired sign-in in flight: each one is
    /// usable once.
    pub async fn take_auth_request(&self, state_hash: &str) -> Result<Option<AuthRequest>, Error> {
        let row: Option<(String, String, String, String, String, i64, bool)> = sqlx::query_as(
            "DELETE FROM auth_requests WHERE state_hash = ? AND expires_at > ? \
             RETURNING client_redirect_uri, client_state, client_challenge, nonce, idp_verifier, created_at, login",
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
        Ok(row.map(
            |(
                client_redirect_uri,
                client_state,
                client_challenge,
                nonce,
                idp_verifier,
                created_at,
                login,
            )| AuthRequest {
                client_redirect_uri,
                client_state,
                client_challenge,
                nonce,
                idp_verifier,
                created_at,
                login,
            },
        ))
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
