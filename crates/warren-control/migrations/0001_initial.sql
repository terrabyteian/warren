-- warren control plane, initial schema.
--
-- One migration set serves SQLite now and PostgreSQL later, so this file
-- sticks to what both accept: TEXT, BIGINT and BOOLEAN columns, times as
-- Unix seconds or milliseconds computed by the control plane, binary values
-- as base64 text, JSON as text, and sequence numbers drawn from the counters
-- table rather than from an engine-specific autoincrement.

-- Monotonic counters: event sequence numbers, bundle versions, device
-- address indexes.
CREATE TABLE counters (
    name  TEXT PRIMARY KEY,
    value BIGINT NOT NULL
);
INSERT INTO counters (name, value) VALUES ('event_seq', 0);
INSERT INTO counters (name, value) VALUES ('bundle_version', 0);
INSERT INTO counters (name, value) VALUES ('device_address', 0);

-- Deployment-wide settings, such as the trust domain the database belongs to.
CREATE TABLE settings (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- CA and signing keys, sealed under the key-encryption key, with the CA
-- certificates.
CREATE TABLE signing_keys (
    name        TEXT PRIMARY KEY,
    sealed_key  TEXT NOT NULL,
    certificate TEXT,
    created_at  BIGINT NOT NULL
);

CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    issuer       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT NOT NULL,
    groups_json  TEXT NOT NULL,
    disabled     BOOLEAN NOT NULL,
    created_at   BIGINT NOT NULL,
    updated_at   BIGINT NOT NULL,
    last_auth_at BIGINT NOT NULL,
    UNIQUE (issuer, subject)
);

CREATE TABLE devices (
    id            TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL,
    trust_class   BIGINT NOT NULL,
    key_storage   TEXT NOT NULL,
    platform_json TEXT NOT NULL,
    address_index BIGINT NOT NULL UNIQUE,
    tunnel_v4     TEXT NOT NULL,
    tunnel_v6     TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL
);

CREATE TABLE device_users (
    device_id  TEXT NOT NULL REFERENCES devices (id),
    user_id    TEXT NOT NULL REFERENCES users (id),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (device_id, user_id)
);

-- Sign-ins in flight: from the client's authorize request to the IdP's
-- callback. Keyed by a hash of the state sent to the IdP.
CREATE TABLE auth_requests (
    state_hash          TEXT PRIMARY KEY,
    client_redirect_uri TEXT NOT NULL,
    client_state        TEXT NOT NULL,
    client_challenge    TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    idp_verifier        TEXT NOT NULL,
    expires_at          BIGINT NOT NULL
);

-- One-time codes handed to the client after a successful IdP sign-in.
CREATE TABLE auth_codes (
    code_hash           TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users (id),
    client_challenge    TEXT NOT NULL,
    client_redirect_uri TEXT NOT NULL,
    auth_time           BIGINT NOT NULL,
    mfa                 BOOLEAN NOT NULL,
    expires_at          BIGINT NOT NULL
);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    TEXT NOT NULL REFERENCES users (id),
    public_key TEXT NOT NULL,
    auth_time  BIGINT NOT NULL,
    mfa        BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Every certificate issued, so any one can be revoked by serial.
CREATE TABLE certificates (
    serial     TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    user_id    TEXT,
    session_id TEXT,
    not_before BIGINT NOT NULL,
    not_after  BIGINT NOT NULL,
    revoked_at BIGINT
);
CREATE INDEX certificates_session ON certificates (session_id);

CREATE TABLE nodes (
    id              TEXT PRIMARY KEY,
    role            TEXT NOT NULL,
    connector_group TEXT,
    name            TEXT NOT NULL,
    dns_names_json  TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    created_at      BIGINT NOT NULL,
    revoked_at      BIGINT,
    UNIQUE (role, name)
);

CREATE TABLE join_tokens (
    token_hash      TEXT PRIMARY KEY,
    role            TEXT NOT NULL,
    connector_group TEXT,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    used_at         BIGINT,
    used_by         TEXT
);

-- The revocation push channel's log.
CREATE TABLE events (
    seq             BIGINT PRIMARY KEY,
    kind            TEXT NOT NULL,
    payload         TEXT NOT NULL,
    committed_at_ms BIGINT NOT NULL
);

CREATE TABLE event_acks (
    seq             BIGINT NOT NULL,
    node_id         TEXT NOT NULL,
    applied_at_ms   BIGINT NOT NULL,
    received_at_ms  BIGINT NOT NULL,
    connections_cut BIGINT NOT NULL,
    PRIMARY KEY (seq, node_id)
);

-- Signed policy bundles, newest last.
CREATE TABLE bundles (
    version       BIGINT PRIMARY KEY,
    digest        TEXT NOT NULL,
    connector_jws TEXT NOT NULL,
    relay_jws     TEXT NOT NULL,
    created_at    BIGINT NOT NULL
);
