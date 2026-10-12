-- warren control plane: built-in accounts and warren's own groups.
--
-- Same rules as 0001: TEXT, BIGINT and BOOLEAN columns only, times as Unix
-- seconds, so the set serves SQLite now and PostgreSQL later.

-- A deleted built-in account keeps its row, disabled, so its revocation
-- stays in every bundle; its username is freed (its subject is rewritten)
-- and it is hidden from listings.
ALTER TABLE users ADD COLUMN deleted_at BIGINT;

-- The credentials of built-in accounts (users.issuer = 'local',
-- users.subject = the username). The password is a PBKDF2-HMAC-SHA256
-- hash; the authenticator secret is sealed under the key-encryption key.
-- managed_by is 'api' (created through the admin API or the bootstrap
-- secret) or 'config' (a LocalUser in the policy directory).
CREATE TABLE local_accounts (
    user_id         TEXT PRIMARY KEY REFERENCES users (id),
    display_name    TEXT NOT NULL,
    password_hash   TEXT,
    totp_secret     TEXT,
    totp_last_step  BIGINT NOT NULL,
    failed_attempts BIGINT NOT NULL,
    locked_until    BIGINT NOT NULL,
    managed_by      TEXT NOT NULL,
    created_at      BIGINT NOT NULL,
    updated_at      BIGINT NOT NULL
);

-- Single-use recovery codes, by digest; a used code is deleted.
CREATE TABLE recovery_codes (
    user_id   TEXT NOT NULL REFERENCES users (id),
    code_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

-- One-time setup links for setting a password, by the hash of their token.
CREATE TABLE setup_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id),
    expires_at BIGINT NOT NULL
);
CREATE INDEX setup_tokens_user ON setup_tokens (user_id);

-- Membership in warren's own groups (policy names them local:<group>), for
-- any user: built-in accounts and IdP users alike. invited_email records
-- the invite a membership came from.
CREATE TABLE group_members (
    group_name    TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users (id),
    managed_by    TEXT NOT NULL,
    invited_email TEXT,
    created_at    BIGINT NOT NULL,
    PRIMARY KEY (group_name, user_id)
);
CREATE INDEX group_members_user ON group_members (user_id);

-- Invites: membership waiting for an IdP user with this verified email to
-- sign in, when it binds to that user's issuer and subject.
CREATE TABLE group_invites (
    group_name TEXT NOT NULL,
    email      TEXT NOT NULL,
    managed_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (group_name, email)
);

-- A sign-in with a built-in account in progress: the browser it is bound
-- to (a hash of a cookie), the account once its password checked out, the
-- step reached, and an authenticator secret being enrolled (sealed).
ALTER TABLE auth_requests ADD COLUMN browser_hash TEXT;
ALTER TABLE auth_requests ADD COLUMN local_user_id TEXT;
ALTER TABLE auth_requests ADD COLUMN local_stage TEXT;
ALTER TABLE auth_requests ADD COLUMN pending_secret TEXT;
