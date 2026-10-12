-- warren control plane: web console sign-ins.
--
-- A console session is a browser's sign-in to the console, separate from
-- the device-bound sessions of the warren app. Only a hash of the cookie's
-- token is stored.
CREATE TABLE console_sessions (
    id         TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    TEXT NOT NULL REFERENCES users (id),
    auth_time  BIGINT NOT NULL,
    mfa        BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    ended_at   BIGINT
);
CREATE INDEX console_sessions_user ON console_sessions (user_id);
