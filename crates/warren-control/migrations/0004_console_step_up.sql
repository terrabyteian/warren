-- warren control plane: console step-up.
--
-- When an admin signed in through an IdP that reported no MFA, or no
-- auth_time, last proved a second factor with the authenticator code of
-- their built-in account (the one whose email is their verified email).
-- Changes count it as a multi-factor authentication at that time.
ALTER TABLE console_sessions ADD COLUMN step_up_at BIGINT;
