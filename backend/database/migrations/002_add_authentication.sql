-- =============================================================================
-- HexShield AI — Migration 002: Authentication and Security Columns
-- =============================================================================

-- Add authentication columns to investigators table
ALTER TABLE investigators
    ADD COLUMN IF NOT EXISTS password_hash        VARCHAR(255)    NULL,
    ADD COLUMN IF NOT EXISTS is_badge_verified    BOOLEAN         NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS first_login          BOOLEAN         NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS failed_login_count   INTEGER         NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until         TIMESTAMPTZ     NULL,
    ADD COLUMN IF NOT EXISTS last_login_ip        INET            NULL,
    ADD COLUMN IF NOT EXISTS last_login_at        TIMESTAMPTZ     NULL,
    ADD COLUMN IF NOT EXISTS session_token        VARCHAR(255)    NULL;

-- System admins bypass badge verification
-- Badge verified must be TRUE for non-admin investigators to login
COMMENT ON COLUMN investigators.is_badge_verified IS
    'Must be TRUE for investigator to log in. Set manually by SYSTEM_ADMIN after verifying badge with Republic of Kenya records.';

COMMENT ON COLUMN investigators.first_login IS
    'TRUE on account creation. Forces password change on first login.';

COMMENT ON COLUMN investigators.failed_login_count IS
    'Incremented on each failed login attempt. Account locked after 5 failures.';

COMMENT ON COLUMN investigators.locked_until IS
    'Account locked until this timestamp after 5 failed login attempts.';

-- Update schema migrations
INSERT INTO schema_migrations (version, description)
VALUES (
    '1.1.0',
    'Added authentication columns to investigators: password_hash, is_badge_verified, first_login, failed_login_count, locked_until, last_login_ip, session_token.'
)
ON CONFLICT (version) DO NOTHING;