-- HexShield AI: administrator MFA support
ALTER TABLE investigators
    ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS mfa_secret TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_investigators_mfa_enabled
    ON investigators (mfa_enabled);
