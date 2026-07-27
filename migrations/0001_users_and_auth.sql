-- Users, devices, sessions, and public identity key material.
-- The backend NEVER stores private keys or plaintext messages.

CREATE TABLE users (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Immutable shareable public ID, e.g. 'yp_1a2b3c4d5e6f7a8b'. Not a secret.
    public_id    TEXT NOT NULL UNIQUE,
    -- Normalized (lowercase) unique username.
    username     TEXT NOT NULL UNIQUE,
    -- Argon2id PHC string. Never a plaintext or reversibly encrypted password.
    password_hash TEXT NOT NULL,
    -- Public identity material only (base64). Private halves never leave clients.
    sign_pub     TEXT NOT NULL,
    dh_pub       TEXT NOT NULL,
    dh_pub_sig   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Single device per user in the MVP; table exists for future multi-device.
CREATE TABLE devices (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL DEFAULT 'default',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Opaque bearer tokens, stored only as BLAKE3 hashes.
CREATE TABLE sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE contacts (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, contact_id),
    CHECK (user_id <> contact_id)
);
