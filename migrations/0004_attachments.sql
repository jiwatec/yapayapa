-- Encrypted attachment blobs. The server stores ciphertext only; the
-- one-time attachment key travels exclusively inside sealed chat envelopes.

CREATE TABLE attachments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    size       BIGINT NOT NULL,
    blob       BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Which users may download which encrypted blob. Grants are set by the
-- uploader (message recipients / group members at upload time).
CREATE TABLE attachment_grants (
    attachment_id UUID NOT NULL REFERENCES attachments(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (attachment_id, user_id)
);
