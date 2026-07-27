-- Ciphertext-only relay queue and delivery state.
-- 'envelope' is an opaque JSON blob of the client-sealed envelope
-- (version, ephemeral public key, nonce, ciphertext, signature). The server
-- cannot decrypt it.

CREATE TABLE encrypted_message_queue (
    message_id   UUID PRIMARY KEY,           -- client-generated, idempotency key
    sender_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id     UUID,
    envelope     JSONB NOT NULL,
    sent_at      TIMESTAMPTZ NOT NULL,
    queued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    acked        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_emq_recipient_pending
    ON encrypted_message_queue(recipient_id, queued_at)
    WHERE NOT acked;

-- Delivery receipts for senders (so senders learn 'delivered' even if they
-- were offline when the recipient acked).
CREATE TABLE message_status (
    message_id UUID PRIMARY KEY,
    sender_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state      TEXT NOT NULL CHECK (state IN ('sent_to_relay', 'delivered', 'read')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- TRUE once the sender has been notified of the latest state.
    notified   BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_message_status_sender_pending
    ON message_status(sender_id)
    WHERE NOT notified;
