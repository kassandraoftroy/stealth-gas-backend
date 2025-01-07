CREATE TABLE Events (
    removed BOOLEAN NOT NULL,
    event_topic TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    event_state TEXT NOT NULL,
    event_data JSONB NOT NULL,
    match_id TEXT NOT NULL DEFAULT '',
    block_number BIGINT NOT NULL,
    block_timestamp BIGINT NOT NULL,
    transaction_hash TEXT NOT NULL,
    transaction_index INT NOT NULL,
    log_index INT NOT NULL,
    fulfill_tx_hash TEXT NOT NULL DEFAULT '',
    fulfill_tx_nonce INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE Events ADD CONSTRAINT events_pkey PRIMARY KEY (transaction_hash, log_index);

CREATE TABLE Tickets (
    id SERIAL PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE,
    sig TEXT NOT NULL,
    spend_id INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Spends (
    id SERIAL PRIMARY KEY,
    spend_state TEXT NOT NULL,
    spend_data JSONB NOT NULL,
    tx_hash TEXT NOT NULL DEFAULT '',
    tx_nonce INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
