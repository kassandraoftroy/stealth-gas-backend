CREATE TABLE Events (
    removed BOOLEAN NOT NULL,
    event_topic TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    event_state TEXT NOT NULL,
    block_number BIGINT NOT NULL,
    block_timestamp BIGINT NOT NULL,
    transaction_hash TEXT NOT NULL,
    transaction_index INT NOT NULL,
    log_index INT NOT NULL,
    event_data JSONB NOT NULL,
    fulfillment_event_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE Events ADD CONSTRAINT events_pkey PRIMARY KEY (transaction_hash, log_index);

