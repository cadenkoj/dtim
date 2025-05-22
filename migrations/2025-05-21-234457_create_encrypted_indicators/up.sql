CREATE TABLE encrypted_indicators (
    id CHAR(64) PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    mac BYTEA NOT NULL,
    tlp_level TEXT NOT NULL
);
