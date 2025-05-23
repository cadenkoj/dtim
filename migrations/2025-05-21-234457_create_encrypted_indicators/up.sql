CREATE TABLE encrypted_indicators (
    id CHAR(64) PRIMARY KEY,
    data BYTEA NOT NULL,
    tlp_level TEXT NOT NULL
);
