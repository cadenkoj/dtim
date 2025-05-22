// @generated automatically by Diesel CLI.

diesel::table! {
    encrypted_indicators (id) {
        #[max_length = 64]
        id -> Bpchar,
        ciphertext -> Bytea,
        nonce -> Bytea,
        mac -> Bytea,
        tlp_level -> Text,
    }
}
