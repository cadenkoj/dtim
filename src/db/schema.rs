// @generated automatically by Diesel CLI.

diesel::table! {
    encrypted_indicators (id) {
        #[max_length = 64]
        id -> Bpchar,
        data -> Bytea,
        tlp_level -> Text,
    }
}
