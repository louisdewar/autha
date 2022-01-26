table! {
    authentication_methods (user_id, method) {
        user_id -> Int4,
        method -> Text,
    }
}

table! {
    password_auth (user_id) {
        user_id -> Int4,
        hashed_password -> Text,
        salt -> Text,
    }
}

table! {
    sso (issuer, subject_identifier) {
        user_id -> Nullable<Int4>,
        issuer -> Text,
        subject_identifier -> Text,
    }
}

table! {
    users (id) {
        id -> Int4,
        username -> Text,
        email -> Nullable<Text>,
        email_verified -> Bool,
        extra -> Jsonb,
    }
}

joinable!(authentication_methods -> users (user_id));
joinable!(password_auth -> users (user_id));
joinable!(sso -> users (user_id));

allow_tables_to_appear_in_same_query!(authentication_methods, password_auth, sso, users,);
