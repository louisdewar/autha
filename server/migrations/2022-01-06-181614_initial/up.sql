CREATE TABLE users(
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    extra JSONB DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamptz NOT NULL default now()
);

CREATE TABLE password_auth(
    user_id INT references users(id) PRIMARY KEY,
    hashed_password TEXT NOT NULL,
    salt TEXT NOT NULL
);

CREATE TABLE sso(
    user_id INT references users(id),
    issuer TEXT NOT NULL,
    subject_identifier TEXT NOT NULL,
    PRIMARY KEY(issuer, subject_identifier)
);

CREATE TABLE authentication_methods(
    user_id INT references users(id) NOT NULL,
    method TEXT NOT NULL,
    PRIMARY KEY(user_id, method)
);