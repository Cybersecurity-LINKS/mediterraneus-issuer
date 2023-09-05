CREATE TABLE identity(
    did text PRIMARY KEY,
    privkey bytea NOT NULL
);

CREATE TABLE verifiable_credential(
    id SERIAL PRIMARY KEY
);

CREATE TABLE challenge (
    did text PRIMARY KEY,
    challenge text NOT NULL,
    expiration text NOT NULL
)
