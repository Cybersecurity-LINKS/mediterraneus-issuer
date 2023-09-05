INSERT INTO challenge(did, challenge, expiration)
VALUES ($1, $2, $3)
RETURNING $table_fields;