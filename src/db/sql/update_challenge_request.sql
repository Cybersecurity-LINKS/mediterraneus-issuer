UPDATE challenge SET (challenge, expiration) = ($2, $3)  WHERE did = $1
RETURNING $table_fields;