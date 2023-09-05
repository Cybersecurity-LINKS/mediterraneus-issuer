use serde::{Deserialize, Serialize};
use tokio_pg_mapper_derive::PostgresMapper;

#[derive(Deserialize, PostgresMapper, Serialize, Clone)]
#[pg_mapper(table = "identity")] 
pub struct Identity {
    pub did: String,
    pub privkey: Vec<u8>,
}

#[derive(Deserialize, PostgresMapper, Serialize, Clone, Debug)]
#[pg_mapper(table = "verifiable_credential")] 
pub struct VerifiableCredential {
    pub id: i32
}

#[derive(Deserialize, PostgresMapper, Serialize, Clone, Debug)]
#[pg_mapper(table = "challenge")] 
pub struct ChallengeRequest {
    pub did: String,
    pub challenge: String,
    pub expiration: String
}