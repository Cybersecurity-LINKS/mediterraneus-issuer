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
    pub id: u32
}


// #[derive(Deserialize, PostgresMapper, Serialize, Clone, Debug)]
// #[pg_mapper(table = "holder_request")] 
// pub struct HolderRequest {
//     pub vchash: String,
//     pub did: String,
//     pub request_expiration: String,
//     pub vc: String
// }

// pub fn is_empty_request(request: HolderRequest) -> bool {
//     if request.did.len() > 0 && request.request_expiration.len() > 0 && request.vc.len() > 0 && request.vchash.len() > 0 {
//         return false;
//     }
//     return true;
// }