use identity_iota::core::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ReqVCorChallenge {
    pub did: String
}


#[derive(Deserialize, Serialize)]
pub struct ReqVCRevocation {
    pub vc_id: i32
}


#[derive(Deserialize, Serialize)]
pub struct ChallengeDTO {
    pub challenge: String,
    pub expiration: String
}