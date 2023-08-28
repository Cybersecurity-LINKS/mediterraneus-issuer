use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ReqVCInitDTO {
    pub did: String
}


#[derive(Deserialize, Serialize, Debug)]
pub struct ReqVCProofsDTO {
    pub vc_hash: String,
    pub ssi_signature: String,
    pub pseudo_sign: String
}

#[derive(Deserialize, Serialize)]
pub struct AbiDTO {
    pub message: String,
    pub result: String,
    pub status: String
}

#[derive(Deserialize, Serialize)]
pub struct VcHashResponse {
    pub vchash: String,
}

#[derive(Deserialize, Serialize)]
pub struct VcIssuingResponse {
    pub message: String,
    pub vc: String,
}




