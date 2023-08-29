use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ReqVCInitDTO {
    pub did: String
}

#[derive(Deserialize, Serialize)]
pub struct ReqVCRevocation {
    pub vc_id: i32
}



