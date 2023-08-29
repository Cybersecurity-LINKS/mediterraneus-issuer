use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ReqVCInitDTO {
    pub did: String
}



