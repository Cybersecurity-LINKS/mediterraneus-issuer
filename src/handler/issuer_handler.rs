use actix_web::{web, HttpResponse, Responder, post, get, http::header::ContentType};
use deadpool_postgres::Pool;
use ethers::utils::hex::FromHex;
use identity_iota::{crypto::Ed25519, core::ToJson};
use iota_client::crypto::signatures::ed25519::{PublicKey, Signature};
use crate::{services::{issuer_identity::resolve_did, issuer_vc::create_vc}, 
            IssuerState, utils::extract_pub_key_from_doc, db::operations::insert_vc, dtos::identity_dtos::ReqVCInitDTO};

/// Store did with expiration so that the client should resend the signatures in a short time.
/// Expiration allows to maintain a light db.
/// It is expected that the holder calls the second API (signatures) within a minute.
/// @param req --> holder's did (as string)
/// @param res --> 200, 400, 500

#[post("")]
async fn create_verifiable_credential(
    req_body: web::Json<ReqVCInitDTO>, 
    pool: web::Data<Pool>,
    issuer_state: web::Data<IssuerState>) -> impl Responder {


    let vc_db = insert_vc(&pool.get().await.unwrap()).await;

    let result = match vc_db {
        Ok(vc) => {
            let verifiable_credential =  create_vc(
                        req_body.did.clone(), 
                        vc.id, 
                        issuer_state.issuer_identity.clone(), 
                        issuer_state.issuer_account.client().clone().to_owned()
                        ).await;
            match verifiable_credential {
                Ok(credential) => {
                    let credential_json = credential.to_json();
                    match credential_json {
                        Ok(cred_json) => HttpResponse::Ok().insert_header(ContentType::json()).body(cred_json),
                        Err(_) => HttpResponse::InternalServerError().body("Error during the creation of the Verifiable Credential".to_string())
                    }
                },
                Err(_) =>  HttpResponse::InternalServerError().body("Error during the creation of the Verifiable Credential".to_string())
            } 
        },
        Err(e) =>  HttpResponse::InternalServerError().body("Error during the creation of the Verifiable Credential".to_string())
    };

    result

}


// TODO: revoke API (must be admin api to let only issuer revoke a VC)
// TODO: verify if credential revoked


#[get("/{sentence}")]
async fn echo_api(path: web::Path<String>) -> impl Responder {
    HttpResponse::Ok().body(path.into_inner())
}

pub fn scoped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
         // prefixes all resources and routes attached to it...
        web::scope("/identity")
            .service(create_verifiable_credential)
            .service(echo_api)
    );
}