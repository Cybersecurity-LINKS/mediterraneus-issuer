use actix_web::{web, HttpResponse, Responder, post, get, put, http::header::ContentType};
use deadpool_postgres::Pool;
use ethers::utils::hex::FromHex;
use identity_iota::{crypto::Ed25519, core::ToJson, credential::Credential};
use iota_client::crypto::signatures::ed25519::{PublicKey, Signature};
use crate::{services::{issuer_identity::resolve_did, issuer_vc::{create_vc, revoke_vc, is_revoked, generate_challenge}}, 
            IssuerState, utils::extract_pub_key_from_doc, db::operations::insert_vc, dtos::identity_dtos::{ReqVCorChallenge, ReqVCRevocation, ChallengeDTO}};
use crate::db::{models::Identity, operations::check_vc_is_present};

/// Store did with expiration so that the client should resend the signatures in a short time.
/// Expiration allows to maintain a light db.
/// It is expected that the holder calls the second API (signatures) within a minute.
/// @param req --> holder's did (as string)
/// @param res --> 200, 400, 500

#[post("")]
async fn request_verifiable_credential(
    req_body: web::Json<ReqVCorChallenge>, 
    pool: web::Data<Pool>,
    issuer_state: web::Data<IssuerState>) -> impl Responder {


    let vc_db = insert_vc(&pool.get().await.unwrap()).await;

    let result = match vc_db {
        Ok(vc) => {
            let verifiable_credential =  create_vc(
                        req_body.did.clone(), 
                        vc.id, 
                        &issuer_state.issuer_identity, 
                        issuer_state.issuer_account.client()
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
#[post("/revoke")]
async fn revoke_verifiable_credential(
    vc_id: web::Json<ReqVCRevocation>,
    pool: web::Data<Pool>,
    issuer_state: web::Data<IssuerState>) -> impl Responder {

    let check = check_vc_is_present(&pool.get().await.unwrap(), vc_id.vc_id).await;

    let result = match check {
        Ok(_) => {
            let sm = issuer_state.secret_manager.read().await;
            let revoked = revoke_vc(vc_id.vc_id, &issuer_state.issuer_identity, issuer_state.issuer_account.client(), &sm).await;
            match revoked {
                Ok(_) => HttpResponse::Ok().body("Credential Revoked!"),
                Err(e) => HttpResponse::InternalServerError().body(e.to_string())
            }
        },
        Err(_) => HttpResponse::BadRequest().body("Not a valid VC id".to_string())
    };

    result

}


#[post("/check")]
async fn check_credential_revocation(
    vc: web::Json<Credential>,
    issuer_state: web::Data<IssuerState>) -> impl Responder {

    let check_result = is_revoked(vc.0, &issuer_state.issuer_identity, issuer_state.issuer_account.client()).await;

    let ret = match check_result {
        Ok(value) => {
            if value {
                return HttpResponse::Ok().body("Credential is Revoked!");
            } else {
                return HttpResponse::Ok().body("Credential is Valid!");
            }
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string())
    };

    ret
}

#[post("/challenge")]
async fn request_challenge(
    req_body: web::Json<ReqVCorChallenge>, 
    pool: web::Data<Pool>,) -> impl Responder {

    let challenge = generate_challenge(pool.get_ref().to_owned(), req_body.did.clone()).await;
    match challenge {
        Ok(challenge) => {
            let response = ChallengeDTO{challenge: challenge.challenge, expiration: challenge.expiration};
            HttpResponse::Ok().insert_header(ContentType::json()).json(response)
        },
        Err(_) => HttpResponse::InternalServerError().body("Failed to get a challenge!")
    }
    
}


#[get("/{sentence}")]
async fn echo_api(path: web::Path<String>) -> impl Responder {
    HttpResponse::Ok().body(path.into_inner())
}


pub fn scoped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
         // prefixes all resources and routes attached to it...
        web::scope("/identity")
            .service(request_verifiable_credential)
            .service(revoke_verifiable_credential)
            .service(check_credential_revocation)
            .service(request_challenge)
            .service(echo_api)
    );
}