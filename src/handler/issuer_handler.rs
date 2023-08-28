use actix_web::{web, HttpResponse, Responder, post, get};
use deadpool_postgres::Pool;
use ethers::utils::hex::FromHex;
use identity_iota::{crypto::Ed25519, core::ToJson};
use iota_client::crypto::signatures::ed25519::{PublicKey, Signature};
use crate::{dtos::identity_dtos::{ReqVCInitDTO, ReqVCProofsDTO, VcHashResponse, VcIssuingResponse}, 
            services::{issuer_identity::resolve_did, issuer_vc::create_vc}, 
            IssuerState, utils::extract_pub_key_from_doc, db::operations::insert_vc};

/// Store did with expiration so that the client should resend the signatures in a short time.
/// Expiration allows to maintain a light db.
/// It is expected that the holder calls the second API (signatures) within a minute.
/// @param req --> holder's did (as string)
/// @param res --> 200, 400, 500
// #[post("")]
// async fn req_vcinit(
//     req_body: web::Json<ReqVCInitDTO>, 
//     pool: web::Data<Pool>,
//     issuer_state: web::Data<IssuerState>) -> impl Responder {
//     let resp = match check_and_clean_holder_requests(pool.get_ref().to_owned(), req_body.did.to_string()).await {
//         true => {
//             // create VC, hash, 
//             // if no error store holder request (did, request expiration, VC)
//             let holder_request = create_hash_and_store_vc(
//                 pool.get_ref().to_owned(),
//                 req_body.did.clone(), 
//                 issuer_state.get_ref().to_owned())
//             .await.unwrap();

//             // send back the H(VC)    
//             HttpResponse::Ok().body(serde_json::to_string::<VcHashResponse>(&VcHashResponse {vchash: holder_request.vchash}).unwrap())
//         },
//         false => {
//             HttpResponse::BadRequest().body("Holder has still a pending reauest".to_string())
//         },
//     };
//     resp
// }


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
                        Ok(cred_json) => HttpResponse::Ok().body(cred_json),
                        Err(_) => HttpResponse::InternalServerError().body("Error during the creation of the Verifiable Credential".to_string())
                    }
                },
                Err(_) =>  HttpResponse::InternalServerError().body("Error during the creation of the Verifiable Credential".to_string())
            } 
        },
        Err(e) =>  HttpResponse::InternalServerError().body("Error during the creation of the Verifiable Credential".to_string())
    };

    
    // .map_or_else(|e| HttpResponse::BadRequest().body("Holder has still a pending reauest".to_string()),
    //  |v| create_vc(
    //         req_body.did.clone(), 
    //         v.id, 
    //         issuer_state.issuer_identity.clone(), 
    //         issuer_state.issuer_account.client().clone().to_owned()
    //         ).await
    //         .map_or_else(|e|  HttpResponse::BadRequest().body("Holder has still a pending reauest".to_string()),
    //             |vc| HttpResponse::Ok().body(vc.to_json())
    //         )
    // );

    result

    // let vc = create_vc(
    //     req_body.did.clone(), 
    //             vc_id, 
    //             issuer_state.issuer_identity.clone(), 
    //     issuer_state.issuer_account.client().clone().to_owned()
    //         ).await.unwrap();

    //         // // create VC, hash, 
    //         // // if no error store holder request (did, request expiration, VC)
    //         // let holder_request = create_hash_and_store_vc(
    //         //     pool.get_ref().to_owned(),
    //         //     req_body.did.clone(), 
    //         //     issuer_state.get_ref().to_owned())
    //         // .await.unwrap();

    //         // send back the H(VC)    
    //         HttpResponse::Ok().body(serde_json::to_string::<VcHashResponse>(&VcHashResponse {vchash: holder_request.vchash}).unwrap())
    // resp
}

// /// Verifies the SSI signature and fills up the IDSC (also with the pseudo signature).
// /// @param req --> vc_hash, ssi_signature, psuedo_signature
// /// @param res --> 200, 400, 500
// #[post("2")]
// async fn req_vc_proofs(
//     req_body: web::Json<ReqVCProofsDTO>, 
//     pool: web::Data<Pool>,
//     issuer_state: web::Data<IssuerState>
// ) -> impl Responder {
//     // read the request from the DB 
//     let holder_request = get_holder_request_by_vc_hash(&pool.get().await.unwrap(), req_body.vc_hash.clone()).await.unwrap();
//     // first check request is valid (anti replay, the hash serves as nonce)
//     let resp = match is_empty_request(holder_request.clone()) {
//         false => { // request is not empty ==>  valid
//             // resolve DID Doc and extract public key
//             let holder_did_document = resolve_did(issuer_state.issuer_account.client().clone(), holder_request.did.clone()).await.unwrap();
//             let holder_pub_key = extract_pub_key_from_doc(holder_did_document.clone());
            

//             let key = PublicKey::try_from_bytes(<[u8; Ed25519::PUBLIC_KEY_LENGTH]>::try_from(holder_pub_key).unwrap()).unwrap();
//             match key.verify(
//                 &Signature::from_bytes(<[u8; Ed25519::SIGNATURE_LENGTH]>::try_from(Vec::from_hex(req_body.ssi_signature.clone()).unwrap()).unwrap()), 
//                 holder_request.vchash.as_bytes()
//             ) {
//                 true => {
//                     register_new_vc(
//                         &pool,
//                         issuer_state.get_ref().to_owned(), 
//                         holder_request.vc.clone(), 
//                         holder_request.vchash, 
//                         req_body.pseudo_sign.clone(), 
//                         holder_request.did
//                     ).await.unwrap();

//                     HttpResponse::Ok().body(serde_json::to_string::<VcIssuingResponse>(
//                         &VcIssuingResponse { 
//                             message: "VC issued. In order to activate it contact the IDentity SC.".to_string(), 
//                             vc: holder_request.vc
//                         }
//                     ).unwrap())
//                 },
//                 false => {
//                     HttpResponse::BadRequest()
//                     .body(serde_json::to_string(&VcHashResponse {vchash: "Invalid ssi_signature".to_string()}).unwrap())
//                 },
//             }
//         },
//         true => { // request is not valid
//             HttpResponse::BadRequest()
//             .body(serde_json::to_string(&VcHashResponse {vchash: "Holder request does not exist".to_string()})
//             .unwrap())
//         },
//     };
//     resp
// }


// TODO: revoke API (must be admin api to let only issuer revoke a VC)

#[get("/{sentence}")]
async fn echo_api(path: web::Path<String>) -> impl Responder {
    HttpResponse::Ok().body(path.into_inner())
}

pub fn scoped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
         // prefixes all resources and routes attached to it...
        web::scope("/identity")
            .service(create_verifiable_credential)
            // .service(req_vc_proofs)
            .service(echo_api)
    );
}