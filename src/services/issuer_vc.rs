use deadpool_postgres::Pool;
use ethers::utils::hex;
use identity_iota::{core::{Timestamp, FromJson, Url, ToJson, Duration}, credential::{Credential, Subject, CredentialBuilder, CredentialValidator, CredentialValidationOptions, FailFast, RevocationBitmap, RevocationBitmapStatus, Status}, crypto::{PrivateKey, ProofOptions}, did::{DIDUrl, DID}, document::Service, prelude::{IotaDocument, IotaIdentityClientExt, IotaClientExt}};
use iota_client::{Client, block::output::{AliasOutput, RentStructure, AliasOutputBuilder}, client, secret::SecretManager};
use iota_wallet::U256;
use serde_json::{json, Value};
use crate::{db::{models::{Identity}}, IssuerState, errors::my_errors::MyError, utils::get_vc_id_from_credential};

use super::{issuer_identity::resolve_did, idsc_wrappers::{get_free_vc_id, register_new_vc_idsc}};

// /// returns @true if the request can continue, @false if the holder has a pending request.
// /// If the holder has an expired request, it gets cleared from the DB and the new one
// /// will be inserted later by the handler (so the function will return true)
// pub async fn check_and_clean_holder_requests(pool: Pool, did: String) -> bool {
//     let holder_request = get_holder_request_by_did(&pool.get().await.unwrap(), did.clone()).await.unwrap();
    
//     if is_empty_request(holder_request.clone()) == false {
//         // request already exists
//         // check that it is not expired, if expired remove from db
//         let holder_request_timestamp = Timestamp::parse(&holder_request.clone().request_expiration).unwrap();
//         if holder_request_timestamp < Timestamp::now_utc() {
//             // request expired --> remove it from DB and let handler continue
//             remove_holder_request_by_did(&pool.get().await.unwrap(), did).await;
//             return true;
//         } else {
//             // request still not expired --> stop handler from continuing
//             return false;
//         }
//     }
//     return true;
// }

pub async fn create_vc(holder_did: String, vc_id: u32, issuer_identity: Identity, client: Client) -> Result<Credential, ()> {

    // Create a credential subject indicating the degree earned by Alice.
    let subject: Subject = Subject::from_json_value(json!({
        "id": holder_did,
        "name": "Alice",
        "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
        },
        "GPA": "4.0",
    })).unwrap();

    let issuer_doc = resolve_did(client, issuer_identity.did.clone()).await.unwrap();

    let service_url = issuer_doc.id().to_url().join("#my-revocation-service").unwrap();
    let credential_index: u32 = vc_id;
    let status: Status = RevocationBitmapStatus::new(service_url, credential_index).into();

    // Build credential using subject above and issuer.
    let mut credential_id = "https://example.edu/credentials/".to_owned();
    credential_id.push_str(vc_id.to_owned().to_string().as_str());
    let mut credential: Credential = CredentialBuilder::default()
    .id(Url::parse(credential_id).unwrap())
    .issuer(Url::parse(issuer_identity.did.clone()).unwrap())
    .type_("MarketplaceCredential")
    .expiration_date(Timestamp::now_utc().checked_add(Duration::days(365)).unwrap())
    .status(status)
    .subject(subject)
    .build().unwrap();

    
    issuer_doc.sign_data(&mut credential, &PrivateKey::try_from(issuer_identity.privkey.clone()).unwrap(), "#key-1", ProofOptions::default()).unwrap();

    // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
    // that the issuance date is not in the future and that the expiration date is not in the past:
    CredentialValidator::validate(
        &credential,
        &issuer_doc,
        &CredentialValidationOptions::default(),
        FailFast::FirstError,
    )
    .unwrap();

    Ok(credential)
}





// fn hash_vc(vc: Credential) -> Vec<u8> {
//     ethers::utils::keccak256(vc.to_json_vec().unwrap()).to_vec()
// }


// pub async fn create_hash_and_store_vc(pool: Pool, holder_did: String, issuer_state: &IssuerState) -> Result<HolderRequest, MyError> {
//     // get VC id from IDSC
    // let vc_id: U256 = get_free_vc_id(issuer_state.idsc_instance.clone(), issuer_state.eth_client.clone()).await;
    
//     let vc = create_vc(
//         holder_did.clone(), 
//         vc_id, 
//         issuer_state.issuer_identity.clone(), 
// issuer_state.issuer_account.client().clone().to_owned()
//     ).await.unwrap();
//     let vc_digest = hash_vc(vc.clone());

//     let expiration = Timestamp::now_utc().checked_add(Duration::minutes(1)).unwrap();
    // insert_holder_request(
    //     &pool.get().await.unwrap(), 
    //     vc.clone().to_json().unwrap(), 
    //     "0x".to_owned() + &hex::encode(vc_digest), 
    //     holder_did.clone(),
    //     expiration
    // ).await
// }

// pub async fn register_new_vc(pool: &Pool, issuer_state: &IssuerState, vc: String, vc_hash: String, pseudo_sign: String, holder_did: String) -> anyhow::Result<()>{
//     let vc_json: Value = serde_json::from_str(vc.as_str()).unwrap();
//     let credential: Credential = Credential::from_json_value(vc_json).unwrap();

//     let vc_id = get_vc_id_from_credential(credential.clone());

//     // issuer_state.idsc_instance.event_with_filter(Filter::new().event(event_name))
//     register_new_vc_idsc(
//         issuer_state.idsc_instance.clone(),
//         issuer_state.eth_client.clone(),
//         vc_id, 
//         pseudo_sign, 
//         holder_did,
//         credential.expiration_date.unwrap().to_unix(), 
//         credential.issuance_date.to_unix(), 
//         vc_hash.clone()
//     ).await?;
    
//     remove_holder_request_by_vchash(&pool.get().await.unwrap(), vc_hash).await;
//     Ok(())
// }