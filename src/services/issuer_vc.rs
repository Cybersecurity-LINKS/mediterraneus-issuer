use identity_iota::{core::{Timestamp, FromJson, Url, ToJson, Duration}, credential::{Credential, Subject, CredentialBuilder, CredentialValidator, CredentialValidationOptions, FailFast, RevocationBitmap, RevocationBitmapStatus, Status}, crypto::{PrivateKey, ProofOptions}, did::{DIDUrl, DID}, document::Service, prelude::{IotaDocument, IotaIdentityClientExt, IotaClientExt}};
use iota_client::Client;
use serde_json::json;
use crate::db::models::Identity;

use super::issuer_identity::resolve_did;


pub async fn create_vc(holder_did: String, vc_id: i32, issuer_identity: Identity, client: Client) -> Result<Credential, ()> {

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
    let credential_index: u32 = vc_id as u32;
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

