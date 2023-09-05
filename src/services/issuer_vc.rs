use std::ops::Deref;

use deadpool_postgres::Pool;
use identity_iota::{core::{Timestamp, FromJson, Url, ToJson, Duration}, credential::{Credential, Subject, CredentialBuilder, CredentialValidator, CredentialValidationOptions, FailFast, RevocationBitmap, RevocationBitmapStatus, Status, ValidationError, Presentation, PresentationValidationOptions, SubjectHolderRelationship}, crypto::{PrivateKey, ProofOptions}, did::{DIDUrl, DID}, document::{Service, verifiable::VerifierOptions}, prelude::{IotaDocument, IotaIdentityClientExt, IotaClientExt}, resolver::Resolver};
use iota_client::{Client, block::output::{AliasOutput, RentStructure, AliasOutputBuilder}, secret::SecretManager, crypto::utils::rand::fill};
use serde_json::json;


use crate::{db::{models::{Identity, ChallengeRequest}, operations::{get_challenge_req, update_challenge_req, insert_challenge_req}}, errors::my_errors::MyError};

use super::issuer_identity::resolve_did;


pub async fn create_vc(holder_did: String, vc_id: i32, issuer_identity: &Identity, client: &Client) -> Result<Credential, ()> {

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


pub async fn revoke_vc(credential_index: i32, issuer_identity: &Identity, client: &Client, secret_manager_issuer: &SecretManager) -> anyhow::Result<()> {

    let mut issuer_document = resolve_did(client, issuer_identity.did.clone()).await?;
    let credential_index = credential_index as u32;
    issuer_document.revoke_credentials("my-revocation-service", &[credential_index])?;

    // Publish the changes.
    let alias_output: AliasOutput = client.update_did_output(issuer_document.clone()).await?;
    let rent_structure: RentStructure = client.get_rent_structure().await?;
    let alias_output: AliasOutput = AliasOutputBuilder::from(&alias_output)
        .with_minimum_storage_deposit(rent_structure)
        .finish(client.get_token_supply().await?)?;
    issuer_document = client.publish_did_output(&secret_manager_issuer, alias_output).await?;
    
    Ok(())
}


pub async fn is_revoked(credential: Credential, issuer_identity: &Identity, client: &Client) -> anyhow::Result<bool> {
    let issuer_document = resolve_did(client, issuer_identity.did.clone()).await?;

    let validation_result = CredentialValidator::validate(
        &credential,
        &issuer_document,
        &CredentialValidationOptions::default(),
        FailFast::FirstError,
    );

    if validation_result.is_ok() {
        return Ok(false)
    }
    
    // We expect validation to no longer succeed because the credential was revoked.
    let result = matches!(
    validation_result.unwrap_err().validation_errors[0],
    ValidationError::Revoked
    );

    Ok(result)
}


pub async fn generate_challenge(pool: Pool, did: String) -> anyhow::Result<ChallengeRequest>{

    let challenge_req = get_challenge_req(&pool.get().await.unwrap(), did.clone()).await;
    let challenge = match challenge_req {
        Ok(challenge_req) => {
                // check that it is not expired, if expired update db with a new one
            let holder_request_timestamp = Timestamp::parse(&challenge_req.clone().expiration).unwrap();
            let challenge =  if holder_request_timestamp < Timestamp::now_utc() {
                // request expired --> update with new challenge
                let mut challenge = [0u8; 32];
                fill(&mut challenge)?;
                let expiration = Timestamp::now_utc().checked_add(Duration::minutes(1)).unwrap();
                let challenge = update_challenge_req(&pool.get().await.unwrap(), did, hex::encode(challenge), expiration ).await?;
                challenge
            } else {
                // request still not expired --> stop handler from continuing
                challenge_req
            };

            challenge
        },
        Err(e) => {
            //request not present -> insert new challenge request into db
            let mut challenge = [0u8; 32];
            fill(&mut challenge)?;
            let expiration = Timestamp::now_utc().checked_add(Duration::minutes(1)).unwrap();
            let challenge = insert_challenge_req(&pool.get().await.unwrap(), did, hex::encode(challenge), expiration).await?;
            challenge
        }
    };

    Ok(challenge)
}


pub async fn verify_vp(presentation: Presentation, pool: Pool, client: Client) -> anyhow::Result<(),()>{
    let holder_did = presentation.holder.as_ref().unwrap().to_string();
    let challenge_req = get_challenge_req(&pool.get().await.unwrap(), holder_did).await;
    let result = match challenge_req {
        Ok(challenge_req) => {
                // check that it is not expired, if expired update db with a new one
            let holder_request_timestamp = Timestamp::parse(&challenge_req.clone().expiration).unwrap();
            let res = if holder_request_timestamp < Timestamp::now_utc() {
                Err(())
            } else {
                // request still not expired 
                let presentation_verifier_options: VerifierOptions = VerifierOptions::new()
                    .challenge(challenge_req.challenge.to_owned())
                    .allow_expired(false);

                // Do not allow credentials that expire within the next 10 hours.
                let credential_validation_options: CredentialValidationOptions = CredentialValidationOptions::default()
                    .earliest_expiry_date(Timestamp::now_utc().checked_add(Duration::hours(10)).unwrap());

                let presentation_validation_options = PresentationValidationOptions::default()
                    .presentation_verifier_options(presentation_verifier_options)
                    .shared_validation_options(credential_validation_options)
                    .subject_holder_relationship(SubjectHolderRelationship::AlwaysSubject);

                // Resolve issuer and holder documents and verify presentation.
                // Passing the holder and issuer to `verify_presentation` will bypass the resolution step.
                let mut resolver: Resolver<IotaDocument> = Resolver::new();
                resolver.attach_iota_handler(client);
                let res = resolver
                    .verify_presentation(
                    &presentation,
                    &presentation_validation_options,
                    FailFast::FirstError,
                    None,
                    None,
                    )
                    .await;

                if res.is_ok() {
                    Ok(())
                } else {
                    Err(())
                }

                // Ok(())
                // res
            };
            res
        },
        Err(_) => {
            Err(())
        }
    };

    result
}


