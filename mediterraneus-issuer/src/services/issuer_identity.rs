use deadpool_postgres::Pool;
use identity_iota::crypto::KeyPair;
use identity_iota::crypto::KeyType;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::prelude::IotaClientExt;
use identity_iota::verification::MethodScope;
use identity_iota::verification::VerificationMethod;
use iota_client::Client;
use iota_client::block::address::Address;
use iota_client::block::output::AliasOutput;
use iota_client::secret::SecretManager;
use crate::db::operations;
use crate::db::operations::insert_identity_issuer;
use crate::{models::models::Identity, errors::my_errors::MyError};

pub async fn create_identity(client: &Client, wallet_address: Address, secret_manager: &mut SecretManager, pool: Pool) -> Result<Identity, MyError> {
    // check if DID is already available
    let issuer_identity = operations::get_identity_did(&pool.get().await.unwrap()).await?;
    if issuer_identity.did.len() > 0 && issuer_identity.privkey.len() > 0 {
        return Ok(issuer_identity);
    }
    log::info!("Creating new Issuer Identity... {:?}", wallet_address.to_bech32(client.get_bech32_hrp().await.unwrap()));
    // Get the Bech32 human-readable part (HRP) of the network.
    let network_name = client.network_name().await.unwrap();

    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    let mut document: IotaDocument = IotaDocument::new(&network_name);
    
    // Insert a new Ed25519 verification method in the DID document.
    let keypair: KeyPair = KeyPair::new(KeyType::Ed25519).unwrap();
    let method: VerificationMethod = VerificationMethod::new(document.id().clone(), keypair.type_(), keypair.public(), "#key-1").unwrap();
    document.insert_method(method, MethodScope::VerificationMethod).unwrap();

    // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    let alias_output: AliasOutput = client.new_did_output(wallet_address, document, None).await.unwrap();

    // Publish the Alias Output and get the published DID document.
    let document: IotaDocument = client.publish_did_output(secret_manager, alias_output).await.unwrap();
    println!("Published DID document: {document:#}");

    // Insert new identity in the DB
    let new_issuer_identity = Identity { did: document.id().to_string(), privkey: keypair.private().as_ref().to_vec() };
    insert_identity_issuer(&pool.get().await.unwrap(), new_issuer_identity.clone()).await?;
    Ok(new_issuer_identity)
}  