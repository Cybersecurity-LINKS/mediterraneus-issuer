use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use anyhow::Context;
use colored_json::ToColoredJson;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::crypto::ProofOptions;
use identity_iota::iota::block::output::AliasOutput;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::iota::NetworkName;
use identity_iota::prelude::KeyPair;
use identity_iota::prelude::KeyType;
use identity_iota::verification::MethodScope;
use identity_iota::verification::VerificationMethod;
use iota_client::Client;
use iota_client::block::address::Address;
use iota_client::block::output::Output;
use iota_client::crypto::keys::bip39;
use iota_client::node_api::indexer::query_parameters::QueryParameter;
use iota_client::secret::SecretManager;
use iota_client::secret::stronghold::StrongholdSecretManager;
use mediterraneus_issuer::dtos::identity_dtos::ChallengeDTO;
use mediterraneus_issuer::services::issuer_wallet;
use mediterraneus_issuer::utils::ensure_address_has_funds;
use mediterraneus_issuer::utils::setup_client;
use rand::distributions::DistString;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let client = setup_client();
    let faucet_endpoint = env::var("FAUCET_URL").expect("$FAUCET_URL must be set");

    let (account_manager, account) = issuer_wallet::create_or_load_wallet_account(None).await?;
    let address = account.addresses().await?[0].address().as_ref().clone();

    ensure_address_has_funds(&client.clone(), address, &faucet_endpoint.clone()).await?;
    
    let secret_manager_holder = account_manager.get_secret_manager();

    // Get the Bech32 human-readable part (HRP) of the network.
    let network_name: NetworkName = client.network_name().await?;

    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    let mut document: IotaDocument = IotaDocument::new(&network_name);

    // Insert a new Ed25519 verification method in the DID document.
    let keypair: KeyPair = KeyPair::new(KeyType::Ed25519)?;
    let method: VerificationMethod = VerificationMethod::new(document.id().clone(), keypair.type_(), keypair.public(), "#key-1")?;
    document.insert_method(method, MethodScope::VerificationMethod)?;

    // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    let alias_output: AliasOutput = client.new_did_output(address.clone(), document, None).await?;

    // Publish the Alias Output and get the published DID document.
    let holder_document: IotaDocument = client.publish_did_output(&mut *secret_manager_holder.write().await, alias_output).await?;
    println!("Published DID document: {holder_document:#}");


    /* Request credential */
    let mut map = HashMap::new();
    map.insert("did", holder_document.id());

    let req_client = reqwest::Client::new();
    let url = "http://".to_owned() + &env::var("ADDR").expect("$ADDR must be set") + ":" + &env::var("PORT").expect("$PORT must be set") + "/api/identity";
    let res = req_client.post(url)
        .json(&map)
        .send()
        .await?;

    

    let credential = res.json::<Credential>().await?;

    log::info!("Credential: \n {}", credential.to_json_pretty()?.to_colored_json_auto()?);


    /* Revoke credential */

    // Get challenge 
    let url = "http://".to_owned() + &env::var("ADDR").expect("$ADDR must be set") + ":" + &env::var("PORT").expect("$PORT must be set") + "/api/identity/challenge";
    let res = req_client.post(url)
        .json(&map)
        .send()
        .await?;

    let challenge = res.json::<ChallengeDTO>().await?;
    log::info!("Challenge: {}", challenge.challenge);

    let expiration = Timestamp::parse(&challenge.expiration).unwrap();


    // Create an unsigned Presentation from the previously issued Verifiable Credential.
    let mut presentation: Presentation = PresentationBuilder::default()
    .holder(Url::parse(holder_document.id().as_ref())?)
    .credential(credential)
    .build()?;

    // Sign the verifiable presentation using the holder's verification method
    // and include the requested challenge and expiry timestamp.
    holder_document.sign_data(
        &mut presentation,
        keypair.private(),
        "#key-1",
        ProofOptions::new().challenge(challenge.challenge).expires(expiration),
    )?;


    log::info!("Presentiation: \n {}", presentation.to_json_pretty()?.to_colored_json_auto()?);


    let presentation_verifier_options: VerifierOptions = VerifierOptions::new()
    .challenge(challenge.to_owned())
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
    resolver
        .verify_presentation(
        &presentation,
        &presentation_validation_options,
        FailFast::FirstError,
        None,
        None,
        )
        .await?;

    Ok(())
}




/// Generates an address from the given [`SecretManager`] and adds funds from the faucet.
pub async fn get_address_with_funds(
    client: &Client,
    stronghold: &mut SecretManager,
    faucet_endpoint: &str,
  ) -> anyhow::Result<Address> {
    let address: Address = get_address(client, stronghold).await?;
  
    request_faucet_funds(
      client,
      address,
      client.get_bech32_hrp().await?.as_str(),
      faucet_endpoint,
    )
    .await
    .context("failed to request faucet funds")?;
  
    Ok(address)
  }
  
  /// Initializes the [`SecretManager`] with a new mnemonic, if necessary,
  /// and generates an address from the given [`SecretManager`].
  pub async fn get_address(client: &Client, secret_manager: &mut SecretManager) -> anyhow::Result<Address> {
    let keypair = KeyPair::new(KeyType::Ed25519)?;
    let mnemonic =
      iota_client::crypto::keys::bip39::wordlist::encode(keypair.private().as_ref(), &bip39::wordlist::ENGLISH)
        .map_err(|err| anyhow::anyhow!(format!("{err:?}")))?;
  
    if let SecretManager::Stronghold(ref mut stronghold) = secret_manager {
      match stronghold.store_mnemonic(mnemonic).await {
        Ok(()) => (),
        Err(iota_client::Error::StrongholdMnemonicAlreadyStored) => (),
        Err(err) => anyhow::bail!(err),
      }
    } else {
      anyhow::bail!("expected a `StrongholdSecretManager`");
    }
  
    let address = client.get_addresses(secret_manager).with_range(0..1).get_raw().await?[0];
  
    Ok(address)
  }
  
  /// Requests funds from the faucet for the given `address`.
  async fn request_faucet_funds(
    client: &Client,
    address: Address,
    network_hrp: &str,
    faucet_endpoint: &str,
  ) -> anyhow::Result<()> {
    let address_bech32 = address.to_bech32(network_hrp);
  
    iota_client::request_funds_from_faucet(faucet_endpoint, &address_bech32).await?;
  
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
      loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
  
        let balance = get_address_balance(client, &address_bech32)
          .await
          .context("failed to get address balance")?;
        if balance > 0 {
          break;
        }
      }
      Ok::<(), anyhow::Error>(())
    })
    .await
    .context("maximum timeout exceeded")??;
  
    Ok(())
  }
  
  /// Returns the balance of the given Bech32-encoded `address`.
  async fn get_address_balance(client: &Client, address: &str) -> anyhow::Result<u64> {
    let output_ids = client
      .basic_output_ids(vec![
        QueryParameter::Address(address.to_owned()),
        QueryParameter::HasExpiration(false),
        QueryParameter::HasTimelock(false),
        QueryParameter::HasStorageDepositReturn(false),
      ])
      .await?;
  
    let outputs_responses = client.get_outputs(output_ids).await?;
  
    let mut total_amount = 0;
    for output_response in outputs_responses {
      let output = Output::try_from_dto(&output_response.output, client.get_token_supply().await?)?;
      total_amount += output.amount();
    }
  
    Ok(total_amount)
  }
  
  /// Creates a random stronghold path in the temporary directory, whose exact location is OS-dependent.
  pub fn random_stronghold_path() -> PathBuf {
    let mut file = std::env::temp_dir();
    file.push("test_strongholds");
    file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
    file.set_extension("stronghold");
    file.to_owned()
  }

