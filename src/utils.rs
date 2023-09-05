use identity_iota::{prelude::{IotaDID, IotaDocument}, verification::MethodScope, credential::Credential};
use iota_wallet::ClientOptions;
use iota_client::{Client, secret::{SecretManager, stronghold::StrongholdSecretManager}, block::{address::Address, output::Output}, node_api::indexer::query_parameters::QueryParameter};
use std::{env, path::PathBuf, path::Path};
use anyhow::Context;
use reqwest;
use serde_json::{self};
use std::fs::File;
use std::io::prelude::*;


pub fn setup_client_options() -> ClientOptions { 
    dotenv::dotenv().ok();
    ClientOptions::new().with_primary_node(&env::var("NODE_URL").unwrap(), None).unwrap()
}

pub fn setup_client() -> Client {
    dotenv::dotenv().ok();
    Client::builder()
        .with_primary_node(&env::var("NODE_URL").unwrap(), None).unwrap()
        .finish()
        .unwrap()
}

pub async fn setup_secret_manager(reset: Option<bool>) -> SecretManager {
    dotenv::dotenv().ok();

    let reset = reset.unwrap_or(false);
    let mut ss = StrongholdSecretManager::builder()
    .password(&env::var("STRONGHOLD_PASSWORD").unwrap())
    .build(PathBuf::from("./wallet.stronghold")).unwrap();

    let mnemonic: String; 
    if reset {
      mnemonic = iota_client::generate_mnemonic().unwrap();
    } else {
      mnemonic = env::var("NON_SECURE_MNEMONIC").unwrap();
    }

    // Only required the first time, can also be generated with `manager.generate_mnemonic()?`
    // The mnemonic only needs to be stored the first time
    match ss.store_mnemonic(mnemonic.to_string()).await {
        Ok(()) => log::info!("Stronghold mnemonic stored"),
        Err(iota_client::Error::StrongholdMnemonicAlreadyStored) => log::info!("Stronghold mnemonic already stored"),
        Err(error) => panic!("Error: {:?}", error)
    }
 
    if reset {
      log::info!("Mnemonic generated {}. Save it.", mnemonic);
    }
    SecretManager::Stronghold(ss)
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

pub async fn ensure_address_has_funds(client: &Client, address: Address, faucet_endpoint: &str) -> anyhow::Result<()> {
    let network_hrp = &client.get_bech32_hrp().await?;
    let address_bech32 = address.to_bech32(network_hrp);

    let balance = get_address_balance(client, &address_bech32)
          .await
          .context("failed to get address balance")?;
    if balance == 0 {
        log::info!("Funding address {}", address.to_bech32(network_hrp));
        request_faucet_funds(client, address, &network_hrp, faucet_endpoint).await?;
    } else {
        log::info!("Address has already enough funds: {}.", balance);
    }
    Ok(())
}

pub fn convert_string_to_iotadid(did: String) -> IotaDID {
  IotaDID::parse(did).unwrap()
}

pub fn extract_pub_key_from_doc(did_doc: IotaDocument) -> Vec<u8> {
  did_doc.methods(Some(MethodScope::VerificationMethod))[0].data().try_decode().unwrap()
}

pub fn get_vc_id_from_credential(vc: Credential) -> i64 {
  let full_id = vc.id.unwrap();

  let split: Vec<&str> = full_id.as_str().split("/").collect();
  let id = split.get(split.len() - 1).unwrap().to_owned();
  let num: i64 = id.parse().unwrap();
  num
}

pub fn remove_0x_prefix(hex_string: String) -> String {
  hex_string.strip_prefix("0x").unwrap().to_string()
}

