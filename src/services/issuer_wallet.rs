use ethers::prelude::{abigen, Contract};
use ethers::contract::Lazy;
use ethers::types::Address;
use iota_wallet::{
    account_manager::AccountManager,
    iota_client::constants::SHIMMER_COIN_TYPE,
    Result, account::AccountHandle,
};
use std::{env, path::PathBuf, sync::Arc};
use crate::LocalContractInstance;
use crate::utils::get_abi_from_file;
use crate::{utils::{setup_secret_manager, setup_client_options}, EthClient};

/// creates or loads the issuer's wallet account. It also ensures that the main account address ([0]) has 
/// funds. Funds are obtained from the faucet. If no funds are given to the account's address 
/// the issuer cannot publish new DIDs, hence he cannot create its SSI.
pub async fn create_or_load_wallet_account() -> Result<(AccountManager, AccountHandle)> {
    dotenv::dotenv().ok();
    let secret_manager = setup_secret_manager().await;
    let client_options = setup_client_options();

    let manager = AccountManager::builder()
        .with_secret_manager(secret_manager)
        .with_storage_path(PathBuf::from("./walletdb").to_str().unwrap())
        .with_client_options(client_options)
        .with_coin_type(SHIMMER_COIN_TYPE)
        .finish()
        .await?;

    // Create a new account
    let _account = match manager
        .create_account()
        .with_alias(env::var("WALLET_ALIAS").unwrap().to_string())
        .finish()
        .await {
            Ok(_account) => _account,
            Err(iota_wallet::Error::AccountAliasAlreadyExists(_account)) => {
                log::info!("Account already exists, loading it.");
                manager.get_account(env::var("WALLET_ALIAS").unwrap().to_string()).await?
            },
            Err(error) => panic!("Error: {:?}", error)
        };
        
    log::info!("Account address: {:?}.", _account.addresses().await?[0].address().to_bech32());

    Ok((manager, _account))
}


/// Checks if the idsc_abi.json has been already downloaded, if not the ABI is retrieved and stored locally.
/// The abigen! macro generates a type-safe binding to an Ethereum smart contract from its ABI (for the IDSC in this case). 
pub async fn setup_eth_wallet(eth_client: Arc<EthClient>) -> LocalContractInstance {
    abigen!(IDSC, "$CARGO_MANIFEST_DIR/abi/idsc_abi.json");

    let json_abi: Lazy<ethers::abi::Abi> = Lazy::new(|| {
        let from_file_abi = get_abi_from_file();
        if from_file_abi.len() == 0 {
            panic!("ABI file does not exist or is empty");
        }        
        serde_json::from_str(from_file_abi.as_str().clone()).expect("Invalid ABI")
    });

    let contract_address: Address = env::var("IDENTITY_SC_ADDRESS").unwrap().as_str().parse().unwrap();
    let idsc_istance = Contract::new(contract_address, json_abi.clone(), eth_client.clone());

    idsc_istance  
}

