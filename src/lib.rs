pub mod config;
pub mod handler;
pub mod dtos;
pub mod services;
pub mod utils;
pub mod errors;
pub mod db;

use std::sync::Arc;

use ethers::prelude::k256::ecdsa::SigningKey;
use iota_wallet::secret::SecretManager;
use iota_wallet::account::AccountHandle;
use db::models::Identity;
use tokio::sync::RwLock;

use ethers::providers::{Provider, Http};
use ethers::prelude::{SignerMiddleware, k256, ContractInstance};
use ethers::prelude::Wallet;

pub type EthClient = SignerMiddleware<Provider<Http>, Wallet<k256::ecdsa::SigningKey>>;
pub type LocalContractInstance = ContractInstance<Arc<SignerMiddleware<ethers::providers::Provider<Http>, Wallet<SigningKey>>>, 
SignerMiddleware<ethers::providers::Provider<Http>, Wallet<SigningKey>>>;

// This struct represents state
pub struct IssuerState {
    pub issuer_account: AccountHandle,
    pub secret_manager: Arc<RwLock<SecretManager>>,
    pub issuer_identity: Identity,
    // pub eth_client: Arc<EthClient>,
    // pub idsc_instance: LocalContractInstance
}