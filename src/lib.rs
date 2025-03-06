use std::collections::HashMap;
use std::time::Duration;

use rpc::MoonboisClientError;
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};

mod pending_snipe;
pub mod rpc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserDTO {
    pub id: i32,
    pub public_key: Pubkey,
    pub sol_balance: u64,
    pub wallets: HashMap<String, WalletDTO>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WalletDTO {
    pub id: i32,
    pub sol_balance: u64,
    pub token_balance: Option<u64>,
    pub public_key: Pubkey
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserExportDTO {
    pub wallets: Vec<String>,
    pub main: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PumpfunDTO {
    pub mint_id: Pubkey,
    pub bonding_curve: Pubkey,
    pub associated_bonding_curve: Pubkey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectDTO {
    pub id: i32,
    pub name: String,
    pub deployer: Pubkey,
    pub user_id: i32,
    pub pumpfun: PumpfunDTO
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserBalancesDTO {
    pub created_at: u64,
    pub user: BalanceDTO,
    pub wallets: HashMap<String, BalanceDTO>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BalanceDTO {
    pub sol_balance: u64,
    pub token_balance: Option<u64>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CreateProjectDTO {
    pub mint_id: Pubkey
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectRecordDTO {
    pub id: i32,
    pub name: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SellResponse {
    pub included: bool,
    pub amount: u64,
    pub amount_out: u64,
    pub seller: Pubkey
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuyResponse {
    pub included: bool,
    pub amount: u64,
    pub amount_out: u64,
    pub buyer: Pubkey
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PumpfunSnipeStatus {
    Pending,
    InProgress,
    Complete(ProjectDTO),
    SnipeFailed(String),
    CreateProjectFailed(String),
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PumpfunBumpStatus {
    Running,
    Pending,
    Failed(String)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnableBumpsParams {
    pub bump_amount: u64,
    pub bump_interval: Duration
}

pub struct Credentials {
    pub signer: Keypair
}

#[derive(thiserror::Error, Debug)]
pub enum PendingSnipeError {
    #[error("ProjectCreationFailed: {0}")]
    ProjectCreationFailed(String),
    #[error("SnipeFailed: {0}")]
    SnipeFailed(String),
    #[error("MoonboisClientError: {0}")]
    MoonboisClientError(#[from] MoonboisClientError),
    #[error("Snipe task was cancelled")]
    SnipeCancelled
}