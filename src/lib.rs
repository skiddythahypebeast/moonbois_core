use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};

pub mod rpc;

#[derive(Serialize, Deserialize, Debug)]
pub struct UserDTO {
    pub id: i32,
    pub public_key: Pubkey,
    pub sol_balance: u64,
    pub wallets: Vec<WalletDTO>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WalletDTO {
    pub id: i32,
    pub sol_balance: u64,
    pub token_balance: Option<u64>,
    pub public_key: Pubkey
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserExportDTO {
    pub wallets: Vec<String>,
    pub main: String
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PumpfunDTO {
    pub mint_id: Pubkey,
    pub bonding_curve: Pubkey,
    pub associated_bonding_curve: Pubkey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProjectDTO {
    pub id: i32,
    pub owner: Pubkey,
    pub deployer: Pubkey,
    pub name: String,
    pub pumpfun: Option<PumpfunDTO>,
    pub mint_id: Option<Pubkey>,
    pub pending_snipe: bool
}

#[derive(Serialize, Deserialize)]
pub struct CreateProjectDTO {
    pub name: String,
    pub deployer: Pubkey
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProjectRecordDTO {
    pub id: i32,
    pub name: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SellResponse {
    pub included: bool,
    pub amount: u64,
    pub amount_out: u64,
    pub seller: Pubkey
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BuyResponse {
    pub included: bool,
    pub amount: u64,
    pub amount_out: u64,
    pub buyer: Pubkey
}

pub struct Credentials {
    pub signer: Keypair
}