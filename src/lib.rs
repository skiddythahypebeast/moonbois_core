use std::collections::HashMap;
use std::time::Duration;

use rpc::MoonboisClientError;
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signature::{Keypair, Signature}};

mod pending_snipe;
pub mod rpc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WalletDTO {
    pub id: i32,
    pub sol_balance: u64,
    pub token_balance: Option<u64>,
    pub public_key: Pubkey
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserExportDTO {
    pub wallets: Vec<String>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PumpfunDTO {
    pub mint_id: Pubkey,
    pub bonding_curve: Pubkey,
    pub associated_bonding_curve: Pubkey,
    pub creator: Pubkey,
    pub creator_vault: Pubkey
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectDTO {
    pub id: i32,
    pub name: String,
    pub deployer: Pubkey,
    pub user_id: i32,
    pub pumpfun: PumpfunDTO,
    pub set_id: i32
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PumpfunAutoBuyRequest {
    pub project_id: i32, 
    pub amount_in_sol: u64, 
    pub bundled: bool
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PumpfunBuyRequest {
    pub project_id: i32, 
    pub amount_in_sol: u64, 
    pub bundled: bool,
    pub wallet_id: i32
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum GrpcBundleResult {
    Confirmed(Vec<Signature>),
    Failed(String),
    Unconfirmed,
    TimedOut
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserBalancesDTO {
    pub created_at: u64,
    pub user: BalanceDTO,
    pub wallets: HashMap<String, BalanceDTO>
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PumpfunAutoSellRequest {
    pub project_id: i32,
    pub bundled: bool
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PumpfunSellRequest {
    pub project_id: i32,
    pub bundled: bool,
    pub wallet_id: i32,
    pub amount_in_tokens: u64
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum PumpfunBuyResult {
    Bundled(GrpcBundleResult),
    Standard(Signature)
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum PumpfunSellResult {
    Bundled(GrpcBundleResult),
    Standard(Signature),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CreateProjectDTO {
    pub mint_id: Pubkey,
    pub set_id: i32
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserDTO {
    pub id: i32,
    pub public_key: Pubkey,
    pub sol_balance: u64
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetDTO {
    pub id: i32,
    pub name: String,
    pub wallets: Vec<WalletDTO>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BalanceDTO {
    pub sol_balance: u64,
    pub token_balance: Option<u64>
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
pub struct BatchedBundleReceipt {
    pub fee_paid: u64,
    pub balances_before: HashMap<String, u64>,
    pub balances_after: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BatchedBundleFailed {
    pub reason: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum BatchedBundleResult {
    Success(Vec<BatchedBundleReceipt>),
    TransactionFailed(BatchedBundleFailed),
    BundleNotIncluded,
    Unconfirmed,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum PumpfunSnipeResults {
    Success(Vec<Signature>),
    Failed(String)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PumpfunSnipeComplete {
    pub project: ProjectDTO,
    pub snipe_results: Vec<PumpfunSnipeResults>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PumpfunSnipeStatus {
    Pending,
    InProgress,
    Complete(PumpfunSnipeComplete),
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

#[derive(Deserialize, Debug)]
pub struct SolTransferFailedReason(pub String);

#[derive(Deserialize, Debug)]
pub struct PendingSolTransferData {
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}

#[derive(Deserialize, Debug)]
pub struct SolTransferReceipt {
    pub fee_paid: u64,
    pub signature: Signature,
    pub data: PendingSolTransferData,
    pub balances_before: HashMap<String, u64>,
    pub balances_after: HashMap<String, u64>,
}

#[derive(Deserialize, Debug)]
pub struct SolTransferFailed {
    pub signature: Option<Signature>,
    pub data: PendingSolTransferData,
    pub reason: SolTransferFailedReason
}

#[derive(Deserialize, Debug)]
pub enum SolTransferResponse {
    Success(SolTransferReceipt),
    Failed(SolTransferFailed),
    CouldNotConfirm(Option<PendingSolTransferData>)
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SolBalanceResponse {
    pub includes_all_balances: bool,
    pub balances: HashMap<String, u64>
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TokenBalanceResponse {
    pub includes_all_balances: bool,
    pub balances: HashMap<String, Option<u64>>
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GetBalanceResponse {
    pub sol: SolBalanceResponse,
    pub token: Option<TokenBalanceResponse>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct GetTokenAccountsResponse {
    pub includes_all_accounts: bool,
    pub accounts: HashMap<String, Vec<Pubkey>>
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum TokenAccountCloseResponse {
    Success(TokenAccountCloseReceipt),
    Failed(TokenAccountCloseFailure),
    CouldNotConfirm(Option<TokenAccountCloseFailure>),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TokenAccountCloseReceipt {
    pub signature: Signature,
    pub closed_accounts: Vec<Pubkey>,
    pub fee_paid: u64,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TokenAccountCloseFailure {
    pub account: Pubkey,
    pub reason: TokenCloseFailedReason,
    pub signature: Option<Signature>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum TokenCloseFailedReason {
    AccountHasBalance,
    InvalidOwner,
    PreflightFailed(String),
    TransactionFailed(String),
    Unknown(String),
}