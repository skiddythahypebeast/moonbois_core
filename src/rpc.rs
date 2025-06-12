use crate::CreateProjectDTO;
use crate::EnableBumpsParams;
use crate::GetBalanceResponse;
use crate::GetTokenAccountsResponse;
use crate::ProjectDTO;
use crate::PumpfunAutoBuyRequest;
use crate::PumpfunAutoSellRequest;
use crate::PumpfunBumpStatus;
use crate::PumpfunBuyRequest;
use crate::PumpfunBuyResult;
use crate::PumpfunSellRequest;
use crate::PumpfunSellResult;
use crate::PumpfunSnipeStatus;
use crate::SetDTO;
use crate::SolTransferResponse;
use crate::TokenAccountCloseResponse;
use crate::UserDTO;
use crate::UserExportDTO;
use crate::WalletDTO;

use reqwest::Client;
use reqwest::Error;
use reqwest::StatusCode;
use reqwest::Url;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use tokio_tungstenite::tungstenite::http::uri::InvalidUri;
use url::ParseError;

use crate::pending_snipe::PendingSnipe;
use crate::Credentials;

pub enum Routes {
    User,
}

#[derive(Clone)]
pub struct MoonboisClient {
    inner: Client,
    pub base_url: Url,
    pub jwt: Option<String>
}

impl MoonboisClient {
    pub fn new() -> Self {
        Self { 
            inner: Client::new(), 
            base_url: Url::parse("http://192.168.50.12:8000/").unwrap(),
            jwt: None
        }
    }
    pub async fn login(&mut self, credentials: &Credentials) -> Result<(), MoonboisClientError> {
        let message = "authorize";
        let signature = credentials.signer.sign_message(message.as_bytes());
        let pubkey = credentials.signer.pubkey().to_string();
        let request = self.inner.get(self.base_url.join("/auth")?)
            .header("X-public-key", pubkey)
            .header("X-signature", signature.to_string())
            .header("X-message", message)
            .build()?;

        let response = self.inner.execute(request).await?;

        if response.status().is_success() {
            self.jwt = Some(response.text().await?);
            return Ok(())
        }

        if let StatusCode::NOT_FOUND = response.status() {
            return Err(MoonboisClientError::NotFound);
        }
        
        Err(MoonboisClientError::UnhandledServerError(response.text().await?))
    }
    pub async fn create_user(&self, credentials: &Credentials) -> Result<(), MoonboisClientError> {
        let message = "authorize";
        let signature = credentials.signer.sign_message(message.as_bytes());
        let pubkey = credentials.signer.pubkey().to_string();

        let request = self.inner.post(self.base_url.join(&format!("/auth"))?)
            .header("X-public-key", pubkey)
            .header("X-signature", signature.to_string())
            .header("X-message", message)
            .build()?;

        let response = self.inner.execute(request).await?;

        if response.status().is_success() {
            return Ok(())
        }

        if let StatusCode::NOT_FOUND = response.status() {
            return Err(MoonboisClientError::NotFound);
        }

        return Err(MoonboisClientError::UnhandledServerError(response.text().await?))
    }
    pub async fn get_user(&self) -> Result<UserDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let request = self.inner.get(self.base_url.join("/user")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;
            
            let response = self.inner.execute(request).await?;
            
            if response.status().is_success() {
                return Ok(response.json().await?)
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?))
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn update_user_wallet(&self, private_key: &str) -> Result<WalletDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let slug = format!("/user/wallet/{}", private_key);
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;
            
            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?)
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?))
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_user_balance(&self) -> Result<u64, MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let slug = format!("/user/balance");
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;
            
            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?)
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?))
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn export(&self) -> Result<UserExportDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let request = self.inner.get(self.base_url.join("/user/export")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;
            
            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?)
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?))
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn create_project(&self, mint_id: Pubkey, set_id: i32) -> Result<ProjectDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let body = CreateProjectDTO { mint_id, set_id };

            let request = self.inner.post(self.base_url.join("/project")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .body(serde_json::to_vec(&body)?)
                .build()?;

            let response = self.inner.execute(request).await?;
            
            if response.status().is_success() {
                return Ok(response.json::<ProjectDTO>().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_user_projects(&self) -> Result<Vec<ProjectDTO>, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let request = self.inner.get(self.base_url.join("/project/all")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_project(&self, project_id: i32) -> Result<ProjectDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/project/{}", project_id);
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json::<ProjectDTO>().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn delete_project(&self, project_id: i32) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/project/{}", project_id);
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }
            
            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_snipe_status(&self, deployer: Pubkey) -> Result<PumpfunSnipeStatus, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/snipe/{}/status", deployer);
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn create_snipe(&self, deployer: Pubkey, wallet_count: usize, wallet_set_id: i32) -> Result<PendingSnipe, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/snipe/{}/{}/{}", wallet_count, deployer, wallet_set_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(PendingSnipe::new(deployer, self));
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn sell(&self, project_id: i32, wallet_id: i32, amount_in_tokens: u64, bundled: bool) -> Result<PumpfunSellResult, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let data = serde_json::to_vec(&PumpfunSellRequest {
                bundled,
                project_id,
                amount_in_tokens,
                wallet_id
            })?;

            let slug = format!("/pumpfun/auto_sell");
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(data)
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn buy(&self, project_id: i32, sniper_id: i32, amount_in_sol: u64, bundled: bool) -> Result<PumpfunBuyResult, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let data = serde_json::to_vec(&PumpfunBuyRequest {
                amount_in_sol,
                bundled,
                project_id,
                wallet_id: sniper_id
            })?;

            let slug = format!("/pumpfun/buy");
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(data)
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn auto_buy(&self, project_id: i32, amount_in_sol: u64, bundled: bool) -> Result<PumpfunBuyResult, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let data = serde_json::to_vec(&PumpfunAutoBuyRequest {
                amount_in_sol,
                bundled,
                project_id
            })?;

            let slug = format!("/pumpfun/auto_buy");
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(data)
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            if response.status() == StatusCode::NOT_FOUND {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        }

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn auto_sell(&self, project_id: i32, bundled: bool) -> Result<PumpfunSellResult, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let data = serde_json::to_vec(&PumpfunAutoSellRequest {
                bundled,
                project_id,
            })?;

            let slug = format!("/pumpfun/auto_sell");
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(data)
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            if response.status() == StatusCode::NOT_FOUND {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        }

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn nuke(&self, project_id: i32) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/nuke/{}", project_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn cancel_snipe(&self, deployer: &Pubkey) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/snipe/{}", deployer);
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_wallet(&self, wallet_id: i32) -> Result<WalletDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/wallet/{}", wallet_id);
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn import_user_wallet(&self, signer: &Keypair) -> Result<WalletDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/wallet/{}", signer.to_base58_string());
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn delete_user_wallet(&self, wallet_id: i32) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/wallet/{}", wallet_id);
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn enable_bumps(&self, project_id: i32, params: EnableBumpsParams) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/bump/{}", project_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .json(&params)
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn disable_bumps(&self) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/bump");
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_bumps_status(&self) -> Result<PumpfunBumpStatus, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/bump");
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn create_set(&self, name: String, wallet_count: usize) -> Result<SetDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/{}", name, wallet_count);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn load_sets(&self) -> Result<Vec<SetDTO>, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets");
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn delete_set(&self, set_id: i32) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}", set_id);
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn add_set_wallet(&self, signer: &Keypair, set_id: i32) -> Result<WalletDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/add_wallet/{}", set_id, signer.to_base58_string());
            let request = self.inner.patch(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn remove_set_wallet(&self, set_id: i32, wallet_id: i32) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/wallet/{}", set_id, wallet_id);
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn rename_set(&self, set_id: i32, name: &str) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/rename/{}", set_id, name);
            let request = self.inner.patch(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn fund_set(&self, set_id: i32, amount: u64) -> Result<Vec<SolTransferResponse>, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/fund/{}", set_id, amount);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn drain_set(&self, set_id: i32) -> Result<Vec<SolTransferResponse>, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/drain_set", set_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_set_balance(&self, set_id: i32, project_id: Option<i32>) -> Result<GetBalanceResponse, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = if let Some(project_id) = project_id {
                format!("/sets/{}/balance?project_id={}", set_id, project_id)
            } else {
                format!("/sets/{}/balance", set_id)
            };

            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_set_token_accounts(&self, set_id: i32) -> Result<GetTokenAccountsResponse, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/token_accounts", set_id);
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn duplicate_set(&self, set_id: i32) -> Result<SetDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/duplicate", set_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn transfer_set_funds(&self, from_set_id: i32, to_set_id: i32) -> Result<Vec<SolTransferResponse>, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/transfer_funds/{}", from_set_id, to_set_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn close_set_token_accounts(&self, set_id: i32) -> Result<Vec<TokenAccountCloseResponse>, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/sets/{}/token_accounts", set_id);
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }
        
            if let StatusCode::NOT_FOUND = response.status() {
                return Err(MoonboisClientError::NotFound);
            }

            return Err(MoonboisClientError::UnhandledServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MoonboisClientError {
    #[error("InvalidUri error: {0}")]
    InvalidUri(#[from] InvalidUri),
    #[error("Parse error: {0}")]
    ParseError(#[from] ParseError),
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] Error),
    #[error("JSON Error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Server error: {0}")]
    UnhandledServerError(String),
    #[error("Request was not accepted")]
    NotAccepted,
    #[error("Resource was not found")]
    NotFound,
    #[error("JWT not found")]
    MissingJWT
}
