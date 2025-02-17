use crate::BuyResponse;
use crate::CreateProjectDTO;
use crate::ProjectDTO;
use crate::ProjectRecordDTO;
use crate::SellResponse;
use crate::UserDTO;
use crate::UserExportDTO;

use reqwest::Client;
use reqwest::Error;
use reqwest::StatusCode;
use reqwest::Url;
use serde_json::json;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use url::ParseError;

use crate::Credentials;

pub enum Routes {
    User,
}

pub struct MoonboisClient {
    inner: Client,
    base_url: Url,
    jwt: Option<String>
}

impl MoonboisClient {
    pub fn new() -> Self {
        Self { 
            inner: Client::new(), 
            base_url: Url::parse("http://127.0.0.1:8000").unwrap(),
            jwt: None
        }
    }
    pub async fn login(&mut self, credentials: &Credentials) -> Result<(), MoonboisClientError> {
        let message = "authorize";
        let signature = credentials.signer.sign_message(message.as_bytes());
        let pubkey = credentials.signer.pubkey().to_string();
        let request = self.inner.get(self.base_url.join("/auth/")?)
            .header("X-public-key", pubkey)
            .header("X-signature", signature.to_string())
            .header("X-message", message)
            .build()?;

        let response = self.inner.execute(request).await?;

        if response.status() == StatusCode::OK {
            self.jwt = Some(response.text().await?);
            return Ok(())
        } else if response.status() == StatusCode::NOT_FOUND {
            return Err(MoonboisClientError::NotFound)
        } else {
            panic!("Unhandled status code");
        }
    }
    pub async fn create_user(&self, credentials: &Credentials, signer: &Keypair) -> Result<(), MoonboisClientError> {
        let message = "authorize";
        let signature = credentials.signer.sign_message(message.as_bytes());
        let pubkey = credentials.signer.pubkey().to_string();
        let body = json!({ "signer": signer.to_base58_string() });

        let request = self.inner.post(self.base_url.join(&format!("/auth/{}", signer.to_base58_string()))?)
            .header("X-public-key", pubkey)
            .header("X-signature", signature.to_string())
            .header("X-message", message)
            .body(serde_json::to_vec(&body)?)
            .build()?;

        let response = self.inner.execute(request).await?;

        if response.status().is_success() {
            return Ok(())
        }

        return Err(MoonboisClientError::ServerError(response.text().await?))
    }
    pub async fn recover_sol(&self) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let request = self.inner.post(self.base_url.join("/user/wallet/recover_sol")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;
            
            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(())
            }

            return Err(MoonboisClientError::ServerError(response.text().await?))
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_user(&self) -> Result<UserDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let request = self.inner.get(self.base_url.join("/user/")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;
            
            let response = self.inner.execute(request).await?;

            if response.status() == StatusCode::NOT_FOUND {
                return Err(MoonboisClientError::NotAccepted);
            }
            
            if response.status() != StatusCode::OK {
                return Err(MoonboisClientError::NotAccepted);
            }

            let response_text = response.text().await?;

            return Ok(serde_json::from_str(&response_text)?)
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn export(&self) -> Result<UserExportDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let request = self.inner.get(self.base_url.join("/user/export")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;
            
            assert!(response.status().is_success());

            return Ok(response.json().await?);
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn create_project(&self, name: String, deployer: Pubkey) -> Result<ProjectDTO, MoonboisClientError> {
        if let Some(jwt) = &self.jwt { 
            let body = CreateProjectDTO {
                deployer,
                name
            };

            let request = self.inner.post(self.base_url.join("/project")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .body(serde_json::to_vec(&body)?)
                .build()?;

            let response = self.inner.execute(request).await?;
            
            if response.status().is_success() {
                return Ok(response.json::<ProjectDTO>().await?);
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_project_records(&self) -> Result<Vec<ProjectRecordDTO>, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let request = self.inner.get(self.base_url.join("/project/all")?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json::<Vec<ProjectRecordDTO>>().await?);
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
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

            return Err(MoonboisClientError::ServerError(response.text().await?));
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
            
            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn get_snipe_status(&self, project_id: i32) -> Result<bool, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/snipe/status/{}", project_id);
            let request = self.inner.get(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn create_snipe(&self, project_id: i32, wallet_count: usize) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/snipe/{}/{}", project_id, wallet_count);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn sell(&self, project_id: i32, sniper_id: i32) -> Result<SellResponse, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/sell/{}?wallet={}", project_id, sniper_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn auto_sell(&self, project_id: i32) -> Result<SellResponse, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/sell/{}", project_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn buy(&self, project_id: i32, sniper_id: i32, amount_in_sol: u64) -> Result<BuyResponse, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/buy/{}/{}?wallet={}", project_id, amount_in_sol, sniper_id);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn auto_buy(&self, project_id: i32, amount_in_sol: u64) -> Result<BuyResponse, MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/buy/{}/{}", project_id, amount_in_sol);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn cancel_snipe(&self, project_id: i32) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/pumpfun/snipe/{}", project_id);
            let request = self.inner.delete(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn transfer_sol_from_main(&self, to: Pubkey, amount: u64) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/user/wallet/transfer/sol/main/{}/{}", to, amount);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
    pub async fn transfer_sol_from_sniper(&self, from: i32, to: Pubkey, amount: u64) -> Result<(), MoonboisClientError> {
        if let Some(jwt) = &self.jwt {
            let slug = format!("/user/wallet/transfer/sol/sniper/{}/{}/{}", from, to, amount);
            let request = self.inner.post(self.base_url.join(&slug)?)
                .header("Authorization", format!("Bearer {jwt}"))
                .build()?;

            let response = self.inner.execute(request).await?;

            if response.status().is_success() {
                return Ok(());
            }

            return Err(MoonboisClientError::ServerError(response.text().await?));
        };

        Err(MoonboisClientError::MissingJWT)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MoonboisClientError {
    #[error("Parse error: {0}")]
    ParseError(#[from] ParseError),
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] Error),
    #[error("JSON Error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Server error: {0}")]
    ServerError(String),
    #[error("Request was not accepted")]
    NotAccepted,
    #[error("Resource was not found")]
    NotFound,
    #[error("JWT not found")]
    MissingJWT
}