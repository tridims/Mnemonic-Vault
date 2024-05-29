mod encryption;
mod utils;
mod vault_encryptor;

use anyhow::{Context, Ok, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use utils::save_to_file;
use vault_encryptor::{EncryptedData, Encryption};

pub struct Vault {
    state: VaultState,
    data: Option<Data>,
    encrypted_data: Option<EncryptedData>,
    encryption: Option<Encryption>,
}

pub enum VaultState {
    Locked,
    Unlocked,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub mnemonic: String,
    pub num_accounts: usize,
}

impl Vault {
    pub fn new(key: &[u8]) -> Self {
        Vault {
            state: VaultState::Unlocked,
            data: None,
            encrypted_data: None,
            encryption: Some(Encryption::new_random(key.to_vec())),
        }
    }

    pub fn set_data(&mut self, mnemonic: String, num_accounts: usize) -> Result<()> {
        // Sets the vault data (mnemonic and number of accounts) in the vault
        // Returns an error if the vault is locked
        if let VaultState::Locked = self.state {
            return Err(anyhow::anyhow!("Vault is locked"));
        }

        let data = Data {
            mnemonic,
            num_accounts,
        };

        self.data = Some(data);

        // refresh the encrypted data
        if let Some(data) = &self.data {
            let encrypted_data = self
                .encryption
                .as_ref()
                .unwrap()
                .encrypt(serde_json::to_vec(data).unwrap().as_slice());
            self.encrypted_data = Some(encrypted_data);
        }

        Ok(())
    }

    pub fn save<P: AsRef<Path>>(&self, file_path: P) -> Result<()> {
        // Saves the locked vault to a file at the specified file path
        // Uses a default encryption algorithm to encrypt the vault data
        // Returns an error if the save operation fails
        if let Some(encrypted_data) = &self.encrypted_data {
            let data = serde_json::to_vec(encrypted_data)?;
            return save_to_file(&data, file_path);
        }

        anyhow::bail!("No encrypted data to save")
    }

    pub fn load<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        // Loads a locked vault from a file at the specified file path
        // Creates a new locked vault instance with the encrypted data
        // Returns an error if the load operation fails or the file is invalid

        let data = utils::load_from_file(file_path).context("Failed to load data from file")?;
        let encrypted_data: EncryptedData =
            serde_json::from_slice(&data).context("Failed to deserialize encrypted data")?;

        Ok(Vault {
            state: VaultState::Locked,
            data: None,
            encrypted_data: Some(encrypted_data),
            encryption: None,
        })
    }

    pub fn unlock(&mut self, password: &[u8]) -> Result<()> {
        // Unlocks the vault using the provided password
        // Decrypts the vault data and makes it accessible
        // Returns an error if the password is incorrect or decryption fails

        if let Some(encrypted_data) = &self.encrypted_data {
            let key = password.to_vec();
            let (encryption, decrypted_data) = Encryption::new_and_decrypt(key, encrypted_data);

            let data: Data = serde_json::from_slice(&decrypted_data)?;

            self.encryption = Some(encryption);
            self.data = Some(data);
            self.state = VaultState::Unlocked;

            Ok(())
        } else {
            Err(anyhow::anyhow!("No encrypted data found"))
        }
    }

    pub fn get_data(&self) -> Result<&Data> {
        // Retrieves a reference to the vault data if the vault is unlocked
        // Returns None if the vault is locked

        if let VaultState::Unlocked = self.state {
            if let Some(data) = &self.data {
                return Ok(data);
            }

            anyhow::bail!("No data found");
        }

        anyhow::bail!("Vault is locked")
    }

    pub fn lock(&mut self) {
        // Locks the vault and securely clears the decrypted vault data from memory
        self.state = VaultState::Locked;
        self.data = None;
        self.encryption = None;
    }

    pub fn change_password(&mut self, current_password: &[u8], new_password: &[u8]) -> Result<()> {
        // Changes the password used to encrypt the vault data
        // Requires the current password for authentication
        // Re-encrypts the vault data with the new password
        // Returns an error if the current password is incorrect or re-encryption fails

        if let Some(encrypted_data) = &self.encrypted_data {
            let key = current_password.to_vec();
            let (_, decrypted_data) = Encryption::new_and_decrypt(key, encrypted_data);

            let new_key = new_password.to_vec();
            let new_encryption = Encryption::new_random(new_key);
            let new_encrypted_data = new_encryption.encrypt(&decrypted_data);

            self.encrypted_data = Some(new_encrypted_data);
            self.encryption = Some(new_encryption);

            Ok(())
        } else {
            Err(anyhow::anyhow!("No encrypted data found"))
        }
    }
}
