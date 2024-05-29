use secure_mnemonic_vault::Vault;
use std::path::Path;

fn main() {
    // Create a new locked vault
    let password = b"password";
    let mut vault = Vault::new(password);

    // Set the vault data
    let mnemonic = "example mnemonic".to_string();
    let num_accounts = 5;
    match vault.set_data(mnemonic, num_accounts) {
        Ok(_) => println!("Vault data set successfully"),
        Err(e) => eprintln!("Failed to set vault data: {}", e),
    }

    // Save the locked vault to a file
    let file_path = Path::new("vault.json");
    match vault.save(file_path) {
        Ok(_) => {
            println!("Vault saved successfully {}", file_path.display());
            assert!(file_path.exists(), "File does not exist after saving");
        }
        Err(e) => eprintln!("Failed to save vault: {}", e),
    }

    // Load the locked vault from a file
    match Vault::load(file_path) {
        Ok(mut loaded_vault) => {
            // Unlock the vault with the password
            match loaded_vault.unlock(password) {
                Ok(_) => println!("Vault unlocked successfully"),
                Err(e) => eprintln!("Failed to unlock vault: {}", e),
            }

            // Access the vault data
            if let Some(data) = loaded_vault.get_data() {
                println!("Mnemonic: {}", data.mnemonic);
                println!("Number of Accounts: {}", data.num_accounts);
            }

            // Change the password
            let current_password = b"password";
            let new_password = b"new_password";
            match loaded_vault.change_password(current_password, new_password) {
                Ok(_) => println!("Password changed successfully"),
                Err(e) => eprintln!("Failed to change password: {}", e),
            }

            // Lock the vault
            loaded_vault.lock();
            println!("Vault locked");
        }
        Err(e) => eprintln!("Failed to load vault: {}", e),
    }
}
