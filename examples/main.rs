use secure_mnemonic_vault::Vault;
use std::path::Path;

fn main() {
    // Create a new locked vault
    let password = b"a good password";
    let mut vault = Vault::new(password);
    println!("Created a new locked vault with a password\n");

    // Set the vault data
    let mnemonic = "train forest limb pistol wide robot blur wrist all also galaxy veteran reveal foil depth couple custom high robust produce crawl victory glare vocal".to_string();
    let num_accounts = 5;
    println!("Setting vault data");
    println!("Mnemonic: {}", mnemonic);
    println!("Number of Accounts: {}\n", num_accounts);
    match vault.set_data(mnemonic, num_accounts) {
        Ok(_) => println!("Vault data set successfully"),
        Err(e) => eprintln!("Failed to set vault data: {}", e),
    }

    // Save the locked vault to a file
    let file_path = Path::new("vault.json");
    println!("\nSaving vault to file: {}", file_path.display());
    match vault.save(file_path) {
        Ok(_) => {
            println!("Vault saved successfully {}", file_path.display());
            assert!(file_path.exists(), "File does not exist after saving");
        }
        Err(e) => eprintln!("Failed to save vault: {}", e),
    }

    // take a look at the file
    println!("\nFile contents:");
    match std::fs::read_to_string(file_path) {
        Ok(contents) => println!("{}", contents),
        Err(e) => eprintln!("Failed to read file: {}", e),
    }

    // Load the locked vault from a file
    println!("\nLoading vault from file: {}", file_path.display());
    match Vault::load(file_path) {
        Ok(mut loaded_vault) => {
            // Unlock the vault with the password
            println!("Unlocking vault");
            match loaded_vault.unlock(password) {
                Ok(_) => println!("Vault unlocked successfully"),
                Err(e) => eprintln!("Failed to unlock vault: {}", e),
            }

            // Access the vault data
            println!("\nVault data:");
            if let Ok(data) = loaded_vault.get_data() {
                println!("Mnemonic: {}", data.mnemonic);
                println!("Number of Accounts: {}", data.num_accounts);
            } else {
                eprintln!("Failed to get vault data");
            }

            // Change the password
            println!("\nChanging password");
            let current_password = b"a good password";
            let new_password = b"another good new_password";
            println!("Current password: {:?}", current_password);
            println!("New password: {:?}", new_password);
            match loaded_vault.change_password(current_password, new_password) {
                Ok(_) => println!("Password changed successfully"),
                Err(e) => eprintln!("Failed to change password: {}", e),
            }

            // Lock the vault
            println!("\nLocking vault");
            loaded_vault.lock();
            println!("Vault locked");
        }
        Err(e) => eprintln!("Failed to load vault: {}", e),
    }
}
