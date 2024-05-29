use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, RngCore, SeedableRng};

// Encrypts the given plaintext using the provided key.
pub fn encrypt_aes_gcm(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8; 12],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    let encrypted_data = cipher.encrypt(&nonce, plaintext).unwrap();

    Ok((encrypted_data, nonce.to_vec()))
}

// Decrypts the given encrypted data using the provided key and nonce.
pub fn decrypt_aes_gcm(key: &[u8], ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed"))
        .expect("Decryption failed");

    Ok(decrypted_data)
}

pub fn pbkdf2_hash(password: &[u8], salt: &[u8], iterations: u32, size: usize) -> Result<Vec<u8>> {
    let mut key = vec![0u8; size];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, salt, iterations, key.as_mut_slice())?;
    Ok(key)
}

pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut rng = StdRng::from_entropy();
    let mut buf = vec![0u8; size];
    rng.fill_bytes(&mut buf);
    buf
}
