use anyhow::Result;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use speck_cipher::{speck_cbc_decrypt, speck_cbc_encrypt};

// Encrypts the given plaintext using the provided key.
pub fn encrypt_speck_cbc(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let iv = generate_random_bytes(16);
    let encrypted_data = speck_cbc_encrypt(key, &iv.as_slice().try_into().unwrap(), plaintext);
    Ok((encrypted_data, iv.to_vec()))
}

// Decrypts the given encrypted data using the provided key and IV.
pub fn decrypt_speck_cbc(key: &[u8; 32], encrypted_data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let decrypted_data = speck_cbc_decrypt(key, iv, encrypted_data);
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
