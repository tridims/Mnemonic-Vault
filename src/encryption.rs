use crate::crypto::{decrypt_speck_cbc, encrypt_speck_cbc, generate_random_bytes, pbkdf2_hash};
use serde::{Deserialize, Serialize};

const DEFAULT_KEY_SIZE: usize = 32; // 256 bits
const DEFAULT_SALT_SIZE: usize = 32;
const DEFAULT_ITERATIONS: u32 = 10_000;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedData {
    data: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    key_algorithm: String,
    key_iterations: u32,
}

#[derive(Debug)]
pub struct Encryption {
    _key: Vec<u8>,
    _salt: Vec<u8>,
}

impl Encryption {
    pub fn new_random(key: Vec<u8>) -> Self {
        let salt = generate_random_bytes(DEFAULT_SALT_SIZE);
        let hashed_key = pbkdf2_hash(&key, &salt, DEFAULT_ITERATIONS, DEFAULT_KEY_SIZE).unwrap();

        Encryption {
            _key: hashed_key,
            _salt: salt,
        }
    }

    pub fn new(key: Vec<u8>, salt: Vec<u8>) -> Self {
        let hashed_key = pbkdf2_hash(&key, &salt, DEFAULT_ITERATIONS, DEFAULT_KEY_SIZE).unwrap();
        Encryption {
            _key: hashed_key,
            _salt: salt,
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> EncryptedData {
        let (encrypted_data, iv) =
            encrypt_speck_cbc(&self._key.as_slice().try_into().unwrap(), data).unwrap();

        EncryptedData {
            data: encrypted_data,
            iv,
            salt: self._salt.clone(),
            key_algorithm: "AES256GCM".to_string(),
            key_iterations: DEFAULT_ITERATIONS,
        }
    }

    pub fn new_and_decrypt(key: Vec<u8>, encrypted_data: &EncryptedData) -> (Self, Vec<u8>) {
        let me = Self::new(key, encrypted_data.salt.clone());
        let res = decrypt_speck_cbc(
            &me._key.as_slice().try_into().unwrap(),
            &encrypted_data.data,
            encrypted_data.iv.as_slice().try_into().unwrap(),
        )
        .unwrap();

        (me, res)
    }
}
