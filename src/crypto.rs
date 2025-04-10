use sha2::{Sha256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit, Error as AesError},
    Aes256Gcm, Nonce
};
use rand::Rng;
use serde::{Serialize, Deserialize};
use std::fmt;
use std::array::TryFromSliceError;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionError(AesError),
    DecryptionError(AesError),
    SerializationError(serde_json::Error),
    DeserializationError(serde_json::Error),
    InvalidKeyLength,
    InvalidNonceLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            CryptoError::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            CryptoError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            CryptoError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidNonceLength => write!(f, "Invalid nonce length"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<AesError> for CryptoError {
    fn from(error: AesError) -> Self {
        CryptoError::EncryptionError(error)
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(error: serde_json::Error) -> Self {
        CryptoError::SerializationError(error)
    }
}

impl From<TryFromSliceError> for CryptoError {
    fn from(_: TryFromSliceError) -> Self {
        CryptoError::InvalidKeyLength
    }
}

#[derive(Debug, Clone)]
pub struct Crypto {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl Crypto {
    pub fn new(key: [u8; 32]) -> Self {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        
        Self { key, nonce }
    }

    pub fn generate_hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    pub fn encrypt<T: Serialize>(&self, data: &T) -> Result<EncryptedData, CryptoError> {
        // Serialize the data
        let serialized_data = serde_json::to_vec(data)?;
        
        // Generate hash
        let hash = self.generate_hash(&serialized_data);
        
        // Encrypt the data
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(&self.nonce);
        let encrypted_data = cipher.encrypt(nonce, serialized_data.as_ref())?;

        Ok(EncryptedData {
            hash,
            encrypted_data,
        })
    }

    pub fn decrypt<T: for<'de> Deserialize<'de>>(&self, encrypted_data: &EncryptedData) -> Result<T, CryptoError> {
        // Verify the hash
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let nonce = Nonce::from_slice(&self.nonce);
        let decrypted_data = cipher.decrypt(nonce, encrypted_data.encrypted_data.as_ref())?;

        // Deserialize the data
        let data = serde_json::from_slice(&decrypted_data)?;
        Ok(data)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub hash: String,
    pub encrypted_data: Vec<u8>,
} 