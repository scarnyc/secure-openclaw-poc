use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Holds decrypted credential JSON bytes. Zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureCredential {
    raw: Vec<u8>,
}

impl SecureCredential {
    pub fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }

    /// Parse the raw bytes as JSON and extract a field value.
    /// Returns a SecureString that will be zeroed on drop.
    pub fn get_field(&self, field: &str) -> Result<SecureString, CryptoError> {
        let parsed: serde_json::Value =
            serde_json::from_slice(&self.raw).map_err(|e| CryptoError::ParseError(e.to_string()))?;

        let value = parsed
            .get(field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| CryptoError::FieldNotFound(field.to_string()))?;

        Ok(SecureString::new(value.to_string()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// Holds a single credential field value. Zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }
}
