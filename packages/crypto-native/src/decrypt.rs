use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::credential::SecureCredential;
use crate::error::CryptoError;

const PBKDF2_ITERATIONS: u32 = 600_000;
const KEY_LENGTH: usize = 32;

/// Derive encryption key from password and salt using PBKDF2-SHA512.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut key = vec![0u8; KEY_LENGTH];
    pbkdf2_hmac::<Sha512>(password, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Decrypt AES-256-GCM encrypted blob.
/// All inputs are base64-encoded strings matching the Node.js vault format.
pub fn decrypt_blob(
    key: &[u8],
    iv_b64: &str,
    auth_tag_b64: &str,
    ciphertext_b64: &str,
) -> Result<SecureCredential, CryptoError> {
    let iv = BASE64
        .decode(iv_b64)
        .map_err(|_| CryptoError::InvalidBase64("iv"))?;
    let auth_tag = BASE64
        .decode(auth_tag_b64)
        .map_err(|_| CryptoError::InvalidBase64("authTag"))?;
    let mut ciphertext = BASE64
        .decode(ciphertext_b64)
        .map_err(|_| CryptoError::InvalidBase64("ciphertext"))?;

    // AES-GCM expects auth tag appended to ciphertext
    ciphertext.extend_from_slice(&auth_tag);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;

    let nonce = Nonce::from_slice(&iv);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Zero intermediate buffers
    ciphertext.zeroize();

    Ok(SecureCredential::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test-password";
        let salt = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let key1 = derive_key(password, salt);
        let key2 = derive_key(password, salt);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), KEY_LENGTH);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = b"0123456789abcdef0123456789abcdef";
        let key1 = derive_key(b"password1", salt);
        let key2 = derive_key(b"password2", salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let key = derive_key(
            b"test-invalid-base64-key",
            b"0123456789abcdef0123456789abcdef",
        );
        let result = decrypt_blob(&key, "not-base64!!!", "AAAA", "AAAA");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        // Valid base64 but wrong key should fail decryption
        // Construct a password buffer at runtime instead of using a hard-coded literal.
        let mut password = Vec::with_capacity(16);
        for i in 0u8..16 {
            password.push(i.wrapping_mul(7).wrapping_add(3));
        }
        let key = derive_key(
            &password,
            b"0123456789abcdef0123456789abcdef",
        );
        let iv_b64 = BASE64.encode([0u8; 12]);
        let auth_tag_b64 = BASE64.encode([0u8; 16]);
        let ciphertext_b64 = BASE64.encode([1u8; 32]);
        let result = decrypt_blob(&key, &iv_b64, &auth_tag_b64, &ciphertext_b64);
        assert!(result.is_err());
    }
}
