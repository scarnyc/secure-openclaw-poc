use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

use crate::credential::SecureCredential;
use crate::decrypt::decrypt_blob;
use crate::error::CryptoError;

#[derive(Deserialize)]
struct EncryptedBlob {
    iv: String,
    #[serde(rename = "authTag")]
    auth_tag: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct VaultEntry {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    entry_type: String,
    data: EncryptedBlob,
    #[allow(dead_code)]
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Deserialize)]
struct VaultFile {
    version: u32,
    #[allow(dead_code)]
    salt: String,
    verifier: EncryptedBlob,
    entries: HashMap<String, VaultEntry>,
}

const VERIFIER_PLAINTEXT: &[u8] = b"sentinel-vault-v1";

/// Open vault, verify password, decrypt a specific service entry.
pub fn decrypt_service(
    vault_path: &str,
    derived_key: &[u8],
    service_id: &str,
) -> Result<SecureCredential, CryptoError> {
    let content =
        fs::read_to_string(vault_path).map_err(|e| CryptoError::IoError(e.to_string()))?;

    let vault: VaultFile =
        serde_json::from_str(&content).map_err(|e| CryptoError::ParseError(e.to_string()))?;

    if vault.version != 1 {
        return Err(CryptoError::UnsupportedVersion(vault.version));
    }

    // Verify password by decrypting verifier
    let verifier = decrypt_blob(
        derived_key,
        &vault.verifier.iv,
        &vault.verifier.auth_tag,
        &vault.verifier.ciphertext,
    )?;

    if verifier.as_bytes() != VERIFIER_PLAINTEXT {
        return Err(CryptoError::InvalidPassword);
    }
    // verifier is dropped here, zeroed by ZeroizeOnDrop

    // Find and decrypt the requested entry
    let entry = vault
        .entries
        .get(service_id)
        .ok_or_else(|| CryptoError::ServiceNotFound(service_id.to_string()))?;

    decrypt_blob(
        derived_key,
        &entry.data.iv,
        &entry.data.auth_tag,
        &entry.data.ciphertext,
    )
}
