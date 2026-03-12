#![deny(clippy::all)]

mod credential;
mod decrypt;
mod error;
mod spawn;
mod vault_io;

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use zeroize::Zeroize;

/// Derive an encryption key from a master password and base64-encoded salt.
/// Uses PBKDF2-SHA512 with 600,000 iterations, producing a 32-byte key.
/// Returns the derived key as a Buffer.
#[napi]
pub fn derive_key_native(password: String, salt_b64: String) -> Result<Buffer> {
    let salt = BASE64
        .decode(&salt_b64)
        .map_err(|_| Error::from_reason("Invalid base64 salt"))?;
    let key = decrypt::derive_key(password.as_bytes(), &salt);
    Ok(Buffer::from(key))
}

/// Decrypt a credential from the vault. Returns the raw credential bytes as a Buffer.
/// The Buffer should be used in a callback scope and then filled with zeros.
/// All Rust memory is zeroed via ZeroizeOnDrop when this function returns.
///
/// Parameters:
/// - vault_path: Absolute path to the vault.enc JSON file
/// - derived_key: 32-byte key from derive_key_native() as Buffer
/// - service_id: The service identifier to decrypt (e.g. "anthropic", "openai")
#[napi]
pub fn use_credential_native(
    vault_path: String,
    derived_key: Buffer,
    service_id: String,
) -> Result<Buffer> {
    let credential =
        vault_io::decrypt_service(&vault_path, derived_key.as_ref(), &service_id)?;

    // Copy credential bytes to a Vec for the Buffer, then credential is dropped (zeroed)
    let mut bytes = credential.as_bytes().to_vec();
    let result = Buffer::from(bytes.clone());
    bytes.zeroize();
    // credential is dropped here, raw bytes zeroed by ZeroizeOnDrop

    Ok(result)
}

/// Decrypt a credential and extract a single field value.
/// Returns the field value as a string. The full credential is zeroed after extraction.
///
/// This is useful when you only need one field (e.g. "apiKey") and want to avoid
/// parsing JSON in JavaScript (which creates V8 strings for all fields).
#[napi]
pub fn get_credential_field_native(
    vault_path: String,
    derived_key: Buffer,
    service_id: String,
    field: String,
) -> Result<String> {
    let credential =
        vault_io::decrypt_service(&vault_path, derived_key.as_ref(), &service_id)?;

    let secure_string = credential.get_field(&field)?;
    let value = secure_string.as_str().to_string();
    // credential and secure_string are both dropped here, zeroed by ZeroizeOnDrop

    Ok(value)
}

#[napi(object)]
pub struct JsSpawnResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Spawn a subprocess with a vault credential injected as an env var.
/// Credential NEVER enters JavaScript — decrypted in Rust, set as env var, zeroed after.
#[napi]
pub fn spawn_with_credential(
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    env_var_name: String,
    vault_path: String,
    derived_key: Buffer,
    service_id: String,
    credential_field: String,
    timeout_ms: Option<u32>,
) -> Result<JsSpawnResult> {
    let result = spawn::spawn_with_credential(
        &command,
        &args,
        &env,
        &env_var_name,
        &vault_path,
        derived_key.as_ref(),
        &service_id,
        &credential_field,
        timeout_ms.map(|ms| ms as u64),
    )?;

    Ok(JsSpawnResult {
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
    })
}
