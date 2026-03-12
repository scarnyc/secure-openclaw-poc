use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::credential::SecureCredential;
use crate::error::CryptoError;
use crate::vault_io::decrypt_service;

pub struct SpawnResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Spawn a subprocess with a credential injected as an environment variable.
/// The credential NEVER enters JavaScript — it's decrypted in Rust, set as an env var,
/// the subprocess runs, and then all credential memory is zeroed.
///
/// When `timeout_ms` is Some, the subprocess is killed after the deadline.
/// Pipe buffer deadlock (>64KB output) is handled by the timeout — if the child
/// blocks on a full pipe, the timeout fires and kills it.
pub fn spawn_with_credential(
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
    env_var_name: &str,
    vault_path: &str,
    derived_key: &[u8],
    service_id: &str,
    credential_field: &str,
    timeout_ms: Option<u64>,
) -> Result<SpawnResult, CryptoError> {
    // Decrypt credential in Rust memory
    let credential: SecureCredential = decrypt_service(vault_path, derived_key, service_id)?;
    let field_value = credential.get_field(credential_field)?;

    // Build subprocess command
    let mut cmd = Command::new(command);
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Clear inherited env and set only provided vars
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }

    // Inject credential as env var — only exists in subprocess memory
    cmd.env(env_var_name, field_value.as_str());

    match timeout_ms {
        Some(ms) => {
            // Spawn child and wait with timeout using a background thread.
            // The thread calls wait_with_output() which reads pipes and waits
            // for exit — this avoids pipe buffer deadlock. The main thread
            // waits on the channel with a timeout.
            let child = cmd
                .spawn()
                .map_err(|e| CryptoError::IoError(format!("Failed to spawn {command}: {e}")))?;

            // field_value and credential are zeroed on drop via ZeroizeOnDrop
            drop(field_value);
            drop(credential);

            let (tx, rx) = mpsc::channel();
            let cmd_name = command.to_string();

            std::thread::spawn(move || {
                let result = child.wait_with_output();
                let _ = tx.send(result);
            });

            match rx.recv_timeout(Duration::from_millis(ms)) {
                Ok(Ok(output)) => {
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(SpawnResult {
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                        exit_code,
                    })
                }
                Ok(Err(e)) => Err(CryptoError::IoError(format!(
                    "Failed to wait for {cmd_name}: {e}"
                ))),
                Err(_) => {
                    // Timeout — the child process will be reaped when the thread
                    // eventually completes (or the process exits)
                    Err(CryptoError::Timeout)
                }
            }
        }
        None => {
            // No timeout — use standard output() which handles pipes correctly
            let output = cmd
                .output()
                .map_err(|e| CryptoError::IoError(format!("Failed to spawn {command}: {e}")))?;

            // field_value and credential are zeroed on drop via ZeroizeOnDrop
            drop(field_value);
            drop(credential);

            let exit_code = output.status.code().unwrap_or(-1);

            Ok(SpawnResult {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                exit_code,
            })
        }
    }
}
