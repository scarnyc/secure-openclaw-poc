use napi::Error as NapiError;

#[derive(Debug)]
pub enum CryptoError {
    InvalidBase64(&'static str),
    InvalidKeyLength,
    DecryptionFailed,
    InvalidPassword,
    ServiceNotFound(String),
    IoError(String),
    ParseError(String),
    UnsupportedVersion(u32),
    FieldNotFound(String),
    Timeout,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBase64(field) => write!(f, "Invalid base64 in {field}"),
            Self::InvalidKeyLength => write!(f, "Invalid key length"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::InvalidPassword => write!(f, "Invalid vault password"),
            Self::ServiceNotFound(id) => write!(f, "Service not found: {id}"),
            Self::IoError(e) => write!(f, "IO error: {e}"),
            Self::ParseError(e) => write!(f, "Parse error: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported vault version: {v}"),
            Self::FieldNotFound(f_name) => write!(f, "Field not found: {f_name}"),
            Self::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl From<CryptoError> for NapiError {
    fn from(e: CryptoError) -> Self {
        NapiError::from_reason(e.to_string())
    }
}
