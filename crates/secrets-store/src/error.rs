use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("no recipients given — refusing to encrypt to nobody")]
    NoRecipients,
    #[error("failed to parse age recipient string: {0}")]
    ParseRecipient(String),
    #[error("failed to parse age identity string: {0}")]
    ParseIdentity(String),
    #[error("age encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
    #[error("age decryption failed: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("credential bundle is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error while (de)serializing the age envelope: {0}")]
    Io(#[from] std::io::Error),
}
