//! Layer 2 (storage) + Layer 3 (access) of Solarplex's secrets design:
//! multi-recipient `age` encryption of the credential bundle that
//! `secrets-ratchet` rotates, and recipient/identity string parsing.
//!
//! Deliberately agnostic to *what* backs an identity — a software
//! X25519 key in a test, or a hardware-backed age plugin (YubiKey, TPM)
//! in production — since both implement the same `age::Recipient` /
//! `age::Identity` traits and this crate's encrypt/decrypt functions are
//! written against those traits, not a concrete key type. This crate
//! never constructs or holds a decryption identity beyond the duration
//! of a single [`decrypt_bundle`] call, and never touches disk itself —
//! callers own all file I/O (see `secrets-cli` for the operational
//! wrapper that does).

mod bundle;
mod error;
mod store;

pub use bundle::CredentialBundle;
pub use error::StoreError;
pub use store::{
    decrypt_bundle, decrypt_bytes, encrypt_bundle, encrypt_bytes, parse_identity, parse_recipient,
};
