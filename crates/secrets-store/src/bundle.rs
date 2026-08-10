//! The plaintext shape that gets encrypted into `secrets.age`.
//!
//! Mirrors Layer 1's complete secret inventory exactly: `DATABASE_URL`,
//! `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` — nothing else. `OIDC_CLIENT_ID`
//! isn't secret material (OAuth client IDs are public-ish by design and
//! don't rotate through `secrets-ratchet`), but it travels in the same
//! bundle since it still needs to reach every host alongside the two
//! that are secret.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct CredentialBundle {
    pub database_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
}

impl Drop for CredentialBundle {
    fn drop(&mut self) {
        self.database_url.zeroize();
        self.oidc_client_id.zeroize();
        self.oidc_client_secret.zeroize();
    }
}
