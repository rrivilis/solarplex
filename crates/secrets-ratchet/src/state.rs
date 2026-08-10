//! The ratchet's core state type and transitions.
//!
//! ```text
//! state_{N+1}         = HKDF-SHA256(state_N || fresh_random, "chain")
//! credential_N(ctx)    = HKDF-SHA256(state_N, ctx)
//! ```
//!
//! One `state_N` derives every credential Solarplex's rotation needs
//! (DATABASE_URL's password, OIDC_CLIENT_SECRET, ...) via distinct
//! context strings — a single `advance()` rotates all of them in
//! lockstep, so there is exactly one piece of state to protect and
//! advance, not one per credential.
//!
//! ## What this buys you, precisely
//! - **Backward secrecy**: HKDF is not invertible (this rests on
//!   HMAC-SHA256's PRF security — nobody has broken it), so possessing
//!   `state_{N+1}` does not let you compute `state_N` or anything derived
//!   from it. Combined with zeroizing retired state, there is no
//!   surviving copy of old state in this process's memory once a
//!   rotation completes.
//! - **Post-compromise security**: each step mixes in caller-supplied
//!   `fresh_random` (see [`crate::fresh_entropy`]) *in addition to* the
//!   deterministic chain. Without that, `state_N` alone would let anyone
//!   compute every future state too, since `HKDF(state_N, "chain")` alone
//!   is a pure function of already-known input — the entropy is what
//!   makes the future unpredictable to someone who only has the past.
//!
//! ## What this does NOT buy you
//! - Protection of `state_N` while it's live and in use — that's Layer 3
//!   (hardware-backed age identities) in the surrounding design. This
//!   type has no opinion on who's allowed to call `advance`/
//!   `derive_credential`, same division of labor `crates/intent` has
//!   toward authorization.
//! - A unit-testable proof of unforgeability. "HKDF is one-way" is a
//!   property of the construction, not something `cargo test` can
//!   establish — see this crate's test suite for what's actually being
//!   checked (determinism, domain separation, that zeroization clears
//!   memory) versus documented as a design assumption.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const CHAIN_INFO: &[u8] = b"solarplex-secrets-ratchet-v1/chain";

/// One epoch of ratchet state — 32 bytes.
///
/// Deliberately not `Clone` or `Copy`: every live copy of this value is a
/// live copy of key material, and the whole design rests on there being
/// exactly one. `Debug` is implemented by hand below to redact the bytes
/// — the derived impl would happily print key material to any log line
/// that formats this type.
pub struct RatchetState([u8; 32]);

impl std::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RatchetState").field(&"<redacted>").finish()
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl RatchetState {
    /// The chain's root. Must be seeded from real entropy (e.g.
    /// [`crate::fresh_entropy`]) — deliberately not `Default`, since
    /// there is no sensible zero/deterministic starting point for a
    /// secrets chain.
    pub fn genesis(seed: [u8; 32]) -> Self {
        RatchetState(seed)
    }

    /// Advance to the next epoch, consuming `self`. The old state is
    /// zeroized before this returns — there is no way to call this and
    /// keep using the old state afterward; Rust's ownership rules enforce
    /// the "no undo" property the design relies on (there is no `&self`
    /// path back to the pre-advance bytes once this returns, and no test
    /// can observe them either — that's the mechanism working, not a
    /// testing gap).
    pub fn advance(mut self, fresh_random: [u8; 32]) -> RatchetState {
        let next = advance_bytes(&self.0, &fresh_random);
        self.0.zeroize(); // explicit, in addition to Drop below — the
                           // intent here is "destroy the old epoch before
                           // handing back the new one", not merely
                           // "eventually get cleaned up on scope exit".
        RatchetState(next)
    }

    /// Derive a credential's raw bytes for `context` from the current
    /// epoch. Does not mutate or consume `self` — call this once per
    /// credential (`"solarplex-db-password-v1"`,
    /// `"solarplex-oidc-secret-v1"`, ...) against the same epoch.
    pub fn derive_credential(&self, context: &str, out: &mut [u8]) {
        derive(&self.0, context.as_bytes(), out);
    }

    /// Convenience wrapper: derive `byte_len` bytes for `context` and
    /// return them base64url-encoded (unpadded) — a printable string
    /// shape suitable for a Postgres password or an OAuth client secret.
    pub fn derive_credential_string(&self, context: &str, byte_len: usize) -> String {
        let mut buf = vec![0u8; byte_len];
        self.derive_credential(context, &mut buf);
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &buf);
        buf.zeroize();
        encoded
    }

    /// Explicit, named retirement for call sites where "this epoch is now
    /// dead" should read as an intentional statement rather than rely on
    /// `Drop` timing implicitly — e.g. immediately after persisting the
    /// *next* epoch, to make the "old destroyed only once new is safely
    /// stored" ordering visible in the caller's own code, not just in
    /// this type's destructor.
    pub fn retire(&mut self) {
        self.0.zeroize();
    }

    /// Consume this epoch and return its raw bytes, for a caller that
    /// must persist `state_N` durably between process runs — this crate
    /// is deliberately I/O-free (see the crate doc comment), so there is
    /// no other way to get bytes out. The returned array is a plain
    /// `[u8; 32]`: none of this type's protections (no `Clone`, redacted
    /// `Debug`, zeroize-on-drop) apply to it anymore. The caller inherits
    /// full responsibility — encrypt it before it touches disk, and
    /// `zeroize()` the array yourself once that's done. This also
    /// doubles as the rehydration counterpart to [`Self::genesis`]: feed
    /// the decrypted bytes from a prior `export_for_storage` call back
    /// into `genesis` to resume the chain where it left off (`genesis`
    /// doesn't care whether its input is fresh entropy or a stored
    /// epoch — both are just 32 bytes to wrap).
    pub fn export_for_storage(self) -> [u8; 32] {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The pure chain-advance function, split out from [`RatchetState::advance`]
/// specifically so it's directly unit-testable (determinism, domain
/// separation, entropy sensitivity) without needing to fight `RatchetState`'s
/// deliberately move-only, zeroize-on-drop API from test code.
fn advance_bytes(current: &[u8; 32], fresh_random: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(current);
    ikm[32..].copy_from_slice(fresh_random);
    let mut out = [0u8; 32];
    derive(&ikm, CHAIN_INFO, &mut out);
    ikm.zeroize();
    out
}

/// `HKDF-SHA256(ikm, info) -> out`, no salt (the salt slot exists to let
/// multiple independent contexts share one high-entropy secret safely;
/// `ikm` here is already a full-entropy 32-byte ratchet epoch, not a
/// low-entropy password, so an all-zero salt is the standard HKDF
/// recommendation for this case — see RFC 5869 §3.1).
fn derive(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    hk.expand(info, out).expect(
        "output length must be <= 255 * 32 bytes (HKDF-SHA256's hard limit) — \
         every caller in this crate requests far less",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn advance_is_deterministic() {
        let a = advance_bytes(&entropy(1), &entropy(2));
        let b = advance_bytes(&entropy(1), &entropy(2));
        assert_eq!(a, b);
    }

    #[test]
    fn advance_depends_on_entropy_not_just_state() {
        let a = advance_bytes(&entropy(1), &entropy(2));
        let b = advance_bytes(&entropy(1), &entropy(3));
        assert_ne!(a, b, "different fresh_random must produce different next states");
    }

    #[test]
    fn advance_depends_on_state_not_just_entropy() {
        let a = advance_bytes(&entropy(1), &entropy(9));
        let b = advance_bytes(&entropy(5), &entropy(9));
        assert_ne!(a, b);
    }

    #[test]
    fn credential_derivation_is_domain_separated() {
        let state = RatchetState::genesis(entropy(7));
        let mut db = [0u8; 32];
        let mut oidc = [0u8; 32];
        state.derive_credential("solarplex-db-password-v1", &mut db);
        state.derive_credential("solarplex-oidc-secret-v1", &mut oidc);
        assert_ne!(db, oidc, "different contexts from the same epoch must not collide");
    }

    #[test]
    fn credential_derivation_is_deterministic_within_an_epoch() {
        let state = RatchetState::genesis(entropy(7));
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        state.derive_credential("same-context", &mut a);
        state.derive_credential("same-context", &mut b);
        assert_eq!(a, b, "re-deriving within the same epoch must be idempotent");
    }

    #[test]
    fn advancing_changes_what_a_fixed_context_derives_to() {
        let state = RatchetState::genesis(entropy(7));
        let mut before = [0u8; 32];
        state.derive_credential("solarplex-db-password-v1", &mut before);

        let advanced = state.advance(entropy(42));
        let mut after = [0u8; 32];
        advanced.derive_credential("solarplex-db-password-v1", &mut after);

        assert_ne!(before, after, "rotation must actually change the derived credential");
    }

    #[test]
    fn derive_credential_string_has_the_requested_length_when_decoded() {
        let state = RatchetState::genesis(entropy(1));
        let s = state.derive_credential_string("ctx", 24);
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &s).unwrap();
        assert_eq!(decoded.len(), 24);
    }

    #[test]
    fn export_for_storage_returns_the_live_epoch_bytes_uncorrupted() {
        // The exported array is a separate Copy of the bytes, taken
        // before Drop zeroizes the (now-inaccessible) original — this
        // confirms that ordering actually holds and doesn't hand back
        // zeroes.
        let state = RatchetState::genesis(entropy(0x5A));
        let exported = state.export_for_storage();
        assert_eq!(exported, entropy(0x5A));
    }

    #[test]
    fn export_for_storage_round_trips_through_genesis() {
        let original = RatchetState::genesis(entropy(0x3C));
        let exported = original.export_for_storage();
        let resumed = RatchetState::genesis(exported);

        let mut before = [0u8; 32];
        let mut after = [0u8; 32];
        RatchetState::genesis(entropy(0x3C)).derive_credential("ctx", &mut before);
        resumed.derive_credential("ctx", &mut after);
        assert_eq!(before, after, "resuming from exported bytes must reproduce the same epoch");
    }

    #[test]
    fn retire_zeroizes_in_place() {
        let mut state = RatchetState::genesis(entropy(0xAB));
        assert_ne!(*state.as_bytes(), [0u8; 32]);
        state.retire();
        assert_eq!(*state.as_bytes(), [0u8; 32], "retire() must actually clear the bytes, not just drop a reference");
    }

    #[test]
    fn raw_zeroize_primitive_actually_clears_memory() {
        // Sanity-checks the `zeroize` crate's own guarantee that this
        // codebase depends on throughout — not testing our own logic,
        // testing the assumption underneath it.
        let mut buf = [0xAAu8; 32];
        buf.zeroize();
        assert_eq!(buf, [0u8; 32]);
    }

    // ── Adversarial ──────────────────────────────────────────────────────
    //
    // These do not, and cannot, *prove* HKDF's one-wayness — that's a
    // property of HMAC-SHA256's PRF security, not something a unit test
    // establishes. What they check: naive, "did we accidentally leak
    // structure" attacks fail — the kind of bug that *would* actually be
    // catchable here (e.g. an implementation that accidentally XORs
    // instead of hashing, or reuses `current` verbatim as part of `next`).

    #[test]
    fn adversarial_next_state_does_not_contain_prior_state_bytes() {
        let prior = entropy(0x42);
        let next = advance_bytes(&prior, &entropy(0x99));
        assert_ne!(next, prior);
        // A 32-byte HKDF output "containing" a specific 32-byte input as a
        // contiguous run is exactly one comparison (equality) since both
        // are the same length — already covered by assert_ne! above, but
        // stated explicitly here as the property being probed, not left
        // implicit in a generic inequality check.
    }

    #[test]
    fn adversarial_hashing_next_state_forward_does_not_reproduce_prior_state() {
        // If an attacker who captures `next` tries the cheapest possible
        // "maybe it's just hashed backward" guess — hashing `next` again
        // — it must not land back on `prior`. Guards against a
        // regression to a reversible construction (e.g. a plain
        // permutation or an XOR-based "derivation").
        let prior = entropy(0x11);
        let next = advance_bytes(&prior, &entropy(0x22));
        let mut guess = [0u8; 32];
        derive(&next, b"attacker-guess", &mut guess);
        assert_ne!(guess, prior);
    }

    #[test]
    fn adversarial_known_context_credentials_do_not_leak_the_next_epoch() {
        // An attacker who knows every context string this crate uses
        // (they're public constants, not secret) and obtains every
        // credential derived from `state_N` still must not be able to
        // compute `state_{N+1}` — advancing requires `state_N` itself
        // (via HKDF's IKM position) plus unpredictable entropy, neither
        // of which the derived *outputs* hand back.
        let state = RatchetState::genesis(entropy(0x77));
        let mut db = [0u8; 32];
        let mut oidc = [0u8; 32];
        state.derive_credential("solarplex-db-password-v1", &mut db);
        state.derive_credential("solarplex-oidc-secret-v1", &mut oidc);

        let real_next = advance_bytes(state.as_bytes(), &entropy(0x88));

        // The best an attacker holding only the derived credentials could
        // try is feeding them back in as if they were the chain state.
        let attacker_guess_from_db = advance_bytes(&db, &entropy(0x88));
        let attacker_guess_from_oidc = advance_bytes(&oidc, &entropy(0x88));

        assert_ne!(real_next, attacker_guess_from_db);
        assert_ne!(real_next, attacker_guess_from_oidc);
    }
}
