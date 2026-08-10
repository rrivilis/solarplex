//! Entropy source for [`crate::RatchetState::advance`]'s `fresh_random`
//! input.
//!
//! Deliberately not an ordinary CSPRNG. If the RNG's own internal state
//! were later compromised, an ordinary CSPRNG can't tell you whether it's
//! safe to reveal what it output in the past — that's exactly the gap a
//! fast-key-erasure RNG closes: `fast_erasure_shake_rng` is a Keccak-f
//! sponge/duplex construction that zeroizes its own capacity area after
//! every output, specifically so that a later compromise of *this*
//! process's memory can't be used to reverse-derive what randomness it
//! handed out earlier. Without that property here, `state_N`'s
//! `fresh_random` input could in principle be recovered even after the
//! ratchet itself has moved on and zeroized `state_N` — quietly
//! undermining the backward secrecy the ratchet exists to provide.
//!
//! One `RngState` per call, seeded fresh from the OS CSPRNG
//! (`getrandom`) — this module holds no long-lived RNG instance to
//! protect; each call is a self-contained generate-then-drop unit, and
//! `RngState`'s own `Drop` handles clearing its internal state.

use fast_erasure_shake_rng::RngState;

/// 32 bytes of fresh randomness for one ratchet advance.
///
/// # Panics
/// If the OS CSPRNG is unavailable (`getrandom` failure) — this is not a
/// condition worth trying to recover from: proceeding with a
/// non-cryptographic fallback would silently defeat the entire point of
/// this module.
pub fn fresh_entropy() -> [u8; 32] {
    let mut rng = RngState::new_from_getrandom()
        .expect("OS CSPRNG (getrandom) unavailable — cannot safely generate ratchet entropy");
    rng.get_random_bytes::<32>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_calls_produce_different_output() {
        // Not a proof of randomness (nothing short of a statistical test
        // suite would be), just a smoke test that this isn't accidentally
        // wired to something deterministic.
        assert_ne!(fresh_entropy(), fresh_entropy());
    }

    #[test]
    fn output_is_not_all_zero() {
        assert_ne!(fresh_entropy(), [0u8; 32]);
    }
}
