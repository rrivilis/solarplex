use std::io::{Read, Write};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::{Decryptor, Encryptor, Identity, Recipient};
use zeroize::Zeroize;

use crate::{bundle::CredentialBundle, error::StoreError};

/// Parse an age recipient from its standard `age1...` string form.
///
/// Only the software/hardware X25519 form is implemented directly here.
/// Hardware plugin recipients (`age1yubikey1...`, `age1tpm1...`) parse to
/// a different concrete type in the `age` crate's own plugin support and
/// are constructed by the deploy tooling that has the plugin binary
/// available — this function is the software-identity and recovery-key
/// path, which is the same X25519 form regardless of whether the private
/// half lives in a file or a plugin.
pub fn parse_recipient(s: &str) -> Result<age::x25519::Recipient, StoreError> {
    s.parse::<age::x25519::Recipient>()
        .map_err(|e| StoreError::ParseRecipient(e.to_string()))
}

/// Parse an age identity from its standard `AGE-SECRET-KEY-1...` string
/// form. See [`parse_recipient`] for why this is the X25519-only half of
/// the story.
pub fn parse_identity(s: &str) -> Result<age::x25519::Identity, StoreError> {
    s.parse::<age::x25519::Identity>()
        .map_err(|e| StoreError::ParseIdentity(e.to_string()))
}

/// Encrypt raw `plaintext` to every recipient in `recipients`,
/// ASCII-armored so the result is safe to commit to git.
///
/// Takes trait objects rather than a concrete key type specifically so
/// hardware-backed (plugin) recipients work here unmodified alongside
/// software X25519 ones — this function has no idea, and does not need
/// to know, which kind of recipient it's holding. This is the whole
/// point of Layer 3 in the surrounding design: swapping a software
/// identity for a hardware one is a config change at the call site, not
/// a code change here.
///
/// This is the primitive both [`encrypt_bundle`] (JSON credential
/// bundles) and the ratchet's own state persistence (raw 32-byte
/// epochs — see `secrets-cli`) encrypt through; neither is privileged
/// over the other, they just serialize different plaintexts.
pub fn encrypt_bytes(plaintext: &[u8], recipients: &[&dyn Recipient]) -> Result<String, StoreError> {
    if recipients.is_empty() {
        return Err(StoreError::NoRecipients);
    }

    let encryptor =
        Encryptor::with_recipients(recipients.iter().copied()).map_err(StoreError::Encrypt)?;

    let mut armored_out = Vec::new();
    let armor = ArmoredWriter::wrap_output(&mut armored_out, Format::AsciiArmor)?;
    let mut writer = encryptor.wrap_output(armor)?;
    writer.write_all(plaintext)?;
    let armor = writer.finish()?;
    armor.finish()?;

    Ok(String::from_utf8(armored_out).expect("age ASCII armor output is always valid UTF-8"))
}

/// Decrypt an ASCII-armored blob against a single identity, returning
/// the raw plaintext bytes. See [`encrypt_bytes`] for why this is
/// separate from the JSON-bundle-specific [`decrypt_bundle`].
pub fn decrypt_bytes(armored: &str, identity: &dyn Identity) -> Result<Vec<u8>, StoreError> {
    let reader = ArmoredReader::new(armored.as_bytes());
    let decryptor = Decryptor::new(reader).map_err(StoreError::Decrypt)?;

    let mut stream = decryptor
        .decrypt(std::iter::once(identity))
        .map_err(StoreError::Decrypt)?;

    let mut plaintext = Vec::new();
    stream.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

/// Encrypt `bundle` to every recipient in `recipients`, ASCII-armored so
/// the result is safe to commit to git as `secrets.age`. See
/// [`encrypt_bytes`] for the underlying primitive.
pub fn encrypt_bundle(
    bundle: &CredentialBundle,
    recipients: &[&dyn Recipient],
) -> Result<String, StoreError> {
    let mut plaintext = serde_json::to_vec(bundle)?;
    let result = encrypt_bytes(&plaintext, recipients);
    plaintext.zeroize();
    result
}

/// Decrypt an ASCII-armored `secrets.age` blob against a single identity.
///
/// `identity` is a trait object for the same reason `encrypt_bundle`
/// takes trait-object recipients — in production this is a hardware
/// plugin identity that never has a plaintext key file behind it at all;
/// in tests it's a software `age::x25519::Identity`.
pub fn decrypt_bundle(
    armored: &str,
    identity: &dyn Identity,
) -> Result<CredentialBundle, StoreError> {
    let mut plaintext = decrypt_bytes(armored, identity)?;
    let result = serde_json::from_slice(&plaintext).map_err(StoreError::Json);
    plaintext.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    fn sample_bundle() -> CredentialBundle {
        CredentialBundle {
            database_url: "postgres://solarplex:hunter2@localhost/solarplex".to_string(),
            oidc_client_id: "solarplex-prod".to_string(),
            oidc_client_secret: "super-secret-oidc-value".to_string(),
        }
    }

    #[test]
    fn raw_bytes_round_trip_through_encrypt_decrypt_bytes() {
        // The primitive `encrypt_bundle`/`decrypt_bundle` are built on —
        // this is what secrets-cli uses directly for the ratchet's own
        // 32-byte state, which isn't JSON at all.
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let payload = [0x42u8; 32];

        let armored = encrypt_bytes(&payload, &[&recipient as &dyn Recipient]).unwrap();
        let decrypted = decrypt_bytes(&armored, &identity as &dyn Identity).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn round_trips_through_a_single_recipient() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();

        let armored =
            encrypt_bundle(&sample_bundle(), &[&recipient as &dyn Recipient]).unwrap();
        let decrypted = decrypt_bundle(&armored, &identity as &dyn Identity).unwrap();

        assert_eq!(decrypted.database_url, "postgres://solarplex:hunter2@localhost/solarplex");
        assert_eq!(decrypted.oidc_client_id, "solarplex-prod");
        assert_eq!(decrypted.oidc_client_secret, "super-secret-oidc-value");
    }

    #[test]
    fn armored_output_looks_like_age_armor() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let armored =
            encrypt_bundle(&sample_bundle(), &[&recipient as &dyn Recipient]).unwrap();
        assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert!(armored.trim_end().ends_with("-----END AGE ENCRYPTED FILE-----"));
    }

    #[test]
    fn each_of_multiple_recipients_can_independently_decrypt() {
        // Models the real design: operator key + recovery key both
        // encrypted to, either alone sufficient to recover the bundle.
        let operator = age::x25519::Identity::generate();
        let recovery = age::x25519::Identity::generate();
        let recipients: Vec<age::x25519::Recipient> =
            vec![operator.to_public(), recovery.to_public()];
        let recipient_refs: Vec<&dyn Recipient> =
            recipients.iter().map(|r| r as &dyn Recipient).collect();

        let armored = encrypt_bundle(&sample_bundle(), &recipient_refs).unwrap();

        let via_operator = decrypt_bundle(&armored, &operator as &dyn Identity).unwrap();
        let via_recovery = decrypt_bundle(&armored, &recovery as &dyn Identity).unwrap();
        assert_eq!(via_operator.oidc_client_secret, via_recovery.oidc_client_secret);
    }

    #[test]
    fn empty_recipients_list_errors_before_touching_age() {
        let err = encrypt_bundle(&sample_bundle(), &[]).unwrap_err();
        assert!(matches!(err, StoreError::NoRecipients));
    }

    #[test]
    fn recipient_and_identity_strings_round_trip_through_parsing() {
        let identity = age::x25519::Identity::generate();
        let recipient_str = identity.to_public().to_string();
        let identity_str = identity.to_string();

        let parsed_recipient = parse_recipient(&recipient_str).unwrap();
        let parsed_identity =
            parse_identity(identity_str.expose_secret()).unwrap();

        let armored = encrypt_bundle(
            &sample_bundle(),
            &[&parsed_recipient as &dyn Recipient],
        )
        .unwrap();
        let decrypted = decrypt_bundle(&armored, &parsed_identity as &dyn Identity).unwrap();
        assert_eq!(decrypted.oidc_client_secret, "super-secret-oidc-value");
    }

    // ── Adversarial ──────────────────────────────────────────────────────

    #[test]
    fn adversarial_wrong_identity_cannot_decrypt() {
        let real_recipient_identity = age::x25519::Identity::generate();
        let attacker_identity = age::x25519::Identity::generate();
        let recipient = real_recipient_identity.to_public();

        let armored =
            encrypt_bundle(&sample_bundle(), &[&recipient as &dyn Recipient]).unwrap();

        let result = decrypt_bundle(&armored, &attacker_identity as &dyn Identity);
        assert!(
            result.is_err(),
            "an identity that was never a recipient must not be able to decrypt"
        );
    }

    #[test]
    fn adversarial_tampered_payload_bytes_are_rejected() {
        // Flip a byte inside the base64 payload region (skip the armor
        // header/footer lines) and confirm age's AEAD tag rejects it
        // rather than silently returning corrupted plaintext.
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let armored =
            encrypt_bundle(&sample_bundle(), &[&recipient as &dyn Recipient]).unwrap();

        let mut lines: Vec<String> = armored.lines().map(|l| l.to_string()).collect();
        let payload_line_idx = lines
            .iter()
            .position(|l| !l.starts_with("-----"))
            .expect("armor must have at least one payload line");
        let mut chars: Vec<char> = lines[payload_line_idx].chars().collect();
        assert!(!chars.is_empty(), "payload line must not be empty");
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        lines[payload_line_idx] = chars.into_iter().collect();
        let tampered = lines.join("\n");

        let result = decrypt_bundle(&tampered, &identity as &dyn Identity);
        assert!(result.is_err(), "tampered ciphertext must be rejected, not silently decrypted");
    }

    #[test]
    fn adversarial_truncated_ciphertext_is_rejected() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let armored =
            encrypt_bundle(&sample_bundle(), &[&recipient as &dyn Recipient]).unwrap();

        let truncated = &armored[..armored.len() * 2 / 3];
        let result = decrypt_bundle(truncated, &identity as &dyn Identity);
        assert!(result.is_err(), "a truncated file must not decrypt");
    }

    #[test]
    fn adversarial_garbage_input_is_rejected_not_panicking() {
        let identity = age::x25519::Identity::generate();
        let result = decrypt_bundle("not an age file at all", &identity as &dyn Identity);
        assert!(result.is_err());
    }

    #[test]
    fn adversarial_recipient_not_in_the_list_cannot_read_a_multi_recipient_blob() {
        let a = age::x25519::Identity::generate();
        let b = age::x25519::Identity::generate();
        let outsider = age::x25519::Identity::generate();
        let recipients: Vec<age::x25519::Recipient> = vec![a.to_public(), b.to_public()];
        let recipient_refs: Vec<&dyn Recipient> =
            recipients.iter().map(|r| r as &dyn Recipient).collect();

        let armored = encrypt_bundle(&sample_bundle(), &recipient_refs).unwrap();
        let result = decrypt_bundle(&armored, &outsider as &dyn Identity);
        assert!(result.is_err(), "being absent from the recipient list must be enforced, not just typical");
    }
}
