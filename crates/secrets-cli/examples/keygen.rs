//! Generate one standalone age identity/recipient pair — the tool an
//! operator runs once to mint the offline recovery key (Layer 3's one
//! deliberate software-key exception; every other identity is hardware-
//! backed and never has a plaintext form to generate here). Also handy
//! for generating disposable test identities when exercising `secrets-cli`
//! by hand. Run with `cargo run --example keygen -p secrets-cli`.

use age::secrecy::ExposeSecret;

fn main() {
    let identity = age::x25519::Identity::generate();
    println!(
        "# Store the secret key offline (e.g. printed, safe/HSM) — never on a networked host."
    );
    println!("AGE_IDENTITY={}", identity.to_string().expose_secret());
    println!("# Safe to keep alongside other recipients in deploy config.");
    println!("AGE_RECIPIENT={}", identity.to_public());
}
