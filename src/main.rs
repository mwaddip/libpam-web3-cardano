//! Cardano verification plugin for libpam-web3.
//!
//! Implements the plugin protocol: reads JSON from stdin, verifies the
//! CIP-30 COSE_Sign1 signature, derives the Cardano address from the
//! Ed25519 public key, and prints it to stdout.
//!
//! # Protocol
//!
//! stdin:  {"sig": {chain, signature, public_key, otp, machine_id}, "otp_message": "..."}
//! stdout: bech32 Cardano address (on success)
//! exit:   0 = verified, 1 = denied
//!
//! # Verification Steps
//!
//! 1. CBOR-decode `signature` as COSE_Sign1
//! 2. CBOR-decode `public_key` as COSE_Key, extract Ed25519 key (32 bytes)
//! 3. Verify protected header contains alg = -8 (EdDSA)
//! 4. Reconstruct COSE Sig_structure and verify Ed25519 signature
//! 5. Verify payload matches the expected OTP message
//! 6. Derive Cardano address (blake2b-224 of pubkey, bech32-encode)
//! 7. Print address to stdout

use serde::Deserialize;
use std::io::Read;
use std::process;

#[derive(Deserialize)]
struct PluginInput {
    sig: CardanoSig,
    otp_message: String,
}

#[derive(Deserialize)]
struct CardanoSig {
    #[allow(dead_code)]
    chain: String,
    signature: String,
    public_key: String,
    otp: String,
    machine_id: String,
}

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read stdin: {}", e);
        process::exit(1);
    }

    let parsed: PluginInput = match serde_json::from_str(&input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invalid input JSON: {}", e);
            process::exit(1);
        }
    };

    match verify(&parsed) {
        Ok(address) => {
            print!("{}", address);
            process::exit(0);
        }
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
}

fn verify(input: &PluginInput) -> Result<String, String> {
    // Validate that required fields are present
    if input.sig.signature.is_empty() {
        return Err("missing signature".to_string());
    }
    if input.sig.public_key.is_empty() {
        return Err("missing public_key".to_string());
    }
    if input.sig.otp.is_empty() || input.sig.machine_id.is_empty() {
        return Err("missing otp or machine_id".to_string());
    }

    // Verify OTP message matches expected format
    let expected_message = format!(
        "Authenticate to {} with code: {}",
        input.sig.machine_id, input.sig.otp
    );
    if input.otp_message != expected_message {
        return Err("otp_message mismatch".to_string());
    }

    // TODO: Implement full CIP-30 COSE_Sign1 verification:
    // 1. CBOR-decode signature as COSE_Sign1
    // 2. CBOR-decode public_key as COSE_Key, extract Ed25519 key
    // 3. Verify alg = -8 (EdDSA) in protected headers
    // 4. Reconstruct Sig_structure, verify Ed25519 signature
    // 5. Verify payload matches otp_message
    // 6. Derive address: bech32(blake2b-224(pubkey))

    Err("cardano verification not yet implemented".to_string())
}
