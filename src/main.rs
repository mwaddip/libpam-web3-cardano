//! Cardano verification plugin for libpam-web3.
//!
//! Identity binding: derives the Cardano payment credential from the
//! Ed25519 public key (already extracted by the auth-svc) and asserts
//! it matches the GECOS-listed bech32 address. The auth-svc has already
//! verified the COSE_Sign1 signature; this plugin only does the
//! key→address derivation and the comparison.
//!
//! # Protocol
//!
//! Discovery: install-time manifest at /usr/lib/libpam-web3/plugins/cardano.json,
//! written by postinst. PAM no longer queries the binary at startup.
//!
//! Verify:
//!   stdin:  {"sig": {chain, ed25519_public_key, otp, machine_id},
//!            "otp_message": "...", "wallet_address": "<from GECOS>"}
//!   exit:   0 = verified, 1 = denied
//!
//! The `ed25519_public_key` field is the raw 32-byte Ed25519 pubkey hex
//! that the auth-svc already extracted from the CIP-30 COSE_Key. Doing
//! the CBOR parse only in the auth-svc means the COSE layout is
//! interpreted in exactly one place — no risk of the two parsers
//! silently disagreeing on a malformed input.

use blake2::digest::{consts::U28, Digest};
use blake2::Blake2b;
use serde::Deserialize;
use std::io::Read;
use std::process;

/// blake2b-224 (28-byte output) — used for Cardano key hashes.
type Blake2b224 = Blake2b<U28>;

#[derive(Deserialize)]
struct PluginInput {
    sig: CardanoSig,
    #[allow(dead_code)]
    otp_message: String,
    /// The wallet address from the user's GECOS field (bech32, includes network)
    wallet_address: String,
}

#[derive(Deserialize)]
struct CardanoSig {
    #[allow(dead_code)]
    chain: String,
    /// Raw 32-byte Ed25519 public key, hex (extracted from COSE_Key by auth-svc).
    ed25519_public_key: String,
    #[allow(dead_code)]
    otp: String,
    #[allow(dead_code)]
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
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
}

fn verify(input: &PluginInput) -> Result<(), String> {
    if input.sig.ed25519_public_key.is_empty() {
        return Err("missing ed25519_public_key".to_string());
    }
    if input.wallet_address.is_empty() {
        return Err("missing wallet_address".to_string());
    }

    // 1. Hex-decode the raw Ed25519 pubkey. Must be exactly 32 bytes —
    //    the auth-svc verified this already, but we re-check defensively.
    let pubkey_raw = hex::decode(&input.sig.ed25519_public_key)
        .map_err(|e| format!("invalid ed25519_public_key hex: {}", e))?;
    if pubkey_raw.len() != 32 {
        return Err(format!(
            "ed25519_public_key must be 32 bytes, got {}",
            pubkey_raw.len()
        ));
    }

    // 2. Derive the payment credential from the public key.
    let key_hash = blake2b_224(&pubkey_raw);

    // 3. Decode the GECOS wallet address (bech32) and extract the payment credential.
    let (_hrp, addr_bytes) = bech32::decode(&input.wallet_address)
        .map_err(|e| format!("invalid bech32 wallet address: {}", e))?;

    // Cardano address: header_byte (1) + payment_credential (28) [+ optional staking (28)]
    if addr_bytes.len() < 29 {
        return Err(format!(
            "wallet address too short: {} bytes (expected >= 29)",
            addr_bytes.len()
        ));
    }

    let payment_credential = &addr_bytes[1..29];

    // 4. Identity binding: signature key → GECOS-listed address.
    if payment_credential != key_hash.as_slice() {
        return Err("public key does not match wallet address".to_string());
    }

    Ok(())
}

fn blake2b_224(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b224::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
