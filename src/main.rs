//! Cardano verification plugin for libpam-web3.
//!
//! Identity verification: derives the Cardano address from the Ed25519
//! public key in the .sig file and returns it. The auth-svc has already
//! verified the COSE_Sign1 signature; this plugin only binds key → address.
//!
//! # Protocol
//!
//! stdin:  {"sig": {chain, signature, public_key, otp, machine_id}, "otp_message": "..."}
//! stdout: bech32 Cardano address (enterprise format)
//! exit:   0 = verified, 1 = denied

use blake2::digest::{consts::U28, Digest};
use blake2::Blake2b;
use serde::Deserialize;
use std::io::Read;
use std::path::Path;
use std::process;

/// blake2b-224 (28-byte output) — used for Cardano key hashes.
type Blake2b224 = Blake2b<U28>;

const CONFIG_PATH: &str = "/etc/libpam-web3/cardano.toml";

#[derive(Deserialize)]
struct PluginConfig {
    #[serde(default = "default_network")]
    network: String,
}

fn default_network() -> String {
    "mainnet".to_string()
}

fn load_config() -> PluginConfig {
    let path = Path::new(CONFIG_PATH);
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(config) = toml::from_str(&content) {
                return config;
            }
        }
    }
    PluginConfig { network: default_network() }
}

#[derive(Deserialize)]
struct PluginInput {
    sig: CardanoSig,
    #[allow(dead_code)]
    otp_message: String,
}

#[derive(Deserialize)]
struct CardanoSig {
    #[allow(dead_code)]
    chain: String,
    #[allow(dead_code)]
    signature: String,
    public_key: String,
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

    let config = load_config();

    match verify(&parsed, &config) {
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

fn verify(input: &PluginInput, config: &PluginConfig) -> Result<String, String> {
    if input.sig.public_key.is_empty() {
        return Err("missing public_key".to_string());
    }

    // 1. Hex-decode the COSE_Key
    let key_bytes =
        hex::decode(&input.sig.public_key).map_err(|e| format!("invalid public_key hex: {}", e))?;

    // 2. CBOR-decode as COSE_Key map, extract Ed25519 public key from label -2
    let pubkey_raw = extract_ed25519_pubkey(&key_bytes)?;

    // 3. Derive Cardano enterprise address based on configured network
    let key_hash = blake2b_224(&pubkey_raw);

    let (header, hrp) = match config.network.as_str() {
        "testnet" => (0x60u8, "addr_test"),
        _ => (0x61u8, "addr"),
    };

    encode_enterprise_address(header, &key_hash, hrp)
}

/// Extract the raw Ed25519 public key (32 bytes) from a CBOR-encoded COSE_Key.
///
/// COSE_Key map labels:
///   1 (kty) = 1 (OKP)
///   3 (alg) = -8 (EdDSA)
///  -1 (crv) = 6 (Ed25519)
///  -2 (x)   = public key bytes (32 bytes)
fn extract_ed25519_pubkey(cose_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value: ciborium::Value = ciborium::from_reader(cose_key_bytes)
        .map_err(|e| format!("COSE_Key CBOR decode failed: {}", e))?;

    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err("COSE_Key: expected CBOR map".to_string()),
    };

    let kty = find_int_value(&map, 1).ok_or("COSE_Key: missing kty (label 1)")?;
    if kty != 1 {
        return Err(format!("COSE_Key: unexpected kty {} (expected 1/OKP)", kty));
    }

    let alg = find_int_value(&map, 3).ok_or("COSE_Key: missing alg (label 3)")?;
    if alg != -8 {
        return Err(format!("COSE_Key: unexpected alg {} (expected -8/EdDSA)", alg));
    }

    let crv = find_int_value(&map, -1).ok_or("COSE_Key: missing crv (label -1)")?;
    if crv != 6 {
        return Err(format!("COSE_Key: unexpected crv {} (expected 6/Ed25519)", crv));
    }

    let pubkey = find_bytes_value(&map, -2).ok_or("COSE_Key: missing x (label -2)")?;
    if pubkey.len() != 32 {
        return Err(format!("COSE_Key: public key is {} bytes (expected 32)", pubkey.len()));
    }

    Ok(pubkey)
}

fn find_int_value(map: &[(ciborium::Value, ciborium::Value)], key: i128) -> Option<i128> {
    for (k, v) in map {
        if let ciborium::Value::Integer(i) = k {
            if i128::from(*i) == key {
                if let ciborium::Value::Integer(val) = v {
                    return Some(i128::from(*val));
                }
            }
        }
    }
    None
}

fn find_bytes_value(map: &[(ciborium::Value, ciborium::Value)], key: i128) -> Option<Vec<u8>> {
    for (k, v) in map {
        if let ciborium::Value::Integer(i) = k {
            if i128::from(*i) == key {
                if let ciborium::Value::Bytes(bytes) = v {
                    return Some(bytes.clone());
                }
            }
        }
    }
    None
}

fn blake2b_224(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b224::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn encode_enterprise_address(header: u8, key_hash: &[u8], hrp: &str) -> Result<String, String> {
    let mut addr_bytes = Vec::with_capacity(29);
    addr_bytes.push(header);
    addr_bytes.extend_from_slice(key_hash);
    let hrp = bech32::Hrp::parse(hrp).map_err(|e| format!("invalid bech32 hrp: {}", e))?;
    bech32::encode::<bech32::Bech32>(hrp, &addr_bytes)
        .map_err(|e| format!("bech32 encoding failed: {}", e))
}
