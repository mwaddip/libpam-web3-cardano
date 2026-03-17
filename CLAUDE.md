# libpam-web3-cardano

Cardano verification plugin for libpam-web3.

## Architecture

This repo produces three components:

| Component | Status | Description |
|-----------|--------|-------------|
| `cardano` plugin binary | Scaffold | Ed25519/COSE verification, installed to `/usr/lib/libpam-web3/plugins/cardano` |
| `web3-auth-svc` | Planned | Cardano-specific signing server (to be extracted from engine) |
| `signing-page/` | Planned | CIP-30 wallet connection UI (to be extracted from engine) |

## Plugin Protocol

See `docs/specs/plugin-interface.md` in the libpam-web3 core repo.

- **stdin:** `{"sig": <.sig JSON>, "otp_message": "..."}`
- **stdout:** bech32 Cardano address
- **exit 0** = verified, **non-zero** = denied

## Verification Steps

1. CBOR-decode `signature` (hex) as COSE_Sign1
2. CBOR-decode `public_key` (hex) as COSE_Key, extract Ed25519 key (32 bytes)
3. Verify protected header `alg = -8` (EdDSA)
4. Reconstruct COSE Sig_structure, verify Ed25519 signature
5. Verify payload matches OTP message
6. Derive Cardano address: `bech32(blake2b-224(pubkey))`

## Build

```bash
cargo build --release
# Binary: target/release/cardano
```

## Install

```bash
sudo mkdir -p /usr/lib/libpam-web3/plugins
sudo cp target/release/cardano /usr/lib/libpam-web3/plugins/
sudo chmod 755 /usr/lib/libpam-web3/plugins/cardano
```

## Dependencies

Requires `libpam-web3` to be installed on the target system.
