# libpam-web3-cardano

Cardano CIP-30 authentication plugin for libpam-web3.

## Architecture

```
src/main.rs             — PAM verification plugin (Rust): COSE_Key → Ed25519 pubkey → bech32 address
auth-svc-src/index.ts   — HTTPS signing server (Node.js): COSE_Sign1 + Ed25519 verification
auth-svc-src/crypto.ts  — ECIES + SHAKE256 crypto utilities
signing-page/
  index.html            — CIP-30 wallet signing UI
  engine.js             — Wallet detection, signData, callback/manual modes
web3-auth-svc.service   — Systemd unit
libpam-web3.conf        — tmpfiles.d (creates /run/libpam-web3/pending/)
config.example.toml     — Auth-svc config template
```

## Plugin Protocol

See `docs/specs/plugin-interface.md` in the libpam-web3 core repo.

- **stdin:** `{"sig": <.sig JSON>, "otp_message": "..."}`
- **stdout:** bech32 Cardano address
- **exit 0** = verified, **non-zero** = denied

## Verification Split

| Step | Owner | What |
|------|-------|------|
| Structural | auth-svc | CBOR decode, Ed25519 verify, OTP match |
| Identity | PAM plugin | COSE_Key → pubkey → blake2b-224 → bech32 address |

The auth-svc verifies the signature is authentic. The plugin derives the address from the public key. PAM matches the address against GECOS `wallet=`.

## Build

```bash
cargo build --release           # Plugin binary: target/release/cardano

# Auth-svc bundle (requires Node.js):
npx esbuild auth-svc-src/index.ts --bundle --platform=node --target=node22 --minify \
  --alias:@noble/curves/ed25519=@noble/curves/ed25519.js --outfile=auth-svc.js

# Full .deb package:
./packaging/build-deb.sh
```

## Install

```bash
sudo dpkg -i packaging/libpam-web3-cardano_0.1.0_amd64.deb
```

Or manually:
```bash
sudo cp target/release/cardano /usr/lib/libpam-web3/plugins/
sudo chmod 755 /usr/lib/libpam-web3/plugins/cardano
```

## Dependencies

- `libpam-web3` (core PAM module)
- `nodejs >= 18` (for auth-svc runtime)
