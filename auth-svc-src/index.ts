/**
 * web3-auth-svc — Cardano CIP-30 auth service for libpam-web3.
 *
 * Self-contained HTTPS server: HTTP boilerplate (routes, TLS, body limits,
 * slowloris timeout, signal handling) is in auth-svc-common; this file
 * provides only the Cardano-specific COSE_Sign1 verification + .sig writer.
 *
 * .sig file format (JSON):
 *   { chain: "cardano", ed25519_public_key, otp, machine_id }
 *
 * SPECIAL profile: S7 P9 E8 C5 I7 A7 L7
 *   P9: Auth boundary — validate every input, trust nothing from the network.
 *   E8: Long-running daemon — must not crash, must not leak.
 *
 * Cryptographic verification:
 *   COSE_Sign1 Ed25519 signatures are verified before writing .sig files.
 *   This is a safety check (not forged garbage), not an identity check —
 *   the PAM plugin handles identity binding via blake2b-224 of the pubkey.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { timingSafeEqual } from "node:crypto";
import * as cbor from "cbor";
import { ed25519 } from "@noble/curves/ed25519";
import {
  runServer,
  type CallbackError,
} from "../../../auth-svc-common/server";
import { chainPort } from "./chain-port";

const CHAIN_NAME = "cardano";

// CIP-30 COSE_Sign1 + COSE_Key fit comfortably under 1.5KB hex-encoded.
const MAX_BODY_SIZE = 1500;

const HEX_RE = /^[0-9a-fA-F]+$/;

function isValidHex(str: string): boolean {
  return str.length > 0 && str.length % 2 === 0 && HEX_RE.test(str);
}

interface CallbackPayload {
  signature: string;
  key: string;
  otp: string;
  machineId: string;
}

function parseCallbackBody(body: string): CallbackPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }

  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj);

  if (keys.length !== 4) return null;
  if (typeof obj["signature"] !== "string") return null;
  if (typeof obj["key"] !== "string") return null;
  if (typeof obj["otp"] !== "string") return null;
  if (typeof obj["machineId"] !== "string") return null;

  if (obj["otp"].length > 16 || obj["machineId"].length > 128) return null;

  if (!isValidHex(obj["signature"])) return null;
  if (!isValidHex(obj["key"])) return null;

  return {
    signature: obj["signature"],
    key: obj["key"],
    otp: obj["otp"],
    machineId: obj["machineId"],
  };
}

interface SessionData {
  otp: string;
  machine_id: string;
}

function readSession(sessionId: string, pendingDir: string): SessionData | null {
  const jsonPath = path.join(pendingDir, `${sessionId}.json`);
  try {
    const content = fs.readFileSync(jsonPath, "utf8");
    const parsed: unknown = JSON.parse(content);
    if (typeof parsed !== "object" || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;
    if (typeof obj["otp"] !== "string" || typeof obj["machine_id"] !== "string") {
      return null;
    }
    return { otp: obj["otp"], machine_id: obj["machine_id"] };
  } catch {
    return null;
  }
}

interface CardanoSigFile {
  chain: "cardano";
  /** Raw 32-byte Ed25519 public key, hex. The plugin uses this directly
   *  (no second CBOR parse) to derive the bech32 address via blake2b-224. */
  ed25519_public_key: string;
  otp: string;
  machine_id: string;
}

/**
 * Parse a CIP-30 COSE_Sign1 + COSE_Key, verify the Ed25519 signature, and
 * return the raw 32-byte Ed25519 public key on success.
 *
 * Doing the COSE parse only here (not also in the PAM plugin) means the
 * CBOR layout is interpreted in exactly one place. The plugin then takes
 * the raw 32-byte hex straight to blake2b-224 → bech32, no ciborium.
 */
function verifyAndExtractPubkey(payload: CallbackPayload): { pubkey: Uint8Array } | string {
  try {
    const sigBytes = Buffer.from(payload.signature, "hex");
    const keyBytes = Buffer.from(payload.key, "hex");

    const coseSign1: unknown = cbor.decodeFirstSync(sigBytes);
    if (!Array.isArray(coseSign1) || coseSign1.length !== 4) {
      return "COSE_Sign1: invalid structure";
    }

    const [protectedHeaders, , cosePayload, signatureRaw] = coseSign1 as [
      Buffer, unknown, Buffer, Buffer
    ];

    const protectedMap: unknown = cbor.decodeFirstSync(protectedHeaders);
    if (!(protectedMap instanceof Map)) {
      return "COSE_Sign1: protected headers not a map";
    }
    const alg = protectedMap.get(1);
    if (alg !== -8) {
      return "COSE_Sign1: unexpected algorithm (expected EdDSA/-8)";
    }

    const coseKey: unknown = cbor.decodeFirstSync(keyBytes);
    if (!(coseKey instanceof Map)) {
      return "COSE_Key: not a map";
    }
    if (coseKey.get(1) !== 1)  return "COSE_Key: unexpected key type (expected OKP/1)";
    if (coseKey.get(3) !== -8) return "COSE_Key: unexpected algorithm (expected EdDSA/-8)";
    if (coseKey.get(-1) !== 6) return "COSE_Key: unexpected curve (expected Ed25519/6)";

    const publicKeyRaw = coseKey.get(-2);
    if (!(publicKeyRaw instanceof Uint8Array) || publicKeyRaw.length !== 32) {
      return "COSE_Key: missing or invalid public key bytes";
    }

    const expectedMsg = `Authenticate to ${payload.machineId} with code: ${payload.otp}`;
    const expectedBytes = Buffer.from(expectedMsg, "utf8");
    const payloadBuf = Buffer.from(cosePayload);
    if (!payloadBuf.equals(expectedBytes)) {
      return "COSE_Sign1: payload does not match expected OTP message";
    }

    const sigStructure = [
      "Signature1",
      Buffer.from(protectedHeaders),
      Buffer.alloc(0),
      payloadBuf,
    ];
    const sigStructureEncoded = cbor.encode(sigStructure) as Buffer;

    const signatureBuf = new Uint8Array(signatureRaw);
    if (signatureBuf.length !== 64) {
      return "COSE_Sign1: signature must be 64 bytes";
    }

    const valid = ed25519.verify(
      signatureBuf,
      new Uint8Array(sigStructureEncoded),
      new Uint8Array(publicKeyRaw),
    );

    if (!valid) {
      return "COSE_Sign1: Ed25519 signature verification failed";
    }

    return { pubkey: new Uint8Array(publicKeyRaw) };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return `COSE verification error: ${detail}`;
  }
}

function handleCallback(
  sessionId: string,
  body: string,
  pendingDir: string,
): CallbackError | null {
  const sigPath = path.join(pendingDir, `${sessionId}.sig`);
  if (fs.existsSync(sigPath)) {
    return { kind: "conflict" };
  }

  const session = readSession(sessionId, pendingDir);
  if (!session) {
    return { kind: "not-found" };
  }

  const payload = parseCallbackBody(body);
  if (!payload) {
    return { kind: "invalid", message: "invalid request body" };
  }

  const otpA = Buffer.from(payload.otp);
  const otpB = Buffer.from(session.otp);
  if (otpA.length !== otpB.length || !timingSafeEqual(otpA, otpB)) {
    return { kind: "invalid", message: "otp mismatch" };
  }
  if (payload.machineId !== session.machine_id) {
    return { kind: "invalid", message: "machine_id mismatch" };
  }

  const verified = verifyAndExtractPubkey(payload);
  if (typeof verified === "string") {
    return { kind: "invalid", message: verified };
  }

  const sigContent: CardanoSigFile = {
    chain: "cardano",
    ed25519_public_key: Buffer.from(verified.pubkey).toString("hex"),
    otp: payload.otp,
    machine_id: payload.machineId,
  };

  const tmpPath = path.join(pendingDir, `${sessionId}.sig.tmp`);
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(sigContent));
    fs.renameSync(tmpPath, sigPath);
  } catch (err) {
    try { fs.unlinkSync(tmpPath); } catch { /* tmp may not exist */ }
    return {
      kind: "invalid",
      message: `sig file write failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  console.log(`[AUTH] Accepted CIP-30 signature for session ${sessionId}`);
  return null;
}

// Only run as a server when invoked as the entry point. Test imports skip.
if (process.argv[1]?.match(/\/(auth-svc\.js|index\.ts)$/)) {
  runServer({
    chain: CHAIN_NAME,
    defaultPort: chainPort(CHAIN_NAME),
    maxBodySize: MAX_BODY_SIZE,
    requireJson: true,
    requestTimeoutMs: 5000,
    handleCallback,
  });
}
