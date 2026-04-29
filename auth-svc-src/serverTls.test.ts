/**
 * Tests for shared auth-svc HTTP/HTTPS branching in
 * auth-svc-common/server.ts. Lives in the cardano plugin because tsx +
 * @noble/curves are already installed here; the code under test is
 * chain-agnostic.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as http from "node:http";
import * as https from "node:https";

import {
  loadUseTls,
  buildAuthServer,
  type ServerConfig,
  type ChainOptions,
} from "../../../auth-svc-common/server";

function tmpFile(content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pam-cfg-"));
  const p = path.join(dir, "config.toml");
  fs.writeFileSync(p, content);
  return p;
}

const NOOP_OPTIONS: ChainOptions = {
  chain: "test",
  defaultPort: 0,
  maxBodySize: 1024,
  requireJson: true,
  requestTimeoutMs: 5000,
  handleCallback: () => null,
};

function baseConfig(over: Partial<ServerConfig>): ServerConfig {
  return {
    port: 0,
    pending_dir: "/tmp/pending-not-used",
    cert: "/nonexistent/cert.pem",
    key: "/nonexistent/key.pem",
    pages_dir: "/tmp/pages-not-used",
    use_tls: true,
    ...over,
  };
}

// ── loadUseTls ───────────────────────────────────────────────────────

test("loadUseTls: defaults to true when config file is missing", () => {
  assert.equal(loadUseTls("/no/such/path/pam-config.toml"), true);
});

test("loadUseTls: defaults to true when [auth] section is absent", () => {
  const p = tmpFile(`[machine]\nid = "x"\n`);
  assert.equal(loadUseTls(p), true);
});

test("loadUseTls: defaults to true when use_tls field is absent", () => {
  const p = tmpFile(`[machine]\nid = "x"\n[auth]\notp_length = 6\n`);
  assert.equal(loadUseTls(p), true);
});

test("loadUseTls: returns true when use_tls = true", () => {
  const p = tmpFile(`[auth]\nuse_tls = true\n`);
  assert.equal(loadUseTls(p), true);
});

test("loadUseTls: returns false when use_tls = false", () => {
  const p = tmpFile(`[auth]\nuse_tls = false\n`);
  assert.equal(loadUseTls(p), false);
});

test("loadUseTls: defaults to true on garbage value (fail-secure)", () => {
  const p = tmpFile(`[auth]\nuse_tls = maybe\n`);
  assert.equal(loadUseTls(p), true);
});

// ── buildAuthServer ──────────────────────────────────────────────────

test("buildAuthServer: returns plain http.Server when use_tls=false", () => {
  // Cert/key paths are bogus on purpose — proves the HTTP branch never
  // reads them. If buildAuthServer touches them, fs.readFileSync throws
  // ENOENT and this test fails.
  const cfg = baseConfig({ use_tls: false });
  const server = buildAuthServer(cfg, NOOP_OPTIONS);
  assert.ok(server instanceof http.Server, "expected http.Server instance");
  // https.Server is a subclass of http.Server in @types/node, so the
  // negative assertion catches a regression where use_tls=false still
  // builds an HTTPS server.
  assert.ok(!(server instanceof https.Server), "expected NOT https.Server");
  server.close();
});

test("buildAuthServer: reads cert/key and returns https.Server when use_tls=true", () => {
  const { spawnSync } = require("node:child_process") as typeof import("node:child_process");
  const opensslCheck = spawnSync("openssl", ["version"], { stdio: "ignore" });
  if (opensslCheck.status !== 0) {
    console.log("skipping HTTPS branch test: openssl not available");
    return;
  }

  // Generate a throwaway cert+key for this test only.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pam-tls-"));
  const certPath = path.join(dir, "cert.pem");
  const keyPath = path.join(dir, "key.pem");
  const r = spawnSync(
    "openssl",
    [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-keyout", keyPath, "-out", certPath,
      "-days", "1", "-nodes", "-subj", "/CN=test",
    ],
    { stdio: "ignore" },
  );
  assert.equal(r.status, 0, "openssl cert generation failed");

  const cfg = baseConfig({ use_tls: true, cert: certPath, key: keyPath });
  const server = buildAuthServer(cfg, NOOP_OPTIONS);
  assert.ok(server instanceof https.Server, "expected https.Server instance");
  server.close();
});

test("buildAuthServer: throws when use_tls=true and cert is missing", () => {
  const cfg = baseConfig({ use_tls: true });
  assert.throws(
    () => buildAuthServer(cfg, NOOP_OPTIONS),
    /ENOENT/,
    "expected fs read error to bubble up",
  );
});
