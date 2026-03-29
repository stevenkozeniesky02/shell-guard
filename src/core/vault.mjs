/**
 * Secrets Vault Engine
 *
 * Multi-layer encrypted secrets management with proxy execution.
 * Agents NEVER see raw secret values — Guard injects them server-side.
 *
 * Encryption architecture:
 * 1. Master seed derived from AGENT_TOKEN + PROJECT_KEY via SHA-512
 * 2. Master seed split into encryption key (32B) and HMAC key (32B)
 * 3. Per-secret keys derived from encryption key via HKDF-like HMAC
 * 4. Each secret encrypted with AES-256-GCM (random IV, auth tag)
 * 5. Vault file integrity verified via HMAC-SHA256
 *
 * This design ensures:
 * - Different agents get different encryption keys (key isolation)
 * - Compromising one secret doesn't expose others (per-secret keys)
 * - Vault tampering is detectable (HMAC integrity)
 * - Each encryption operation uses a unique IV (nonce reuse prevention)
 */

import {
  createHash, createCipheriv, createDecipheriv,
  randomBytes, createHmac
} from "crypto";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve } from "path";
import { config } from "./config.mjs";

// ─── Vault State ───

let _state = null;

/**
 * Initialize or return the vault singleton.
 * Derives keys, loads encrypted vault from disk, verifies integrity.
 */
export function initVault() {
  if (_state) return _state;

  // ── Key Derivation ──
  // Master seed: SHA-512(token:key:purpose:version) → 64 bytes
  const masterSeed = createHash("sha512")
    .update(config.agentToken + ":" + config.projectKey + ":vault:v1")
    .digest();

  // Split: first 32 bytes for encryption, last 32 for HMAC
  const encKey = masterSeed.subarray(0, 32);
  const hmacKey = masterSeed.subarray(32, 64);

  // ── Per-Secret Key Derivation (HKDF-like) ──
  function deriveSecretKey(secretName) {
    return createHmac("sha256", encKey)
      .update("secret-key:" + secretName + ":v1")
      .digest();
  }

  // ── AES-256-GCM Encryption ──
  function encrypt(secretName, plaintext) {
    const key = deriveSecretKey(secretName);
    const iv = randomBytes(16);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf-8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    // Bundle: iv(16) + authTag(16) + ciphertext(N)
    return Buffer.concat([iv, authTag, encrypted]).toString("base64");
  }

  // ── AES-256-GCM Decryption ──
  function decrypt(secretName, bundle64) {
    const key = deriveSecretKey(secretName);
    const bundle = Buffer.from(bundle64, "base64");
    const iv = bundle.subarray(0, 16);
    const authTag = bundle.subarray(16, 32);
    const encrypted = bundle.subarray(32);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]).toString("utf-8");
  }

  // ── HMAC Integrity ──
  function hmacSign(data) {
    return createHmac("sha256", hmacKey).update(data).digest("hex");
  }

  // ── Load from Disk ──
  const vaultPath = resolve(config.cwd, ".agentsid-vault.enc");
  let secrets = {};
  let accessLog = [];
  let rotationHistory = {};

  if (existsSync(vaultPath)) {
    try {
      const raw = readFileSync(vaultPath, "utf-8");
      const parsed = JSON.parse(raw);
      const payload = JSON.stringify(parsed.data);
      if (parsed.hmac === hmacSign(payload)) {
        secrets = parsed.data.secrets || {};
        accessLog = parsed.data.accessLog || [];
        rotationHistory = parsed.data.rotationHistory || {};
      }
    } catch {
      // Corrupted vault — start fresh
    }
  }

  // ── Persist to Disk ──
  function persist() {
    const data = {
      secrets,
      accessLog: accessLog.slice(-1000),
      rotationHistory,
    };
    const payload = JSON.stringify(data);
    const hmac = hmacSign(payload);
    writeFileSync(
      vaultPath,
      JSON.stringify({ data, hmac, version: 1 }),
      "utf-8"
    );
  }

  _state = Object.freeze({
    secrets,
    accessLog,
    rotationHistory,
    encrypt,
    decrypt,
    persist,
    hmacSign,
    deriveSecretKey,
  });

  return _state;
}

/**
 * Reset vault state (for testing).
 */
export function resetVault() {
  _state = null;
}
