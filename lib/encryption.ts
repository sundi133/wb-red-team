/**
 * AES-256-GCM envelope encryption.
 * Master key encrypts per-tenant keys; tenant keys encrypt data.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;

function getMasterKey(): Buffer {
  const hex = process.env.MASTER_ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error(
      "MASTER_ENCRYPTION_KEY must be set to 64 hex characters (32 bytes)",
    );
  }
  return Buffer.from(hex, "hex");
}

/** Encrypt a buffer with a given key. */
function encryptRaw(
  plaintext: Buffer,
  key: Buffer,
): { ciphertext: Buffer; iv: Buffer; authTag: Buffer } {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext: encrypted, iv, authTag };
}

/** Decrypt a buffer with a given key. */
function decryptRaw(
  ciphertext: Buffer,
  iv: Buffer,
  authTag: Buffer,
  key: Buffer,
): Buffer {
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Generate a new per-tenant AES-256 key, encrypted under the master key.
 * Returns the encrypted key as a hex string (to store in tenants.encryption_key_enc).
 */
export function generateTenantKey(): string {
  const tenantKey = randomBytes(32);
  const masterKey = getMasterKey();
  const { ciphertext, iv, authTag } = encryptRaw(tenantKey, masterKey);
  // Pack as: iv (12) + authTag (16) + ciphertext (32) → hex
  return Buffer.concat([iv, authTag, ciphertext]).toString("hex");
}

/** Decrypt a tenant key from its stored hex form. */
function decryptTenantKey(tenantKeyEnc: string): Buffer {
  const buf = Buffer.from(tenantKeyEnc, "hex");
  const iv = buf.subarray(0, IV_LEN);
  const authTag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ciphertext = buf.subarray(IV_LEN + TAG_LEN);
  return decryptRaw(ciphertext, iv, authTag, getMasterKey());
}

/**
 * Encrypt plaintext string with a tenant's key.
 * @param plaintext - The string to encrypt (e.g., JSON report)
 * @param tenantKeyEnc - The tenant's encrypted key from DB (hex string)
 */
export function encryptWithTenantKey(
  plaintext: string,
  tenantKeyEnc: string,
): { ciphertext: Buffer; iv: Buffer; authTag: Buffer } {
  const tenantKey = decryptTenantKey(tenantKeyEnc);
  return encryptRaw(Buffer.from(plaintext, "utf-8"), tenantKey);
}

/**
 * Decrypt ciphertext with a tenant's key.
 * @returns The original plaintext string
 */
export function decryptWithTenantKey(
  ciphertext: Buffer,
  iv: Buffer,
  authTag: Buffer,
  tenantKeyEnc: string,
): string {
  const tenantKey = decryptTenantKey(tenantKeyEnc);
  return decryptRaw(ciphertext, iv, authTag, tenantKey).toString("utf-8");
}
