import { describe, it, expect } from "vitest";
import { encrypt, decrypt, saveTokens, loadTokens, deleteTokens, type StoredTokens } from "./storage.js";

const SECRET = "test-secret-key-for-unit-tests!!";

describe("encrypt / decrypt", () => {
  it("round-trips a string", () => {
    const plain = '{"access_token":"abc","refresh_token":"def","expiry_date":123}';
    const cipher = encrypt(plain, SECRET);
    expect(cipher).not.toBe(plain);
    expect(decrypt(cipher, SECRET)).toBe(plain);
  });

  it("produces different ciphertext each time (random IV)", () => {
    const plain = "same-input";
    const a = encrypt(plain, SECRET);
    const b = encrypt(plain, SECRET);
    expect(a).not.toBe(b);
    expect(decrypt(a, SECRET)).toBe(plain);
    expect(decrypt(b, SECRET)).toBe(plain);
  });

  it("fails to decrypt with wrong secret", () => {
    const cipher = encrypt("secret-data", SECRET);
    expect(() => decrypt(cipher, "wrong-secret")).toThrow();
  });

  it("fails on tampered ciphertext", () => {
    const cipher = encrypt("data", SECRET);
    const buf = Buffer.from(cipher, "base64");
    buf[buf.length - 1] ^= 0xff;
    expect(() => decrypt(buf.toString("base64"), SECRET)).toThrow();
  });
});

describe("saveTokens / loadTokens / deleteTokens", () => {
  const tokens: StoredTokens = {
    access_token: "ya29.test-access",
    refresh_token: "1//test-refresh",
    expiry_date: Date.now() + 3600_000,
  };

  it("saves and loads tokens for a user", () => {
    saveTokens("user-1", tokens, SECRET);
    const loaded = loadTokens("user-1", SECRET);
    expect(loaded).toEqual(tokens);
  });

  it("returns null for unknown user", () => {
    expect(loadTokens("nonexistent", SECRET)).toBeNull();
  });

  it("deletes tokens", () => {
    saveTokens("user-2", tokens, SECRET);
    expect(loadTokens("user-2", SECRET)).toEqual(tokens);
    deleteTokens("user-2");
    expect(loadTokens("user-2", SECRET)).toBeNull();
  });

  it("returns null when decrypted with wrong secret", () => {
    saveTokens("user-3", tokens, SECRET);
    expect(loadTokens("user-3", "wrong-key")).toBeNull();
  });
});
