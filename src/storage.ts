import { readFileSync, writeFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

function getKey(secret: string): Buffer {
  return scryptSync(secret, "mcp-calendar", 64).subarray(0, KEY_LEN);
}

export function encrypt(plain: string, secret: string): string {
  const key = getKey(secret);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

export function decrypt(ciphertext: string, secret: string): string {
  const key = getKey(secret);
  const buf = Buffer.from(ciphertext, "base64");
  const iv = buf.subarray(0, IV_LEN);
  const tag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const enc = buf.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc) + decipher.final("utf8");
}

export interface StoredTokens {
  access_token: string;
  refresh_token: string;
  expiry_date: number;
}

const memory = new Map<string, string>();
const FILE_PATH = process.env.TOKEN_STORE_PATH;

function loadFile(): Record<string, string> {
  if (!FILE_PATH) return {};
  try {
    return JSON.parse(readFileSync(FILE_PATH, "utf8")) as Record<string, string>;
  } catch {
    return {};
  }
}

function saveFile(data: Record<string, string>): void {
  if (!FILE_PATH) return;
  try {
    writeFileSync(FILE_PATH, JSON.stringify(data));
  } catch {
    // ignore
  }
}

export function saveTokens(userId: string, tokens: StoredTokens, secret: string): void {
  const raw = encrypt(JSON.stringify(tokens), secret);
  memory.set(userId, raw);
  const data = Object.fromEntries(memory);
  saveFile(data);
}

export function loadTokens(userId: string, secret: string): StoredTokens | null {
  let raw = memory.get(userId);
  if (!raw) {
    const data = loadFile();
    raw = data[userId] ?? null;
    if (raw) memory.set(userId, raw);
  }
  if (!raw) return null;
  try {
    return JSON.parse(decrypt(raw, secret)) as StoredTokens;
  } catch {
    return null;
  }
}

export function deleteTokens(userId: string): void {
  memory.delete(userId);
  saveFile(Object.fromEntries(memory));
}
