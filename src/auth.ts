import { createHash, randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { getAuthUrl, exchangeCode } from "./calendar.js";
import { saveTokens } from "./storage.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOKEN_BYTES = 32;
const AUTH_CODE_TTL = 10 * 60 * 1000;          // 10 minutes
const PENDING_AUTH_TTL = 10 * 60 * 1000;        // 10 minutes
const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60 * 1000; // 1 hour

function accessTokenTtl(): number {
  const envSeconds = Number(process.env.ACCESS_TOKEN_TTL_SECONDS);
  return (envSeconds > 0 ? envSeconds * 1000 : DEFAULT_ACCESS_TOKEN_TTL);
}

function accessTokenTtlSeconds(): number {
  return Math.floor(accessTokenTtl() / 1000);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PendingAuthorization {
  mcpClientId: string;
  mcpRedirectUri: string;
  mcpCodeChallenge: string;
  mcpCodeChallengeMethod: string;
  mcpState: string;
  mcpScope: string;
  googleState: string;
  googleCodeVerifier: string;
  createdAt: number;
}

interface IssuedAuthCode {
  code: string;
  mcpClientId: string;
  mcpRedirectUri: string;
  mcpCodeChallenge: string;
  mcpCodeChallengeMethod: string;
  userId: string;
  createdAt: number;
  used: boolean;
}

interface IssuedAccessToken {
  token: string;
  userId: string;
  mcpClientId: string;
  expiresAt: number;
}

interface IssuedRefreshToken {
  token: string;
  userId: string;
  mcpClientId: string;
}

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

const pendingAuthorizations = new Map<string, PendingAuthorization>();
const authCodes = new Map<string, IssuedAuthCode>();
const accessTokens = new Map<string, IssuedAccessToken>();
const refreshTokens = new Map<string, IssuedRefreshToken>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function b64url(b: Buffer): string {
  return b.toString("base64url");
}

function generateToken(): string {
  return b64url(randomBytes(TOKEN_BYTES));
}

function verifyS256(codeVerifier: string, codeChallenge: string): boolean {
  const computed = createHash("sha256").update(codeVerifier).digest("base64url");
  return computed === codeChallenge;
}

function cleanupExpired(): void {
  const now = Date.now();
  for (const [key, val] of pendingAuthorizations) {
    if (now - val.createdAt > PENDING_AUTH_TTL) pendingAuthorizations.delete(key);
  }
  for (const [key, val] of accessTokens) {
    if (now > val.expiresAt) accessTokens.delete(key);
  }
  // Auth codes are not cleaned here — expiry is checked explicitly in exchangeAuthCode
  // so that the caller gets a specific "expired" error rather than "invalid".
}

function revokeTokensForUser(userId: string, mcpClientId: string): void {
  for (const [key, val] of accessTokens) {
    if (val.userId === userId && val.mcpClientId === mcpClientId) accessTokens.delete(key);
  }
  for (const [key, val] of refreshTokens) {
    if (val.userId === userId && val.mcpClientId === mcpClientId) refreshTokens.delete(key);
  }
}

// ---------------------------------------------------------------------------
// OAuth Authorization Server functions
// ---------------------------------------------------------------------------

export function startAuthorization(params: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  state: string;
  scope: string;
}): { googleAuthUrl: string } {
  cleanupExpired();

  if (params.codeChallengeMethod !== "S256") {
    throw new Error("Only code_challenge_method=S256 is supported");
  }

  const googleState = generateToken();
  const googleCodeVerifier = b64url(randomBytes(32));

  pendingAuthorizations.set(googleState, {
    mcpClientId: params.clientId,
    mcpRedirectUri: params.redirectUri,
    mcpCodeChallenge: params.codeChallenge,
    mcpCodeChallengeMethod: params.codeChallengeMethod,
    mcpState: params.state,
    mcpScope: params.scope,
    googleState,
    googleCodeVerifier,
    createdAt: Date.now(),
  });

  const baseUrl = process.env.BASE_URL || "http://localhost:3000";
  const clientId = process.env.GOOGLE_CLIENT_ID!;
  const googleAuthUrl = getAuthUrl(clientId, `${baseUrl}/callback`, googleState, googleCodeVerifier);
  return { googleAuthUrl };
}

export async function handleOAuthCallback(
  googleCode: string,
  googleState: string,
  clientSecret: string,
  secret: string
): Promise<{ redirectUrl: string }> {
  const pending = pendingAuthorizations.get(googleState);
  pendingAuthorizations.delete(googleState);

  if (!pending) throw new Error("Invalid or expired state");
  if (Date.now() - pending.createdAt > PENDING_AUTH_TTL) throw new Error("Authorization request expired");

  const baseUrl = process.env.BASE_URL || "http://localhost:3000";
  const clientId = process.env.GOOGLE_CLIENT_ID!;
  const tokens = await exchangeCode(clientId, clientSecret, `${baseUrl}/callback`, googleCode, pending.googleCodeVerifier);

  const userId = generateToken();
  saveTokens(userId, tokens, secret);

  const code = generateToken();
  authCodes.set(code, {
    code,
    mcpClientId: pending.mcpClientId,
    mcpRedirectUri: pending.mcpRedirectUri,
    mcpCodeChallenge: pending.mcpCodeChallenge,
    mcpCodeChallengeMethod: pending.mcpCodeChallengeMethod,
    userId,
    createdAt: Date.now(),
    used: false,
  });

  const redirectUrl = new URL(pending.mcpRedirectUri);
  redirectUrl.searchParams.set("code", code);
  redirectUrl.searchParams.set("state", pending.mcpState);
  return { redirectUrl: redirectUrl.toString() };
}

export function exchangeAuthCode(params: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientId: string;
}): { access_token: string; token_type: string; expires_in: number; refresh_token: string } {
  cleanupExpired();

  const entry = authCodes.get(params.code);
  if (!entry) throw new Error("Invalid authorization code");

  if (entry.used) {
    revokeTokensForUser(entry.userId, entry.mcpClientId);
    authCodes.delete(params.code);
    throw new Error("Authorization code already used");
  }

  entry.used = true;

  if (Date.now() - entry.createdAt > AUTH_CODE_TTL) {
    authCodes.delete(params.code);
    throw new Error("Authorization code expired");
  }

  if (params.clientId !== entry.mcpClientId) {
    throw new Error("client_id mismatch");
  }

  if (params.redirectUri !== entry.mcpRedirectUri) {
    throw new Error("redirect_uri mismatch");
  }

  if (!verifyS256(params.codeVerifier, entry.mcpCodeChallenge)) {
    throw new Error("PKCE verification failed");
  }

  authCodes.delete(params.code);

  const accessToken = generateToken();
  const refreshToken = generateToken();

  accessTokens.set(accessToken, {
    token: accessToken,
    userId: entry.userId,
    mcpClientId: entry.mcpClientId,
    expiresAt: Date.now() + accessTokenTtl(),
  });

  refreshTokens.set(refreshToken, {
    token: refreshToken,
    userId: entry.userId,
    mcpClientId: entry.mcpClientId,
  });

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: accessTokenTtlSeconds(),
    refresh_token: refreshToken,
  };
}

export function refreshAccessToken(params: {
  refreshToken: string;
  clientId: string;
}): { access_token: string; token_type: string; expires_in: number } {
  const entry = refreshTokens.get(params.refreshToken);
  if (!entry) throw new Error("Invalid refresh token");

  if (params.clientId !== entry.mcpClientId) {
    throw new Error("client_id mismatch");
  }

  const accessToken = generateToken();
  accessTokens.set(accessToken, {
    token: accessToken,
    userId: entry.userId,
    mcpClientId: entry.mcpClientId,
    expiresAt: Date.now() + accessTokenTtl(),
  });

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: accessTokenTtlSeconds(),
  };
}

export function resolveAccessToken(token: string): string | null {
  const entry = accessTokens.get(token);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    accessTokens.delete(token);
    return null;
  }
  return entry.userId;
}

// ---------------------------------------------------------------------------
// Express middleware
// ---------------------------------------------------------------------------

export function authMiddleware(req: Request, res: Response, next: () => void): void {
  const auth = req.headers.authorization;
  const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  const userId = token ? resolveAccessToken(token) : null;
  if (!userId) {
    const baseUrl = process.env.BASE_URL || "http://localhost:3000";
    res.status(401)
      .set("WWW-Authenticate", `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`)
      .json({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized" },
        id: null,
      });
    return;
  }
  (req as Request & { userId: string }).userId = userId;
  next();
}

// ---------------------------------------------------------------------------
// Test helpers (exported for unit tests only)
// ---------------------------------------------------------------------------

export const _testHelpers = {
  pendingAuthorizations,
  authCodes,
  accessTokens,
  refreshTokens,
  verifyS256,
  generateToken,
};
