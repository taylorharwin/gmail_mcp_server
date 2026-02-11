import { randomBytes } from "node:crypto";
import type { Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
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
// Helpers
// ---------------------------------------------------------------------------

function b64url(b: Buffer): string {
  return b.toString("base64url");
}

function generateToken(): string {
  return b64url(randomBytes(TOKEN_BYTES));
}

// ---------------------------------------------------------------------------
// OAuth Server Provider
// ---------------------------------------------------------------------------

export class GoogleCalendarOAuthProvider implements OAuthServerProvider {
  private readonly _clients = new Map<string, OAuthClientInformationFull>();
  private readonly _pendingAuths = new Map<string, PendingAuthorization>();
  private readonly _authCodes = new Map<string, IssuedAuthCode>();
  private readonly _accessTokens = new Map<string, IssuedAccessToken>();
  private readonly _refreshTokens = new Map<string, IssuedRefreshToken>();

  get clientsStore(): OAuthRegisteredClientsStore {
    const clients = this._clients;
    return {
      getClient: (clientId: string) => clients.get(clientId),
      registerClient: (client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">) => {
        const clientId = generateToken();
        const full = {
          ...client,
          client_id: clientId,
          client_id_issued_at: Math.floor(Date.now() / 1000),
        } as OAuthClientInformationFull;
        clients.set(clientId, full);
        return full;
      },
    };
  }

  // --- Authorization (redirect to Google) ---

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    this._cleanupExpired();

    const googleState = generateToken();
    const googleCodeVerifier = b64url(randomBytes(32));

    this._pendingAuths.set(googleState, {
      mcpClientId: client.client_id,
      mcpRedirectUri: params.redirectUri,
      mcpCodeChallenge: params.codeChallenge,
      mcpState: params.state ?? "",
      mcpScope: params.scopes?.join(" ") ?? "google-calendar",
      googleState,
      googleCodeVerifier,
      createdAt: Date.now(),
    });

    const baseUrl = process.env.BASE_URL || "http://localhost:3000";
    const googleClientId = process.env.GOOGLE_CLIENT_ID!;
    const googleAuthUrl = getAuthUrl(googleClientId, `${baseUrl}/callback`, googleState, googleCodeVerifier);
    res.redirect(302, googleAuthUrl);
  }

  // --- Google callback (not part of OAuthServerProvider interface) ---

  async handleGoogleCallback(googleCode: string, googleState: string): Promise<string> {
    const pending = this._pendingAuths.get(googleState);
    this._pendingAuths.delete(googleState);

    if (!pending) throw new Error("Invalid or expired state");
    if (Date.now() - pending.createdAt > PENDING_AUTH_TTL) throw new Error("Authorization request expired");

    const baseUrl = process.env.BASE_URL || "http://localhost:3000";
    const googleClientId = process.env.GOOGLE_CLIENT_ID!;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET!;
    const secret = process.env.TOKEN_ENCRYPTION_KEY!;

    const tokens = await exchangeCode(googleClientId, clientSecret, `${baseUrl}/callback`, googleCode, pending.googleCodeVerifier);
    const userId = generateToken();
    saveTokens(userId, tokens, secret);

    const code = generateToken();
    this._authCodes.set(code, {
      code,
      mcpClientId: pending.mcpClientId,
      mcpRedirectUri: pending.mcpRedirectUri,
      mcpCodeChallenge: pending.mcpCodeChallenge,
      userId,
      createdAt: Date.now(),
      used: false,
    });

    const redirectUrl = new URL(pending.mcpRedirectUri);
    redirectUrl.searchParams.set("code", code);
    redirectUrl.searchParams.set("state", pending.mcpState);
    return redirectUrl.toString();
  }

  // --- PKCE challenge lookup (SDK uses this for validation) ---

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const entry = this._authCodes.get(authorizationCode);
    if (!entry) throw new Error("Invalid authorization code");
    return entry.mcpCodeChallenge;
  }

  // --- Token exchange ---

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    _resource?: URL,
  ): Promise<OAuthTokens> {
    this._cleanupExpired();

    const entry = this._authCodes.get(authorizationCode);
    if (!entry) throw new Error("Invalid authorization code");

    if (entry.used) {
      this._revokeTokensForUser(entry.userId, entry.mcpClientId);
      this._authCodes.delete(authorizationCode);
      throw new Error("Authorization code already used");
    }

    entry.used = true;

    if (Date.now() - entry.createdAt > AUTH_CODE_TTL) {
      this._authCodes.delete(authorizationCode);
      throw new Error("Authorization code expired");
    }

    if (client.client_id !== entry.mcpClientId) {
      throw new Error("client_id mismatch");
    }

    if (redirectUri && redirectUri !== entry.mcpRedirectUri) {
      throw new Error("redirect_uri mismatch");
    }

    this._authCodes.delete(authorizationCode);

    const accessToken = generateToken();
    const refreshToken = generateToken();

    this._accessTokens.set(accessToken, {
      token: accessToken,
      userId: entry.userId,
      mcpClientId: entry.mcpClientId,
      expiresAt: Date.now() + accessTokenTtl(),
    });

    this._refreshTokens.set(refreshToken, {
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

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    _resource?: URL,
  ): Promise<OAuthTokens> {
    const entry = this._refreshTokens.get(refreshToken);
    if (!entry) throw new Error("Invalid refresh token");

    if (client.client_id !== entry.mcpClientId) {
      throw new Error("client_id mismatch");
    }

    const accessToken = generateToken();
    this._accessTokens.set(accessToken, {
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

  // --- Token verification ---

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const entry = this._accessTokens.get(token);
    if (!entry) throw new Error("Invalid access token");

    if (Date.now() > entry.expiresAt) {
      this._accessTokens.delete(token);
      throw new Error("Access token expired");
    }

    return {
      token,
      clientId: entry.mcpClientId,
      scopes: [],
      expiresAt: Math.floor(entry.expiresAt / 1000),
      extra: { userId: entry.userId },
    };
  }

  // --- Internal helpers ---

  private _cleanupExpired(): void {
    const now = Date.now();
    for (const [key, val] of this._pendingAuths) {
      if (now - val.createdAt > PENDING_AUTH_TTL) this._pendingAuths.delete(key);
    }
    for (const [key, val] of this._accessTokens) {
      if (now > val.expiresAt) this._accessTokens.delete(key);
    }
  }

  private _revokeTokensForUser(userId: string, mcpClientId: string): void {
    for (const [key, val] of this._accessTokens) {
      if (val.userId === userId && val.mcpClientId === mcpClientId) this._accessTokens.delete(key);
    }
    for (const [key, val] of this._refreshTokens) {
      if (val.userId === userId && val.mcpClientId === mcpClientId) this._refreshTokens.delete(key);
    }
  }

  // --- Test helpers ---

  get _testHelpers() {
    return {
      pendingAuths: this._pendingAuths,
      authCodes: this._authCodes,
      accessTokens: this._accessTokens,
      refreshTokens: this._refreshTokens,
    };
  }
}

// Exported for tests
export const _testHelpers = { generateToken };
