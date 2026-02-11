import { createHash } from "node:crypto";
import { describe, it, expect, beforeEach } from "vitest";
import {
  startAuthorization,
  exchangeAuthCode,
  refreshAccessToken,
  resolveAccessToken,
  authMiddleware,
  _testHelpers,
} from "./auth.js";

const { pendingAuthorizations, authCodes, accessTokens, refreshTokens, verifyS256, generateToken } = _testHelpers;

function clearAll() {
  pendingAuthorizations.clear();
  authCodes.clear();
  accessTokens.clear();
  refreshTokens.clear();
}

beforeEach(() => {
  clearAll();
  process.env.GOOGLE_CLIENT_ID = "test-client-id";
  process.env.BASE_URL = "http://localhost:3000";
});

// ---------------------------------------------------------------------------
// verifyS256
// ---------------------------------------------------------------------------

describe("verifyS256", () => {
  it("returns true for matching verifier/challenge pair", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    expect(verifyS256(verifier, challenge)).toBe(true);
  });

  it("returns false for non-matching pair", () => {
    expect(verifyS256("wrong-verifier", "some-challenge")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// startAuthorization
// ---------------------------------------------------------------------------

describe("startAuthorization", () => {
  it("returns a Google auth URL", () => {
    const result = startAuthorization({
      clientId: "mcp-client-1",
      redirectUri: "http://localhost:8080/callback",
      codeChallenge: "abc123challenge",
      codeChallengeMethod: "S256",
      state: "mcp-state-xyz",
      scope: "google-calendar",
    });
    expect(result.googleAuthUrl).toContain("accounts.google.com");
    expect(result.googleAuthUrl).toContain("code_challenge=");
    expect(result.googleAuthUrl).toContain(encodeURIComponent("http://localhost:3000/callback"));
  });

  it("stores a pending authorization keyed by googleState", () => {
    startAuthorization({
      clientId: "mcp-client-1",
      redirectUri: "http://localhost:8080/callback",
      codeChallenge: "abc123",
      codeChallengeMethod: "S256",
      state: "s",
      scope: "google-calendar",
    });
    expect(pendingAuthorizations.size).toBe(1);
    const entry = [...pendingAuthorizations.values()][0];
    expect(entry.mcpClientId).toBe("mcp-client-1");
    expect(entry.mcpRedirectUri).toBe("http://localhost:8080/callback");
  });

  it("generates unique state per call", () => {
    const a = startAuthorization({ clientId: "c", redirectUri: "http://x", codeChallenge: "x", codeChallengeMethod: "S256", state: "a", scope: "s" });
    const b = startAuthorization({ clientId: "c", redirectUri: "http://x", codeChallenge: "x", codeChallengeMethod: "S256", state: "b", scope: "s" });
    expect(a.googleAuthUrl).not.toBe(b.googleAuthUrl);
  });

  it("throws if code_challenge_method is not S256", () => {
    expect(() => startAuthorization({
      clientId: "x", redirectUri: "http://x", codeChallenge: "x",
      codeChallengeMethod: "plain", state: "x", scope: "x",
    })).toThrow("S256");
  });
});

// ---------------------------------------------------------------------------
// exchangeAuthCode
// ---------------------------------------------------------------------------

describe("exchangeAuthCode", () => {
  const codeVerifier = "test-code-verifier-value-for-pkce";
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  function seedAuthCode(overrides?: Partial<{ used: boolean; createdAt: number; mcpClientId: string; mcpRedirectUri: string }>) {
    const code = generateToken();
    authCodes.set(code, {
      code,
      mcpClientId: overrides?.mcpClientId ?? "client-1",
      mcpRedirectUri: overrides?.mcpRedirectUri ?? "http://localhost:8080/cb",
      mcpCodeChallenge: codeChallenge,
      mcpCodeChallengeMethod: "S256",
      userId: "user-abc",
      createdAt: overrides?.createdAt ?? Date.now(),
      used: overrides?.used ?? false,
    });
    return code;
  }

  it("issues tokens for a valid auth code with correct PKCE", () => {
    const code = seedAuthCode();
    const result = exchangeAuthCode({
      code,
      codeVerifier,
      redirectUri: "http://localhost:8080/cb",
      clientId: "client-1",
    });
    expect(result.access_token).toBeTruthy();
    expect(result.refresh_token).toBeTruthy();
    expect(result.token_type).toBe("Bearer");
    expect(result.expires_in).toBeGreaterThan(0);
  });

  it("deletes auth code after successful exchange", () => {
    const code = seedAuthCode();
    exchangeAuthCode({ code, codeVerifier, redirectUri: "http://localhost:8080/cb", clientId: "client-1" });
    expect(authCodes.has(code)).toBe(false);
  });

  it("rejects unknown auth code", () => {
    expect(() => exchangeAuthCode({
      code: "nonexistent", codeVerifier, redirectUri: "http://x", clientId: "c",
    })).toThrow("Invalid authorization code");
  });

  it("rejects reused auth code and revokes tokens", () => {
    const code = seedAuthCode({ used: true });
    // Seed a token for this user to verify revocation
    accessTokens.set("tok-1", { token: "tok-1", userId: "user-abc", mcpClientId: "client-1", expiresAt: Date.now() + 99999 });
    expect(() => exchangeAuthCode({
      code, codeVerifier, redirectUri: "http://localhost:8080/cb", clientId: "client-1",
    })).toThrow("already used");
    expect(accessTokens.has("tok-1")).toBe(false);
  });

  it("rejects expired auth code", () => {
    const code = seedAuthCode({ createdAt: Date.now() - 11 * 60 * 1000 });
    expect(() => exchangeAuthCode({
      code, codeVerifier, redirectUri: "http://localhost:8080/cb", clientId: "client-1",
    })).toThrow("expired");
  });

  it("rejects wrong client_id", () => {
    const code = seedAuthCode();
    expect(() => exchangeAuthCode({
      code, codeVerifier, redirectUri: "http://localhost:8080/cb", clientId: "wrong-client",
    })).toThrow("client_id mismatch");
  });

  it("rejects wrong redirect_uri", () => {
    const code = seedAuthCode();
    expect(() => exchangeAuthCode({
      code, codeVerifier, redirectUri: "http://wrong.example.com/cb", clientId: "client-1",
    })).toThrow("redirect_uri mismatch");
  });

  it("rejects wrong code_verifier (PKCE failure)", () => {
    const code = seedAuthCode();
    expect(() => exchangeAuthCode({
      code, codeVerifier: "wrong-verifier", redirectUri: "http://localhost:8080/cb", clientId: "client-1",
    })).toThrow("PKCE verification failed");
  });
});

// ---------------------------------------------------------------------------
// refreshAccessToken
// ---------------------------------------------------------------------------

describe("refreshAccessToken", () => {
  it("issues a new access token for a valid refresh token", () => {
    const rt = generateToken();
    refreshTokens.set(rt, { token: rt, userId: "user-1", mcpClientId: "client-1" });
    const result = refreshAccessToken({ refreshToken: rt, clientId: "client-1" });
    expect(result.access_token).toBeTruthy();
    expect(result.token_type).toBe("Bearer");
    expect(result.expires_in).toBeGreaterThan(0);
  });

  it("rejects unknown refresh token", () => {
    expect(() => refreshAccessToken({ refreshToken: "bad", clientId: "c" })).toThrow("Invalid refresh token");
  });

  it("rejects wrong client_id", () => {
    const rt = generateToken();
    refreshTokens.set(rt, { token: rt, userId: "user-1", mcpClientId: "client-1" });
    expect(() => refreshAccessToken({ refreshToken: rt, clientId: "wrong" })).toThrow("client_id mismatch");
  });
});

// ---------------------------------------------------------------------------
// resolveAccessToken
// ---------------------------------------------------------------------------

describe("resolveAccessToken", () => {
  it("returns userId for a valid non-expired token", () => {
    const tok = generateToken();
    accessTokens.set(tok, { token: tok, userId: "user-1", mcpClientId: "c", expiresAt: Date.now() + 60000 });
    expect(resolveAccessToken(tok)).toBe("user-1");
  });

  it("returns null for unknown token", () => {
    expect(resolveAccessToken("nope")).toBeNull();
  });

  it("returns null and deletes an expired token", () => {
    const tok = generateToken();
    accessTokens.set(tok, { token: tok, userId: "user-1", mcpClientId: "c", expiresAt: Date.now() - 1 });
    expect(resolveAccessToken(tok)).toBeNull();
    expect(accessTokens.has(tok)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// authMiddleware
// ---------------------------------------------------------------------------

describe("authMiddleware", () => {
  function mockReq(auth?: string) {
    return { headers: { authorization: auth } } as any;
  }

  function mockRes() {
    const res: any = { statusCode: 0, body: null, headers: {} };
    res.status = (code: number) => { res.statusCode = code; return res; };
    res.set = (k: string, v: string) => { res.headers[k] = v; return res; };
    res.json = (data: any) => { res.body = data; return res; };
    return res;
  }

  it("rejects requests without Bearer token", () => {
    const req = mockReq();
    const res = mockRes();
    let called = false;
    authMiddleware(req, res, () => { called = true; });
    expect(called).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(res.body.error.code).toBe(-32001);
  });

  it("includes resource_metadata in WWW-Authenticate header", () => {
    const req = mockReq();
    const res = mockRes();
    authMiddleware(req, res, () => {});
    expect(res.headers["WWW-Authenticate"]).toContain("resource_metadata=");
    expect(res.headers["WWW-Authenticate"]).toContain("/.well-known/oauth-protected-resource");
  });

  it("rejects requests with invalid token", () => {
    const req = mockReq("Bearer bad-token");
    const res = mockRes();
    let called = false;
    authMiddleware(req, res, () => { called = true; });
    expect(called).toBe(false);
    expect(res.statusCode).toBe(401);
  });

  it("calls next() and sets userId for valid token", () => {
    const tok = generateToken();
    accessTokens.set(tok, { token: tok, userId: "user-42", mcpClientId: "c", expiresAt: Date.now() + 60000 });
    const req = mockReq(`Bearer ${tok}`);
    const res = mockRes();
    let called = false;
    authMiddleware(req, res, () => { called = true; });
    expect(called).toBe(true);
    expect((req as any).userId).toBe("user-42");
  });
});
