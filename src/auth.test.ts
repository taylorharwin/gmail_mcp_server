import { describe, it, expect, beforeEach } from "vitest";
import { GoogleCalendarOAuthProvider, _testHelpers } from "./auth.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

const { generateToken } = _testHelpers;

function mockClient(id = "client-1"): OAuthClientInformationFull {
  return {
    client_id: id,
    redirect_uris: ["http://localhost:8080/cb"],
  } as OAuthClientInformationFull;
}

let provider: GoogleCalendarOAuthProvider;

beforeEach(() => {
  provider = new GoogleCalendarOAuthProvider();
  process.env.GOOGLE_CLIENT_ID = "test-client-id";
  process.env.BASE_URL = "http://localhost:3000";
});

// ---------------------------------------------------------------------------
// authorize
// ---------------------------------------------------------------------------

describe("authorize", () => {
  it("redirects to Google auth URL", async () => {
    const res: any = { redirectUrl: null, redirectStatus: 0 };
    res.redirect = (status: number, url: string) => {
      res.redirectStatus = status;
      res.redirectUrl = url;
    };

    await provider.authorize(mockClient(), {
      redirectUri: "http://localhost:8080/callback",
      codeChallenge: "abc123challenge",
      state: "mcp-state-xyz",
      scopes: ["google-calendar"],
    }, res);

    expect(res.redirectStatus).toBe(302);
    expect(res.redirectUrl).toContain("accounts.google.com");
    expect(res.redirectUrl).toContain("code_challenge=");
    expect(res.redirectUrl).toContain(encodeURIComponent("http://localhost:3000/callback"));
  });

  it("stores a pending authorization", async () => {
    const res: any = {};
    res.redirect = () => {};

    await provider.authorize(mockClient(), {
      redirectUri: "http://localhost:8080/callback",
      codeChallenge: "abc123",
      state: "s",
    }, res);

    const { pendingAuths } = provider._testHelpers;
    expect(pendingAuths.size).toBe(1);
    const entry = [...pendingAuths.values()][0];
    expect(entry.mcpClientId).toBe("client-1");
    expect(entry.mcpRedirectUri).toBe("http://localhost:8080/callback");
  });

  it("generates unique state per call", async () => {
    const urls: string[] = [];
    const res: any = {};
    res.redirect = (_s: number, url: string) => { urls.push(url); };

    await provider.authorize(mockClient(), { redirectUri: "http://x", codeChallenge: "x", state: "a" }, res);
    await provider.authorize(mockClient(), { redirectUri: "http://x", codeChallenge: "x", state: "b" }, res);

    expect(urls[0]).not.toBe(urls[1]);
  });
});

// ---------------------------------------------------------------------------
// exchangeAuthorizationCode
// ---------------------------------------------------------------------------

describe("exchangeAuthorizationCode", () => {
  function seedAuthCode(overrides?: Partial<{
    used: boolean;
    createdAt: number;
    mcpClientId: string;
    mcpRedirectUri: string;
  }>) {
    const { authCodes } = provider._testHelpers;
    const code = generateToken();
    authCodes.set(code, {
      code,
      mcpClientId: overrides?.mcpClientId ?? "client-1",
      mcpRedirectUri: overrides?.mcpRedirectUri ?? "http://localhost:8080/cb",
      mcpCodeChallenge: "test-challenge",
      userId: "user-abc",
      createdAt: overrides?.createdAt ?? Date.now(),
      used: overrides?.used ?? false,
    });
    return code;
  }

  it("issues tokens for a valid auth code", async () => {
    const code = seedAuthCode();
    const result = await provider.exchangeAuthorizationCode(
      mockClient(), code, undefined, "http://localhost:8080/cb"
    );
    expect(result.access_token).toBeTruthy();
    expect(result.refresh_token).toBeTruthy();
    expect(result.token_type).toBe("Bearer");
    expect(result.expires_in).toBeGreaterThan(0);
  });

  it("deletes auth code after successful exchange", async () => {
    const code = seedAuthCode();
    await provider.exchangeAuthorizationCode(mockClient(), code, undefined, "http://localhost:8080/cb");
    expect(provider._testHelpers.authCodes.has(code)).toBe(false);
  });

  it("rejects unknown auth code", async () => {
    await expect(provider.exchangeAuthorizationCode(
      mockClient(), "nonexistent", undefined, "http://x"
    )).rejects.toThrow("Invalid authorization code");
  });

  it("rejects reused auth code and revokes tokens", async () => {
    const code = seedAuthCode({ used: true });
    const { accessTokens } = provider._testHelpers;
    accessTokens.set("tok-1", { token: "tok-1", userId: "user-abc", mcpClientId: "client-1", expiresAt: Date.now() + 99999 });

    await expect(provider.exchangeAuthorizationCode(
      mockClient(), code, undefined, "http://localhost:8080/cb"
    )).rejects.toThrow("already used");
    expect(accessTokens.has("tok-1")).toBe(false);
  });

  it("rejects expired auth code", async () => {
    const code = seedAuthCode({ createdAt: Date.now() - 11 * 60 * 1000 });
    await expect(provider.exchangeAuthorizationCode(
      mockClient(), code, undefined, "http://localhost:8080/cb"
    )).rejects.toThrow("expired");
  });

  it("rejects wrong client_id", async () => {
    const code = seedAuthCode();
    await expect(provider.exchangeAuthorizationCode(
      mockClient("wrong-client"), code, undefined, "http://localhost:8080/cb"
    )).rejects.toThrow("client_id mismatch");
  });

  it("rejects wrong redirect_uri", async () => {
    const code = seedAuthCode();
    await expect(provider.exchangeAuthorizationCode(
      mockClient(), code, undefined, "http://wrong.example.com/cb"
    )).rejects.toThrow("redirect_uri mismatch");
  });
});

// ---------------------------------------------------------------------------
// exchangeRefreshToken
// ---------------------------------------------------------------------------

describe("exchangeRefreshToken", () => {
  it("issues a new access token for a valid refresh token", async () => {
    const { refreshTokens } = provider._testHelpers;
    const rt = generateToken();
    refreshTokens.set(rt, { token: rt, userId: "user-1", mcpClientId: "client-1" });

    const result = await provider.exchangeRefreshToken(mockClient(), rt);
    expect(result.access_token).toBeTruthy();
    expect(result.token_type).toBe("Bearer");
    expect(result.expires_in).toBeGreaterThan(0);
  });

  it("rejects unknown refresh token", async () => {
    await expect(provider.exchangeRefreshToken(mockClient(), "bad"))
      .rejects.toThrow("Invalid refresh token");
  });

  it("rejects wrong client_id", async () => {
    const { refreshTokens } = provider._testHelpers;
    const rt = generateToken();
    refreshTokens.set(rt, { token: rt, userId: "user-1", mcpClientId: "client-1" });

    await expect(provider.exchangeRefreshToken(mockClient("wrong"), rt))
      .rejects.toThrow("client_id mismatch");
  });
});

// ---------------------------------------------------------------------------
// verifyAccessToken
// ---------------------------------------------------------------------------

describe("verifyAccessToken", () => {
  it("returns AuthInfo for a valid non-expired token", async () => {
    const { accessTokens } = provider._testHelpers;
    const tok = generateToken();
    accessTokens.set(tok, { token: tok, userId: "user-1", mcpClientId: "c", expiresAt: Date.now() + 60000 });

    const info = await provider.verifyAccessToken(tok);
    expect(info.token).toBe(tok);
    expect(info.clientId).toBe("c");
    expect(info.extra?.userId).toBe("user-1");
    expect(info.expiresAt).toBeGreaterThan(0);
  });

  it("throws for unknown token", async () => {
    await expect(provider.verifyAccessToken("nope"))
      .rejects.toThrow("Invalid access token");
  });

  it("throws and deletes an expired token", async () => {
    const { accessTokens } = provider._testHelpers;
    const tok = generateToken();
    accessTokens.set(tok, { token: tok, userId: "user-1", mcpClientId: "c", expiresAt: Date.now() - 1 });

    await expect(provider.verifyAccessToken(tok)).rejects.toThrow("expired");
    expect(accessTokens.has(tok)).toBe(false);
  });
});
