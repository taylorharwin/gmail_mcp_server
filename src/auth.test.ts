import { describe, it, expect } from "vitest";
import { createPendingAuth, resolveSession, authMiddleware } from "./auth.js";

describe("createPendingAuth", () => {
  it("returns state, codeVerifier, and authUrl", () => {
    process.env.GOOGLE_CLIENT_ID = "test-client-id";
    process.env.BASE_URL = "http://localhost:3000";

    const result = createPendingAuth();
    expect(result.state).toBeTruthy();
    expect(result.codeVerifier).toBeTruthy();
    expect(result.authUrl).toContain("accounts.google.com");
    expect(result.authUrl).toContain("code_challenge_method=S256");
    expect(result.authUrl).toContain("code_challenge=");
    expect(result.authUrl).toContain(encodeURIComponent("http://localhost:3000/callback"));
  });

  it("generates unique state per call", () => {
    process.env.GOOGLE_CLIENT_ID = "test-client-id";
    const a = createPendingAuth();
    const b = createPendingAuth();
    expect(a.state).not.toBe(b.state);
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
  });
});

describe("resolveSession", () => {
  it("returns null for unknown token", () => {
    expect(resolveSession("nonexistent-token")).toBeNull();
  });
});

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

  it("rejects requests with invalid token", () => {
    const req = mockReq("Bearer bad-token");
    const res = mockRes();
    let called = false;
    authMiddleware(req, res, () => { called = true; });
    expect(called).toBe(false);
    expect(res.statusCode).toBe(401);
  });
});
