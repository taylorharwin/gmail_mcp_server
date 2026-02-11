import { randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { getAuthUrl, exchangeCode } from "./calendar.js";
import { saveTokens } from "./storage.js";

const pending = new Map<string, { codeVerifier: string }>();
const sessions = new Map<string, string>(); // sessionToken -> userId

const TOKEN_BYTES = 24;

function b64url(b: Buffer) {
  return b.toString("base64url");
}

export function createPendingAuth(): { state: string; codeVerifier: string; authUrl: string } {
  const state = b64url(randomBytes(TOKEN_BYTES));
  const codeVerifier = b64url(randomBytes(32));
  pending.set(state, { codeVerifier });
  const baseUrl = process.env.BASE_URL || "http://localhost:3000";
  const clientId = process.env.GOOGLE_CLIENT_ID!;
  const authUrl = getAuthUrl(clientId, `${baseUrl}/callback`, state, codeVerifier);
  return { state, codeVerifier, authUrl };
}

export async function handleCallback(
  code: string,
  state: string,
  clientSecret: string,
  secret: string
): Promise<{ sessionToken: string }> {
  const p = pending.get(state);
  pending.delete(state);
  if (!p) throw new Error("Invalid or expired state");

  const baseUrl = process.env.BASE_URL || "http://localhost:3000";
  const clientId = process.env.GOOGLE_CLIENT_ID!;
  const tokens = await exchangeCode(clientId, clientSecret, `${baseUrl}/callback`, code, p.codeVerifier);

  const userId = b64url(randomBytes(TOKEN_BYTES));
  saveTokens(userId, tokens, secret);
  const sessionToken = b64url(randomBytes(TOKEN_BYTES));
  sessions.set(sessionToken, userId);
  return { sessionToken };
}

export function resolveSession(token: string): string | null {
  return sessions.get(token) ?? null;
}

export function authMiddleware(req: Request, res: Response, next: () => void): void {
  const auth = req.headers.authorization;
  const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  const userId = token ? resolveSession(token) : null;
  if (!userId) {
    res.status(401).set("WWW-Authenticate", 'Bearer realm="MCP", authorization_uri="/authorize"').json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Unauthorized. Visit /authorize to sign in." },
      id: null,
    });
    return;
  }
  (req as Request & { userId: string }).userId = userId;
  next();
}
