import { config } from "dotenv";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: join(__dirname, "..", ".env") });

import { randomUUID } from "node:crypto";
import express, { type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { startAuthorization, handleOAuthCallback, exchangeAuthCode, refreshAccessToken, registerClient, authMiddleware } from "./auth.js";
import { registerTools, setSessionUser, clearSession } from "./tools.js";

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  process.exit(1);
});
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled rejection at", promise, "reason:", reason);
  process.exit(1);
});

function createServer(): McpServer {
  const s = new McpServer(
    { name: "google-calendar-mcp", version: "1.0.0" },
    { capabilities: { tools: { listChanged: false } } }
  );
  registerTools(s);
  return s;
}

const transports: Record<string, StreamableHTTPServerTransport> = {};
const servers: Record<string, McpServer> = {};

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// CORS — required by MCP spec for browser-based clients
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type, Authorization, mcp-session-id");
  res.set("Access-Control-Expose-Headers", "mcp-session-id");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});

function htmlPage(title: string, body: string): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head><body style="font-family:sans-serif;max-width:480px;margin:2rem auto;padding:1.5rem;background:#eee;color:#111;"><h1 style="margin-top:0">${escapeHtml(title)}</h1>${body}</body></html>`;
}
function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------------
// Well-known metadata endpoints (RFC 9728, RFC 8414)
// ---------------------------------------------------------------------------

app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: BASE_URL,
    authorization_servers: [BASE_URL],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  });
});

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

app.post("/register", (req, res) => {
  const { client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method } = req.body;

  if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    res.status(400).json({ error: "invalid_client_metadata", error_description: "redirect_uris is required" });
    return;
  }

  const client = registerClient({
    clientName: client_name || "MCP Client",
    redirectUris: redirect_uris,
    grantTypes: grant_types,
    responseTypes: response_types,
    tokenEndpointAuthMethod: token_endpoint_auth_method,
  });

  res.status(201).json(client);
});

// ---------------------------------------------------------------------------
// Home / health
// ---------------------------------------------------------------------------

app.get("/", (_req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(
    htmlPage("Google Calendar MCP",
      "<p>Server is running. Connect via an MCP client that supports OAuth 2.1.</p>" +
      "<p>Metadata: <a href=\"/.well-known/oauth-authorization-server\">Authorization Server</a> &middot; " +
      "<a href=\"/.well-known/oauth-protected-resource\">Protected Resource</a></p>")
  );
});

app.get("/ping", (_req, res) => {
  res.set("Content-Type", "text/plain").send("pong");
});

// ---------------------------------------------------------------------------
// OAuth Authorization Endpoint
// ---------------------------------------------------------------------------

app.get("/authorize", (req, res) => {
  const googleClientId = process.env.GOOGLE_CLIENT_ID;
  if (!googleClientId) {
    res.status(500).set("Content-Type", "text/html").send(
      htmlPage("Error", '<p style="color:red">GOOGLE_CLIENT_ID is not set in .env</p>')
    );
    return;
  }

  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query;

  if (response_type !== "code" ||
      !client_id || typeof client_id !== "string" ||
      !redirect_uri || typeof redirect_uri !== "string" ||
      !code_challenge || typeof code_challenge !== "string" ||
      !state || typeof state !== "string") {
    res.status(400).set("Content-Type", "text/html").send(
      htmlPage("Bad Request",
        "<p>Missing or invalid OAuth parameters.</p>" +
        "<p>Required: <code>response_type=code</code>, <code>client_id</code>, <code>redirect_uri</code>, <code>code_challenge</code>, <code>state</code></p>")
    );
    return;
  }

  const method = (typeof code_challenge_method === "string" ? code_challenge_method : "S256");
  if (method !== "S256") {
    res.status(400).set("Content-Type", "text/html").send(
      htmlPage("Bad Request", "<p>Only <code>code_challenge_method=S256</code> is supported</p>")
    );
    return;
  }

  try {
    const { googleAuthUrl } = startAuthorization({
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: method,
      state,
      scope: (typeof req.query.scope === "string" ? req.query.scope : "google-calendar"),
    });
    res.redirect(302, googleAuthUrl);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    res.status(500).set("Content-Type", "text/html").send(
      htmlPage("Error", `<p style="color:red">${escapeHtml(msg)}</p>`)
    );
  }
});

// ---------------------------------------------------------------------------
// OAuth Callback (Google redirects here, we redirect to MCP client)
// ---------------------------------------------------------------------------

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const secret = process.env.TOKEN_ENCRYPTION_KEY;
  if (!code || typeof code !== "string" || !state || typeof state !== "string" || !clientSecret || !secret) {
    res.status(400).send("Missing code, state, or server config");
    return;
  }
  try {
    const { redirectUrl } = await handleOAuthCallback(code, state, clientSecret, secret);
    res.redirect(302, redirectUrl);
  } catch (e) {
    res.status(400).send("Auth failed: " + (e instanceof Error ? e.message : String(e)));
  }
});

// ---------------------------------------------------------------------------
// OAuth Token Endpoint
// ---------------------------------------------------------------------------

app.post("/token", (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === "authorization_code") {
    const { code, code_verifier, redirect_uri, client_id } = req.body;
    if (!code || !code_verifier || !redirect_uri || !client_id) {
      res.status(400).json({ error: "invalid_request", error_description: "Missing required parameters" });
      return;
    }
    try {
      const result = exchangeAuthCode({ code, codeVerifier: code_verifier, redirectUri: redirect_uri, clientId: client_id });
      res.json(result);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      res.status(400).json({ error: "invalid_grant", error_description: msg });
    }
  } else if (grant_type === "refresh_token") {
    const { refresh_token, client_id } = req.body;
    if (!refresh_token || !client_id) {
      res.status(400).json({ error: "invalid_request", error_description: "Missing required parameters" });
      return;
    }
    try {
      const result = refreshAccessToken({ refreshToken: refresh_token, clientId: client_id });
      res.json(result);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      res.status(400).json({ error: "invalid_grant", error_description: msg });
    }
  } else {
    res.status(400).json({ error: "unsupported_grant_type" });
  }
});

// ---------------------------------------------------------------------------
// MCP transport (protected)
// ---------------------------------------------------------------------------

app.post("/mcp", authMiddleware, async (req, res) => {
  const r = req as Request & { userId: string };
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let transport = sessionId ? transports[sessionId] : undefined;

  if (!transport && !sessionId && isInitializeRequest(req.body)) {
    const sessionServer = createServer();
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (sid: string) => {
        transports[sid] = transport!;
        servers[sid] = sessionServer;
        setSessionUser(sid, r.userId);
      },
    });
    transport.onclose = () => {
      const sid = transport!.sessionId;
      if (sid) {
        delete transports[sid];
        servers[sid]?.close();
        delete servers[sid];
        clearSession(sid);
      }
    };
    await sessionServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
    return;
  }

  if (!transport) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Bad Request: No valid session ID" },
      id: null,
    });
    return;
  }
  await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", authMiddleware, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;
  if (!transport) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }
  await transport.handleRequest(req, res);
});

app.delete("/mcp", authMiddleware, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;
  if (!transport) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }
  await transport.handleRequest(req, res);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const serverUrl = "http://localhost:" + PORT;
const httpServer = app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("  Google Calendar MCP server is running");
  console.log("  Open in browser: " + serverUrl);
  console.log("  Metadata: " + serverUrl + "/.well-known/oauth-authorization-server");
  console.log("  Test: " + serverUrl + "/ping");
  console.log("  Press Ctrl+C to stop");
  console.log("");
});

httpServer.on("error", (err: NodeJS.ErrnoException) => {
  console.error("Server failed to start:", err.message);
  if (err.code === "EADDRINUSE") {
    console.error("Port " + PORT + " is already in use. Try PORT=3001 npm run serve");
  }
  process.exit(1);
});

process.on("SIGINT", async () => {
  for (const t of Object.values(transports)) await t.close().catch(() => {});
  for (const s of Object.values(servers)) await s.close().catch(() => {});
  httpServer.close();
  process.exit(0);
});
