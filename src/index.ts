import { config } from "dotenv";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: join(__dirname, "..", ".env") });

import { randomUUID } from "node:crypto";
import express, { type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createPendingAuth, handleCallback, authMiddleware } from "./auth.js";
import { registerTools, setSessionUser, clearSession } from "./tools.js";

const PORT = Number(process.env.PORT) || 3001;
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
function htmlPage(title: string, body: string): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head><body style="font-family:sans-serif;max-width:480px;margin:2rem auto;padding:1.5rem;background:#eee;color:#111;"><h1 style="margin-top:0">${escapeHtml(title)}</h1>${body}</body></html>`;
}
function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

app.get("/", (_req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(
    htmlPage("Google Calendar MCP", "<p>Server is running.</p><p><a href=\"/authorize\" style=\"display:inline-block;background:#4285f4;color:white;padding:0.5rem 1rem;text-decoration:none;border-radius:4px;\">Sign in with Google</a></p>")
  );
});

app.get("/ping", (_req, res) => {
  res.set("Content-Type", "text/plain").send("pong");
});

app.get("/authorize", (_req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    res.status(500).set("Content-Type", "text/html").send(
      htmlPage("Error", "<p style=\"color:red\">GOOGLE_CLIENT_ID is not set in .env</p>")
    );
    return;
  }
  try {
    const { authUrl } = createPendingAuth();
    res.redirect(302, authUrl);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    res.status(500).set("Content-Type", "text/html").send(
      htmlPage("Error", "<p style=\"color:red\">" + escapeHtml(msg) + "</p>")
    );
  }
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const secret = process.env.TOKEN_ENCRYPTION_KEY;
  if (!code || typeof code !== "string" || !state || typeof state !== "string" || !clientSecret || !secret) {
    res.status(400).send("Missing code, state, or server config");
    return;
  }
  try {
    const { sessionToken } = await handleCallback(code, state, clientSecret, secret);
    const tokenPath = process.env.MCP_TOKEN_FILE || join(__dirname, "..", ".mcp-token");
    writeFileSync(tokenPath, sessionToken, "utf8");
    res.redirect(302, `${BASE_URL}/auth/success?token=${encodeURIComponent(sessionToken)}`);
  } catch (e) {
    res.status(400).send("Auth failed: " + (e instanceof Error ? e.message : String(e)));
  }
});

app.get("/auth/success", (req, res) => {
  const token = (req.query.token as string) ?? "";
  const tokenPath = process.env.MCP_TOKEN_FILE || join(__dirname, "..", ".mcp-token");
  const savedNote = token ? "<p>Token also saved to <code>" + escapeHtml(tokenPath) + "</code></p>" : "";
  res.set("Content-Type", "text/html").send(
    htmlPage("Signed in", "<p>Use this token in your MCP client (Bearer):</p><pre style=\"background:#fff;padding:1rem;overflow:auto\">" + escapeHtml(token) + "</pre>" + savedNote + (token ? "" : "<p style=\"color:red\">No token received. Try signing in again from <a href=\"/authorize\">/authorize</a>.</p>"))
  );
});

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

const serverUrl = "http://localhost:" + PORT;
const httpServer = app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("  Google Calendar MCP server is running");
  console.log("  Open in browser: " + serverUrl);
  console.log("  Sign in: " + serverUrl + "/authorize");
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
