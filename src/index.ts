import { config } from "dotenv";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: join(__dirname, "..", ".env") });

import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { GoogleCalendarOAuthProvider } from "./auth.js";
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

// ---------------------------------------------------------------------------
// OAuth (SDK-provided routes + custom Google callback)
// ---------------------------------------------------------------------------

const provider = new GoogleCalendarOAuthProvider();

app.use(mcpAuthRouter({
  provider,
  issuerUrl: new URL(BASE_URL),
  baseUrl: new URL(BASE_URL),
}));

const bearerAuth = requireBearerAuth({
  verifier: provider,
  resourceMetadataUrl: `${BASE_URL}/.well-known/oauth-protected-resource`,
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code || typeof code !== "string" || !state || typeof state !== "string") {
    res.status(400).send("Missing code or state");
    return;
  }
  if (!process.env.GOOGLE_CLIENT_SECRET || !process.env.TOKEN_ENCRYPTION_KEY) {
    res.status(500).send("Server configuration error");
    return;
  }
  try {
    const redirectUrl = await provider.handleGoogleCallback(code, state);
    res.redirect(302, redirectUrl);
  } catch (e) {
    res.status(400).send("Auth failed: " + (e instanceof Error ? e.message : String(e)));
  }
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get("/ping", (_req, res) => {
  res.set("Content-Type", "text/plain").send("pong");
});

// ---------------------------------------------------------------------------
// MCP transport (protected)
// ---------------------------------------------------------------------------

app.post("/mcp", bearerAuth, async (req, res) => {
  const userId = req.auth!.extra!.userId as string;
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
        setSessionUser(sid, userId);
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

app.get("/mcp", bearerAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;
  if (!transport) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }
  await transport.handleRequest(req, res);
});

app.delete("/mcp", bearerAuth, async (req, res) => {
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
