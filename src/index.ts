import "dotenv/config";
import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer, StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server";
import { isInitializeRequest } from "@modelcontextprotocol/sdk";
import { createPendingAuth, handleCallback, authMiddleware } from "./auth.js";
import { registerTools, setSessionUser, clearSession } from "./tools.js";

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const server = new McpServer(
  { name: "google-calendar-mcp", version: "1.0.0" },
  { capabilities: { tools: { listChanged: false } } }
);
registerTools(server);

const transports: Record<string, StreamableHTTPServerTransport> = {};

const app = express();
app.use(express.json());

app.get("/authorize", (_req, res) => {
  const { authUrl } = createPendingAuth();
  res.redirect(302, authUrl);
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
    res.redirect(302, `${BASE_URL}/auth/success?token=${encodeURIComponent(sessionToken)}`);
  } catch (e) {
    res.status(400).send("Auth failed: " + (e instanceof Error ? e.message : String(e)));
  }
});

app.get("/auth/success", (req, res) => {
  const token = req.query.token as string;
  res.set("Content-Type", "text/html").send(
    `<!DOCTYPE html><html><body><p>Signed in. Use this token in your MCP client:</p><pre>${token ?? ""}</pre></body></html>`
  );
});

app.post("/mcp", authMiddleware, async (req: express.Request & { userId: string }, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let transport = sessionId ? transports[sessionId] : undefined;

  if (!transport && !sessionId && isInitializeRequest(req.body)) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (sid) => {
        transports[sid] = transport!;
        setSessionUser(sid, req.userId);
      },
    });
    transport.onclose = () => {
      const sid = transport!.sessionId;
      if (sid) {
        delete transports[sid];
        clearSession(sid);
      }
    };
    await server.connect(transport);
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

app.get("/mcp", authMiddleware, async (req: express.Request & { userId: string }, res) => {
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

app.listen(PORT, () => {
  console.log(`MCP server at ${BASE_URL} (POST/GET/DELETE /mcp). Sign in: ${BASE_URL}/authorize`);
});

process.on("SIGINT", async () => {
  for (const t of Object.values(transports)) await t.close().catch(() => {});
  await server.close();
  process.exit(0);
});
