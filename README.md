# Google Calendar MCP Server

Remote MCP server for Google Calendar (Streamable HTTP + OAuth 2.1 with PKCE). Tools: `list_calendars`, `list_events`, `list_acl`, `create_event`.

## Quick Start

1. **Google Cloud**: Create a project, enable [Calendar API](https://console.cloud.google.com/apis/library/calendar-json.googleapis.com), configure OAuth consent screen, create OAuth 2.0 Client ID (Web app). Add redirect URI: `http://localhost:3000/callback`.

2. **Env**:
   ```bash
   cp .env.example .env
   # Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL (e.g. http://localhost:3000), TOKEN_ENCRYPTION_KEY (32+ chars)
   ```

3. **Run**:
   ```bash
   npm install && npm start
   ```

4. **Connect**: Point an MCP client (Claude Desktop, Cursor, etc.) at `http://localhost:3000/mcp`. The client will discover the OAuth flow automatically via the well-known metadata endpoints.

## OAuth flow (MCP-spec compliant)

The server acts as both an OAuth 2.1 Authorization Server and a Resource Server, wrapping Google OAuth underneath. The flow follows the [MCP authorization spec (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

```
MCP Client → POST /mcp (no token)
         ← 401 + WWW-Authenticate with resource_metadata URL

MCP Client → GET /.well-known/oauth-protected-resource
         ← { resource, authorization_servers: [BASE_URL] }

MCP Client → GET /.well-known/oauth-authorization-server
         ← { issuer, authorization_endpoint, token_endpoint, ... }

MCP Client → (browser) GET /authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&state=...
         → server redirects to Google OAuth consent
         → Google redirects back to /callback
         → server redirects to MCP client's redirect_uri with ?code=...&state=...

MCP Client → POST /token (grant_type=authorization_code, code, code_verifier, redirect_uri, client_id)
         ← { access_token, token_type: "Bearer", expires_in, refresh_token }

MCP Client → POST /mcp with Authorization: Bearer <access_token>
         ← Calendar data
```

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 protected resource metadata |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 authorization server metadata |
| `/authorize` | GET | OAuth authorization endpoint (redirects to Google) |
| `/callback` | GET | Google OAuth redirect URI (redirects to MCP client) |
| `/token` | POST | OAuth token endpoint (authorization_code, refresh_token) |
| `/mcp` | POST/GET/DELETE | MCP transport (protected, requires Bearer token) |

### Token lifecycle

- **Authorization codes**: 10 min TTL, single-use. Replay triggers revocation of all associated tokens.
- **Access tokens**: configurable via `ACCESS_TOKEN_TTL_SECONDS` (default 3600 = 1 hour).
- **Refresh tokens**: long-lived. Use `grant_type=refresh_token` at `/token` to get a new access token.

## Google OAuth scope

- `https://www.googleapis.com/auth/calendar` — full read/write access to calendars, events, and ACL.

## Tools (JSON Schema summary)

| Tool | Input | Output |
|------|--------|--------|
| `list_calendars` | `minAccessRole?: string` | `{ items: { id, summary, primary?, accessRole }[] }` |
| `list_events` | `calendarId`, `timeMin`, `timeMax` (ISO), `maxResults` (default 50), `q?` | `{ items: { id, summary, start, end, status, htmlLink }[] }` |
| `list_acl` | `calendarId` | `{ items: { id, scope: { type, value }, role }[] }` |
| `create_event` | `calendarId`, `summary`, `start`, `end` (ISO), `description?`, `attendees?` (string[]) | `{ id, htmlLink, start, end }` |

## Examples

1. **list_calendars** — `arguments: {}` or `{ "minAccessRole": "writer" }`.
2. **list_events** — `arguments: { "calendarId": "primary", "timeMin": "2025-02-10T00:00:00Z", "timeMax": "2025-02-11T00:00:00Z", "maxResults": 10 }`.
3. **list_acl** — `arguments: { "calendarId": "primary" }`.
4. **create_event** — `arguments: { "calendarId": "primary", "summary": "Meeting", "start": "2025-02-15T14:00:00Z", "end": "2025-02-15T15:00:00Z" }`.

## Adding a `delete_event` tool

### 1. Add the Google Calendar API call in `src/calendar.ts`

```ts
export async function deleteEvent(
  client: Awaited<ReturnType<typeof getCalendarClient>>,
  calendarId: string,
  eventId: string
): Promise<void> {
  await client.events.delete({ calendarId, eventId });
}
```

### 2. Register the tool in `src/tools.ts`

Import `deleteEvent` from `./calendar.js`, then add inside `registerTools()`:

```ts
server.registerTool(
  "delete_event",
  {
    description: "Delete a calendar event",
    inputSchema: {
      calendarId: z.string().describe("Calendar ID (e.g. primary)"),
      eventId: z.string().describe("Event ID to delete"),
    },
    outputSchema: {
      deleted: z.boolean(),
    },
  },
  async (args, extra) => {
    const client = await calendarFor(extra);
    await deleteEvent(client, args.calendarId, args.eventId);
    return { content: [], structuredContent: { deleted: true } };
  }
);
```

### 3. Update the tools table above

Add a row for `delete_event` to the **Tools** table in this README.

### 4. Test it

```bash
npm run dev
# Call via MCP:
# arguments: { "calendarId": "primary", "eventId": "EVENT_ID_HERE" }
```

You can get event IDs from the `list_events` tool output.

## Security

- MCP-spec compliant OAuth 2.1 with PKCE (S256) — server acts as its own Authorization Server wrapping Google OAuth
- Protected Resource Metadata (RFC 9728) and Authorization Server Metadata (RFC 8414)
- Google tokens encrypted at rest (AES-256-GCM with scrypt-derived keys)
- Authorization codes are single-use with replay detection and token revocation
- No tokens in logs or URLs; Bearer tokens in Authorization header only
- Use HTTPS for `BASE_URL` in production

## Stack (open source)

- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) — Streamable HTTP transport, tools, JSON-RPC
- [googleapis](https://github.com/googleapis/google-api-nodejs-client) — Google Calendar API + OAuth2
- [Express](https://expressjs.com/), [Zod](https://zod.dev/); Node `crypto` for token encryption
