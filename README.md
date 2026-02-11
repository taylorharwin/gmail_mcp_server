# Google Calendar MCP Server

Remote MCP server for Google Calendar (Streamable HTTP + OAuth 2.1 with PKCE). Tools: `list_calendars`, `list_events`, `create_event`.

## Quick Start (5 min)

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

4. **Sign in**: Open `http://localhost:3000/authorize` in a browser; after Google consent you’ll get a session token. Use it as Bearer token for MCP requests.

## OAuth scopes (least-privilege)

- `https://www.googleapis.com/auth/calendar.events` — view and edit events
- `https://www.googleapis.com/auth/calendar.readonly` — list calendars

## Tools (JSON Schema summary)

| Tool | Input | Output |
|------|--------|--------|
| `list_calendars` | `minAccessRole?: string` | `{ items: { id, summary, primary?, accessRole }[] }` |
| `list_events` | `calendarId`, `timeMin`, `timeMax` (ISO), `maxResults` (default 50), `q?` | `{ items: { id, summary, start, end, status, htmlLink }[] }` |
| `create_event` | `calendarId`, `summary`, `start`, `end` (ISO), `description?`, `attendees?` (string[]) | `{ id, htmlLink, start, end }` |

## Client config (Cursor / Claude)

Point the MCP client at your server URL. Auth: use the token from `/auth/success` as Bearer for the session.

Example (after you have a token):

```bash
# POST /mcp with session from GET (initialize first to get session id)
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: YOUR_SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_calendars","arguments":{}}}'
```

## Examples

1. **list_calendars** — `arguments: {}` or `{ "minAccessRole": "writer" }`.
2. **list_events** — `arguments: { "calendarId": "primary", "timeMin": "2025-02-10T00:00:00Z", "timeMax": "2025-02-11T00:00:00Z", "maxResults": 10 }`.
3. **create_event** — `arguments: { "calendarId": "primary", "summary": "Meeting", "start": "2025-02-15T14:00:00Z", "end": "2025-02-15T15:00:00Z" }`.

## Trade-offs

- Phase 1: three tools only; more (get/update/delete event, ACL/freebusy) can be added later.
- Tokens stored encrypted (memory + optional file via `TOKEN_STORE_PATH`). Sessions in memory.
- No dynamic client registration or full RFC 8414 metadata; single user per server instance for simplicity.

## Security

- PKCE (S256) for Google OAuth; tokens encrypted at rest; no tokens in logs.
- Validate `Origin` in production; use HTTPS for `BASE_URL` in production.

## Stack (open source)

- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) — Streamable HTTP transport, tools, JSON-RPC
- [googleapis](https://github.com/googleapis/google-api-nodejs-client) — Google Calendar API + OAuth2
- [Express](https://expressjs.com/), [Zod](https://zod.dev/); Node `crypto` for token encryption
