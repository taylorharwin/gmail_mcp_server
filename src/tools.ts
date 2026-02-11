import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { getCalendarClient, listCalendars, listEvents, listAcl, createEvent } from "./calendar.js";

const secret = () => process.env.TOKEN_ENCRYPTION_KEY!;
const clientId = () => process.env.GOOGLE_CLIENT_ID!;
const clientSecret = () => process.env.GOOGLE_CLIENT_SECRET!;

const sessionToUserId = new Map<string, string>();

export function setSessionUser(sessionId: string, userId: string): void {
  sessionToUserId.set(sessionId, userId);
}

export function getUserIdForSession(sessionId: string): string | undefined {
  return sessionToUserId.get(sessionId);
}

export function clearSession(sessionId: string): void {
  sessionToUserId.delete(sessionId);
}

export function registerTools(server: McpServer): void {
  server.tool(
    "list_calendars",
    "List calendars the user can access",
    { minAccessRole: z.string().optional().describe("Optional filter by min access role") },
    async (args, extra) => {
      const userId = extra?.sessionId ? getUserIdForSession(extra.sessionId) : undefined;
      if (!userId) throw new Error("Not authenticated");
      const client = await getCalendarClient(userId, secret(), clientId(), clientSecret());
      const items = await listCalendars(client, args.minAccessRole);
      return { content: [{ type: "text" as const, text: JSON.stringify({ items }, null, 2) }] };
    }
  );

  server.tool(
    "list_events",
    "List events in a calendar",
    {
      calendarId: z.string().describe("Calendar ID (e.g. primary)"),
      timeMin: z.string().describe("ISO datetime min"),
      timeMax: z.string().describe("ISO datetime max"),
      maxResults: z.number().default(50),
      q: z.string().optional(),
    },
    async (args, extra) => {
      const userId = extra?.sessionId ? getUserIdForSession(extra.sessionId) : undefined;
      if (!userId) throw new Error("Not authenticated");
      const client = await getCalendarClient(userId, secret(), clientId(), clientSecret());
      const items = await listEvents(
        client,
        args.calendarId,
        args.timeMin,
        args.timeMax,
        args.maxResults,
        args.q
      );
      return { content: [{ type: "text" as const, text: JSON.stringify({ items }, null, 2) }] };
    }
  );

  server.tool(
    "list_acl",
    "List access control rules for a calendar (who has access and their role)",
    {
      calendarId: z.string().describe("Calendar ID (e.g. primary)"),
    },
    async (args, extra) => {
      const userId = extra?.sessionId ? getUserIdForSession(extra.sessionId) : undefined;
      if (!userId) throw new Error("Not authenticated");
      const client = await getCalendarClient(userId, secret(), clientId(), clientSecret());
      const items = await listAcl(client, args.calendarId);
      return { content: [{ type: "text" as const, text: JSON.stringify({ items }, null, 2) }] };
    }
  );

  server.tool(
    "create_event",
    "Create a calendar event",
    {
      calendarId: z.string(),
      summary: z.string(),
      start: z.string().describe("ISO datetime"),
      end: z.string().describe("ISO datetime"),
      description: z.string().optional(),
      attendees: z.array(z.string()).optional(),
    },
    async (args, extra) => {
      const userId = extra?.sessionId ? getUserIdForSession(extra.sessionId) : undefined;
      if (!userId) throw new Error("Not authenticated");
      const client = await getCalendarClient(userId, secret(), clientId(), clientSecret());
      const event = await createEvent(
        client,
        args.calendarId,
        args.summary,
        args.start,
        args.end,
        args.description,
        args.attendees
      );
      return { content: [{ type: "text" as const, text: JSON.stringify(event, null, 2) }] };
    }
  );
}
