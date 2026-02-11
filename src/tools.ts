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

type CalendarClient = Awaited<ReturnType<typeof getCalendarClient>>;

async function calendarFor(extra: { sessionId?: string }): Promise<CalendarClient> {
  const userId = extra?.sessionId ? getUserIdForSession(extra.sessionId) : undefined;
  if (!userId) throw new Error("Not authenticated");
  return getCalendarClient(userId, secret(), clientId(), clientSecret());
}

export function registerTools(server: McpServer): void {
  server.registerTool(
    "list_calendars",
    {
      description: "List calendars the user can access",
      inputSchema: {
        minAccessRole: z.string().optional().describe("Optional filter by min access role"),
      },
      outputSchema: {
        items: z.array(z.object({
          id: z.string(),
          summary: z.string(),
          primary: z.boolean().optional(),
          accessRole: z.string(),
        })),
      },
    },
    async (args, extra) => {
      const client = await calendarFor(extra);
      const items = await listCalendars(client, args.minAccessRole);
      return { content: [], structuredContent: { items } };
    }
  );

  server.registerTool(
    "list_events",
    {
      description: "List events in a calendar",
      inputSchema: {
        calendarId: z.string().describe("Calendar ID (e.g. primary)"),
        timeMin: z.string().describe("ISO datetime min"),
        timeMax: z.string().describe("ISO datetime max"),
        maxResults: z.number().default(50),
        q: z.string().optional(),
      },
      outputSchema: {
        items: z.array(z.object({
          id: z.string(),
          summary: z.string(),
          start: z.string(),
          end: z.string(),
          status: z.string(),
          htmlLink: z.string(),
        })),
      },
    },
    async (args, extra) => {
      const client = await calendarFor(extra);
      const items = await listEvents(client, args.calendarId, args.timeMin, args.timeMax, args.maxResults, args.q);
      return { content: [], structuredContent: { items } };
    }
  );

  server.registerTool(
    "list_acl",
    {
      description: "List access control rules for a calendar (who has access and their role)",
      inputSchema: {
        calendarId: z.string().describe("Calendar ID (e.g. primary)"),
      },
      outputSchema: {
        items: z.array(z.object({
          id: z.string(),
          scope: z.object({
            type: z.string(),
            value: z.string(),
          }),
          role: z.string(),
        })),
      },
    },
    async (args, extra) => {
      const client = await calendarFor(extra);
      const items = await listAcl(client, args.calendarId);
      return { content: [], structuredContent: { items } };
    }
  );

  server.registerTool(
    "create_event",
    {
      description: "Create a calendar event",
      inputSchema: {
        calendarId: z.string(),
        summary: z.string(),
        start: z.string().describe("ISO datetime"),
        end: z.string().describe("ISO datetime"),
        description: z.string().optional(),
        attendees: z.array(z.string()).optional(),
      },
      outputSchema: {
        id: z.string(),
        htmlLink: z.string(),
        start: z.string(),
        end: z.string(),
      },
    },
    async (args, extra) => {
      const client = await calendarFor(extra);
      const event = await createEvent(
        client, args.calendarId, args.summary, args.start, args.end, args.description, args.attendees
      );
      return { content: [], structuredContent: event };
    }
  );
}
