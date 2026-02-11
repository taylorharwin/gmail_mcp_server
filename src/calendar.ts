import { createHash } from "node:crypto";
import { google } from "googleapis";
import { loadTokens, saveTokens, type StoredTokens } from "./storage.js";

const SCOPES = ["https://www.googleapis.com/auth/calendar"];

export function getAuthUrl(clientId: string, redirectUri: string, state: string, codeVerifier: string): string {
  const oauth2 = new google.auth.OAuth2(clientId, undefined, redirectUri);
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  return oauth2.generateAuthUrl({
    access_type: "offline",
    scope: SCOPES,
    prompt: "consent",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256" as import("google-auth-library").CodeChallengeMethod,
  });
}

export async function exchangeCode(
  clientId: string,
  clientSecret: string,
  redirectUri: string,
  code: string,
  codeVerifier: string
): Promise<StoredTokens> {
  const oauth2 = new google.auth.OAuth2(clientId, clientSecret, redirectUri);
  const { tokens } = await oauth2.getToken({ code, codeVerifier });
  if (!tokens.refresh_token) throw new Error("No refresh_token in response");
  return {
    access_token: tokens.access_token!,
    refresh_token: tokens.refresh_token,
    expiry_date: tokens.expiry_date ?? 0,
  };
}

export async function getCalendarClient(
  userId: string,
  secret: string,
  clientId: string,
  clientSecret: string
): Promise<ReturnType<typeof google.calendar>> {
  const stored = loadTokens(userId, secret);
  if (!stored) throw new Error("Not authenticated");

  const oauth2 = new google.auth.OAuth2(clientId, clientSecret, undefined);
  oauth2.setCredentials({
    access_token: stored.access_token,
    refresh_token: stored.refresh_token,
    expiry_date: stored.expiry_date,
  });

  if (stored.expiry_date && stored.expiry_date <= Date.now() + 60_000) {
    const { credentials } = await oauth2.refreshAccessToken();
    const next: StoredTokens = {
      access_token: credentials.access_token!,
      refresh_token: credentials.refresh_token ?? stored.refresh_token,
      expiry_date: credentials.expiry_date ?? 0,
    };
    saveTokens(userId, next, secret);
    oauth2.setCredentials(credentials);
  }

  return google.calendar({ version: "v3", auth: oauth2 });
}

export async function listCalendars(
  client: Awaited<ReturnType<typeof getCalendarClient>>,
  minAccessRole?: string
): Promise<{ id: string; summary: string; primary?: boolean; accessRole: string }[]> {
  const res = await client.calendarList.list({ minAccessRole });
  return (res.data.items ?? []).map((c) => ({
    id: c.id!,
    summary: c.summary ?? "",
    primary: c.primary ?? undefined,
    accessRole: c.accessRole ?? "freeBusyReader",
  }));
}

export async function listEvents(
  client: Awaited<ReturnType<typeof getCalendarClient>>,
  calendarId: string,
  timeMin: string,
  timeMax: string,
  maxResults: number,
  q?: string
): Promise<{ id: string; summary: string; start: string; end: string; status: string; htmlLink: string }[]> {
  const res = await client.events.list({
    calendarId,
    timeMin,
    timeMax,
    maxResults,
    q: q || undefined,
    singleEvents: true,
  });
  return (res.data.items ?? []).map((e) => ({
    id: e.id!,
    summary: e.summary ?? "",
    start: (e.start?.dateTime ?? e.start?.date) ?? "",
    end: (e.end?.dateTime ?? e.end?.date) ?? "",
    status: e.status ?? "confirmed",
    htmlLink: e.htmlLink ?? "",
  }));
}

export async function listAcl(
  client: Awaited<ReturnType<typeof getCalendarClient>>,
  calendarId: string
): Promise<{ id: string; scope: { type: string; value: string }; role: string }[]> {
  const res = await client.acl.list({ calendarId });
  return (res.data.items ?? []).map((rule) => ({
    id: rule.id!,
    scope: {
      type: rule.scope?.type ?? "unknown",
      value: rule.scope?.value ?? "",
    },
    role: rule.role ?? "none",
  }));
}

export async function createEvent(
  client: Awaited<ReturnType<typeof getCalendarClient>>,
  calendarId: string,
  summary: string,
  start: string,
  end: string,
  description?: string,
  attendees?: string[]
): Promise<{ id: string; htmlLink: string; start: string; end: string }> {
  const res = await client.events.insert({
    calendarId,
    requestBody: {
      summary,
      description: description ?? undefined,
      start: { dateTime: start, timeZone: "UTC" },
      end: { dateTime: end, timeZone: "UTC" },
      attendees: attendees?.map((email) => ({ email })),
    },
  });
  const e = res.data;
  return {
    id: e.id!,
    htmlLink: e.htmlLink ?? "",
    start: (e.start?.dateTime ?? e.start?.date) ?? "",
    end: (e.end?.dateTime ?? e.end?.date) ?? "",
  };
}
