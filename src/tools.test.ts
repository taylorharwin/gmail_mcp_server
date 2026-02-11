import { describe, it, expect } from "vitest";
import { setSessionUser, getUserIdForSession, clearSession } from "./tools.js";

describe("session-user mapping", () => {
  it("stores and retrieves a mapping", () => {
    setSessionUser("sess-1", "user-a");
    expect(getUserIdForSession("sess-1")).toBe("user-a");
  });

  it("returns undefined for unknown session", () => {
    expect(getUserIdForSession("unknown")).toBeUndefined();
  });

  it("clears a mapping", () => {
    setSessionUser("sess-2", "user-b");
    clearSession("sess-2");
    expect(getUserIdForSession("sess-2")).toBeUndefined();
  });
});
