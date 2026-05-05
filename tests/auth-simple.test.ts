import { afterEach, describe, expect, it } from "vitest";
import {
  buildSimpleSessionCookie,
  getSimpleSessionUser,
  loginSimpleUser,
  validateSimpleSession,
} from "../lib/auth-simple.js";

const ORIGINAL_ENV = {
  AUTH_MODE: process.env.AUTH_MODE,
  SIMPLE_AUTH_USERNAME: process.env.SIMPLE_AUTH_USERNAME,
  SIMPLE_AUTH_PASSWORD: process.env.SIMPLE_AUTH_PASSWORD,
  SIMPLE_AUTH_ROLE: process.env.SIMPLE_AUTH_ROLE,
  SIMPLE_AUTH_NAME: process.env.SIMPLE_AUTH_NAME,
  SIMPLE_AUTH_SESSION_SECRET: process.env.SIMPLE_AUTH_SESSION_SECRET,
  SIMPLE_AUTH_USERS: process.env.SIMPLE_AUTH_USERS,
  __DB_DISABLED: process.env.__DB_DISABLED,
  DATABASE_URL: process.env.DATABASE_URL,
};

afterEach(() => {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

describe("simple auth", () => {
  it("creates and validates a cookie-backed session", async () => {
    process.env.__DB_DISABLED = "1";
    delete process.env.DATABASE_URL;
    process.env.SIMPLE_AUTH_USERNAME = "admin";
    process.env.SIMPLE_AUTH_PASSWORD = "secret";
    process.env.SIMPLE_AUTH_ROLE = "admin";
    process.env.SIMPLE_AUTH_NAME = "Admin User";
    process.env.SIMPLE_AUTH_SESSION_SECRET = "test-secret";

    const login = await loginSimpleUser("admin", "secret");
    const cookieHeader = buildSimpleSessionCookie(login.token);
    const auth = await validateSimpleSession(cookieHeader);
    const user = await getSimpleSessionUser(cookieHeader);

    expect(auth.sub).toBe("simple:admin");
    expect(auth.role).toBe("admin");
    expect(user.name).toBe("Admin User");
    expect(user.username).toBe("admin");
  });

  it("supports multiple env-defined users", async () => {
    process.env.__DB_DISABLED = "1";
    delete process.env.DATABASE_URL;
    process.env.SIMPLE_AUTH_SESSION_SECRET = "test-secret";
    process.env.SIMPLE_AUTH_USERS = JSON.stringify([
      {
        username: "viewer1",
        password: "pw1",
        role: "viewer",
        name: "View Only",
      },
      {
        username: "auditor1",
        password: "pw2",
        role: "auditor",
      },
    ]);

    const login = await loginSimpleUser("auditor1", "pw2");
    const user = await getSimpleSessionUser(
      buildSimpleSessionCookie(login.token),
    );

    expect(user.username).toBe("auditor1");
    expect(user.role).toBe("auditor");
  });
});
