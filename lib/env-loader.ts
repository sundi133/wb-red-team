import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface LoadEnvOptions {
  override?: boolean;
  envPath?: string;
}

export function loadEnvFile(options: LoadEnvOptions = {}): void {
  const envPath = options.envPath ?? join(process.cwd(), ".env");
  const override = options.override ?? true;

  if (!existsSync(envPath)) return;

  for (const line of readFileSync(envPath, "utf-8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;

    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();

    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }

    if (override || !process.env[key]) {
      process.env[key] = val;
    }
  }
}
