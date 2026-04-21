/**
 * Loads compliance frameworks from JSON files in the compliance/ directory.
 * Users can add custom frameworks by dropping JSON files there.
 */

import { readFileSync, readdirSync } from "fs";
import { join, resolve } from "path";
import type { ComplianceFramework, ComplianceItem } from "./compliance-mappings.js";

// Fallback: built-in frameworks from compliance-mappings.ts
import { ALL_FRAMEWORKS as BUILTIN_FRAMEWORKS } from "./compliance-mappings.js";

const COMPLIANCE_DIR = resolve(
  import.meta.dirname ?? process.cwd(),
  "..",
  "compliance",
);

/**
 * Load all compliance frameworks from JSON files in the compliance/ directory.
 * Falls back to built-in OWASP frameworks if directory is missing or empty.
 */
export function loadComplianceFrameworks(
  complianceDir?: string,
): ComplianceFramework[] {
  const dir = complianceDir ?? COMPLIANCE_DIR;
  const frameworks: ComplianceFramework[] = [];

  try {
    const files = readdirSync(dir).filter((f) => f.endsWith(".json"));

    for (const file of files) {
      try {
        const raw = readFileSync(join(dir, file), "utf-8");
        const data = JSON.parse(raw);

        if (!data.id || !data.name || !Array.isArray(data.items)) {
          console.warn(
            `  Compliance: skipping ${file} — missing id, name, or items`,
          );
          continue;
        }

        // Validate items have required fields
        const validItems: ComplianceItem[] = [];
        for (const item of data.items) {
          if (
            item.code &&
            item.title &&
            item.description &&
            Array.isArray(item.categories)
          ) {
            validItems.push(item);
          }
        }

        if (validItems.length === 0) {
          console.warn(
            `  Compliance: skipping ${file} — no valid items found`,
          );
          continue;
        }

        frameworks.push({
          id: data.id,
          name: data.name,
          items: validItems,
        });
      } catch (err) {
        console.warn(
          `  Compliance: failed to load ${file}: ${(err as Error).message}`,
        );
      }
    }
  } catch {
    // Directory doesn't exist — fall through to built-in frameworks
  }

  // Fall back to built-in frameworks if no files were loaded
  if (frameworks.length === 0) {
    return BUILTIN_FRAMEWORKS;
  }

  return frameworks;
}

/**
 * List available framework IDs and names without loading full content.
 */
export function listComplianceFrameworks(
  complianceDir?: string,
): { id: string; name: string; controlCount: number }[] {
  return loadComplianceFrameworks(complianceDir).map((fw) => ({
    id: fw.id,
    name: fw.name,
    controlCount: fw.items.length,
  }));
}
