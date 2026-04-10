/** Try to parse a JSON array from LLM output (handles refusals, markdown, and text around the array). */
export function parseJsonArrayFromLlmResponse<T = unknown>(text: string): T[] {
  let cleaned = (text || "[]")
    .trim()
    .replace(/^```(?:json)?\n?/i, "")
    .replace(/\n?```\s*$/i, "")
    .trim();
  if (
    cleaned.startsWith("I'm sorry") ||
    cleaned.startsWith("I cannot") ||
    cleaned.startsWith("I can't") ||
    (!cleaned.startsWith("[") && cleaned.includes("["))
  ) {
    const start = cleaned.indexOf("[");
    if (start >= 0) {
      let depth = 0;
      let end = -1;
      for (let i = start; i < cleaned.length; i++) {
        if (cleaned[i] === "[") depth++;
        else if (cleaned[i] === "]") {
          depth--;
          if (depth === 0) {
            end = i;
            break;
          }
        }
      }
      if (end > start) cleaned = cleaned.slice(start, end + 1);
    } else {
      cleaned = "[]";
    }
  }
  try {
    const parsed = JSON.parse(cleaned) as unknown;
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
