import { createServer } from "node:http";
import { readFileSync, readdirSync } from "node:fs";
import { join, extname } from "node:path";

const PORT = parseInt(process.argv[2] || "4100", 10);
const REPORT_DIR = join(import.meta.dirname, "..", "report");
const DASHBOARD_DIR = import.meta.dirname;

const MIME: Record<string, string> = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".svg": "image/svg+xml",
};

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

  // CORS headers for local dev
  res.setHeader("Access-Control-Allow-Origin", "*");

  // API: list reports
  if (url.pathname === "/api/reports") {
    try {
      const files = readdirSync(REPORT_DIR)
        .filter((f) => f.endsWith(".json"))
        .sort()
        .reverse();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(files));
    } catch {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("[]");
    }
    return;
  }

  // API: get a specific report
  if (url.pathname.startsWith("/api/report/")) {
    const filename = url.pathname.slice("/api/report/".length);
    // Prevent path traversal
    if (filename.includes("..") || filename.includes("/")) {
      res.writeHead(400);
      res.end("Bad request");
      return;
    }
    try {
      const data = readFileSync(join(REPORT_DIR, filename), "utf-8");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(data);
    } catch {
      res.writeHead(404);
      res.end("Not found");
    }
    return;
  }

  // Serve static files from dashboard dir
  let filePath = url.pathname === "/" ? "/index.html" : url.pathname;
  // Prevent path traversal
  if (filePath.includes("..")) {
    res.writeHead(400);
    res.end("Bad request");
    return;
  }
  try {
    const fullPath = join(DASHBOARD_DIR, filePath);
    const data = readFileSync(fullPath);
    const mime = MIME[extname(fullPath)] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": mime });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
});

server.listen(PORT, () => {
  console.log(`\n  Red Team Dashboard → http://localhost:${PORT}\n`);
});
