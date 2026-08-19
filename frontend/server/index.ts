import express from "express";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const server = createServer(app);

  // Serve static files from dist/public in production
  const staticPath = path.resolve(__dirname, "public");

  app.use(express.static(staticPath));

  // Handle client-side routing - serve index.html for all routes
  app.get("*", (_req, res) => {
    res.sendFile(path.join(staticPath, "index.html"));
  });

  const host = process.env.HOST || "0.0.0.0";
  const port = Number(process.env.PORT || 3000);

  server.listen(port, host, () => {
    console.log(`TraceLock Control Center running on http://${host}:${port}`);
  });
}

startServer().catch((error) => {
  console.error("Frontend server failed to start", error);
  process.exitCode = 1;
});
