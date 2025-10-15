import http from "node:http";
import path from "node:path";
import { createBareServer } from "@nebula-services/bare-server-node";
import chalk from "chalk";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import basicAuth from "express-basic-auth";
import mime from "mime";
import fetch from "node-fetch";
// import { setupMasqr } from "./Masqr.js";
import config from "./config.js";
import DeviceManager from "./device-manager.js";

console.log(chalk.yellow("🚀 Starting server..."));

const __dirname = process.cwd();
const server = http.createServer();
const app = express();
const bareServer = createBareServer("/ca/");
const PORT = process.env.PORT || 8080;
const cache = new Map();
const CACHE_TTL = 30 * 24 * 60 * 60 * 1000; // Cache for 30 Days
const deviceManager = new DeviceManager();

if (config.challenge !== false) {
  console.log(chalk.green("🔒 Password protection is enabled! Listing logins below"));
  Object.entries(config.users).forEach(([username, password]) => {
    console.log(chalk.blue(`Username: ${username}, Password: ${password}`));
  });
  app.use(basicAuth({ users: config.users, challenge: true }));
}

// Device approval middleware
app.use((req, res, next) => {
  // Skip device check for API endpoints, static files, admin pages, and device approval page
  if (req.path.startsWith("/api/") || req.path.startsWith("/assets/") || req.path.startsWith("/ca/") || req.path === "/admin" || req.path === "/waiting-approval") {
    return next();
  }

  const deviceInfo = deviceManager.getDeviceInfo(req);
  const status = deviceInfo.status;
  const username = deviceInfo.username;

  // Owner bypass - Owner can access without device approval
  if (username === "Owner") {
    console.log(chalk.green(`👑 Owner access granted: ${username} (${deviceInfo.ip}) - Session: ${deviceInfo.sessionId}`));
    deviceManager.addActiveSession(deviceInfo);
    return next();
  }

  if (status === "blocked") {
    console.log(chalk.red(`🚫 Blocked device attempted access: ${username} (${deviceInfo.ip}) - ${deviceInfo.userAgent} - Session: ${deviceInfo.sessionId}`));
    return res.status(403).send(`
      <html>
        <head><title>Access Denied</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5;">
          <h1 style="color: #d32f2f;">🚫 Access Denied</h1>
          <p>This device has been permanently blocked from accessing this proxy.</p>
          <p>Contact the administrator if you believe this is an error.</p>
        </body>
      </html>
    `);
  }

  if (status === "new") {
    console.log(chalk.yellow(`🆕 New device detected: ${username} (${deviceInfo.ip}) - ${deviceInfo.userAgent} - Session: ${deviceInfo.sessionId} - Fingerprint: ${deviceInfo.fingerprint.substring(0, 16)}...`));
    deviceManager.addPendingDeviceWithDetails(deviceInfo);
    return res.redirect("/waiting-approval");
  }

  if (status === "pending") {
    console.log(chalk.yellow(`⏳ Pending device attempted access: ${username} (${deviceInfo.ip}) - ${deviceInfo.userAgent} - Session: ${deviceInfo.sessionId}`));
    return res.redirect("/waiting-approval");
  }

  // Device is approved, continue and track session
  console.log(chalk.blue(`✅ Approved device access: ${username} (${deviceInfo.ip}) - Session: ${deviceInfo.sessionId}`));
  deviceManager.addActiveSession(deviceInfo);
  next();
});

app.get("/e/*", async (req, res, next) => {
  try {
    if (cache.has(req.path)) {
      const { data, contentType, timestamp } = cache.get(req.path);
      if (Date.now() - timestamp > CACHE_TTL) {
        cache.delete(req.path);
      } else {
        res.writeHead(200, { "Content-Type": contentType });
        return res.end(data);
      }
    }

    const baseUrls = {
      "/e/1/": "https://raw.githubusercontent.com/qrs/x/fixy/",
      "/e/2/": "https://raw.githubusercontent.com/3v1/V5-Assets/main/",
      "/e/3/": "https://raw.githubusercontent.com/3v1/V5-Retro/master/",
    };

    let reqTarget;
    for (const [prefix, baseUrl] of Object.entries(baseUrls)) {
      if (req.path.startsWith(prefix)) {
        reqTarget = baseUrl + req.path.slice(prefix.length);
        break;
      }
    }

    if (!reqTarget) {
      return next();
    }

    const asset = await fetch(reqTarget);
    if (!asset.ok) {
      return next();
    }

    const data = Buffer.from(await asset.arrayBuffer());
    const ext = path.extname(reqTarget);
    const no = [".unityweb"];
    const contentType = no.includes(ext) ? "application/octet-stream" : mime.getType(ext);

    cache.set(req.path, { data, contentType, timestamp: Date.now() });
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  } catch (error) {
    console.error("Error fetching asset:", error);
    res.setHeader("Content-Type", "text/html");
    res.status(500).send("Error fetching the asset");
  }
});

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* if (process.env.MASQR === "true") {
  console.log(chalk.green("Masqr is enabled"));
  setupMasqr(app);
} */

app.use(express.static(path.join(__dirname, "static")));
app.use("/ca", cors({ origin: true }));

const routes = [
  { path: "/b", file: "apps.html" },
  { path: "/a", file: "games.html" },
  { path: "/play.html", file: "games.html" },
  { path: "/c", file: "settings.html" },
  { path: "/d", file: "tabs.html" },
  { path: "/waiting-approval", file: "waiting-approval.html" },
  { path: "/admin", file: "admin.html" },
  { path: "/", file: "index.html" },
];

routes.forEach(route => {
  app.get(route.path, (_req, res) => {
    res.sendFile(path.join(__dirname, "static", route.file));
  });
});

// Device approval API endpoints
app.get("/api/device-info", (req, res) => {
  const deviceInfo = deviceManager.getDeviceInfo(req);
  res.json(deviceInfo);
});

app.get("/api/device-status", (req, res) => {
  const deviceInfo = deviceManager.getDeviceInfo(req);
  res.json({ status: deviceInfo.status });
});

app.post("/api/approve-device", (req, res) => {
  const { fingerprint } = req.body;
  const adminUser = req.auth ? req.auth.user : "Unknown";

  if (!fingerprint) {
    return res.status(400).json({ error: "Fingerprint is required" });
  }

  deviceManager.approveDevice(fingerprint);
  deviceManager.logAdminAction(adminUser, "approve_device", fingerprint, {});
  console.log(chalk.green(`✅ Device approved by ${adminUser}: ${fingerprint}`));

  res.json({ success: true, message: "Device approved successfully" });
});

app.post("/api/block-device", (req, res) => {
  const { fingerprint } = req.body;
  const adminUser = req.auth ? req.auth.user : "Unknown";

  if (!fingerprint) {
    return res.status(400).json({ error: "Fingerprint is required" });
  }

  deviceManager.blockDevice(fingerprint);
  deviceManager.logAdminAction(adminUser, "block_device", fingerprint, {});
  console.log(chalk.red(`🚫 Device blocked by ${adminUser}: ${fingerprint}`));

  res.json({ success: true, message: "Device blocked successfully" });
});

// Session management endpoints
app.get("/api/admin/sessions", (req, res) => {
  const sessions = deviceManager.getActiveSessions();
  res.json({ sessions });
});

app.post("/api/admin/terminate-session", (req, res) => {
  const { sessionId } = req.body;
  const adminUser = req.auth ? req.auth.user : "Unknown";

  if (!sessionId) {
    return res.status(400).json({ error: "Session ID is required" });
  }

  deviceManager.terminateSession(sessionId);
  deviceManager.logAdminAction(adminUser, "terminate_session", sessionId, {});
  console.log(chalk.yellow(`🔌 Session terminated by ${adminUser}: ${sessionId}`));

  res.json({ success: true, message: "Session terminated successfully" });
});

// Communication endpoints
app.post("/api/admin/announcement", (req, res) => {
  const { message } = req.body;
  const adminUser = req.auth ? req.auth.user : "Unknown";

  if (!message) {
    return res.status(400).json({ error: "Message is required" });
  }

  const announcement = deviceManager.sendAnnouncement(message, adminUser);
  console.log(chalk.blue(`📢 Announcement sent by ${adminUser}: ${message}`));

  res.json({ success: true, announcement });
});

app.post("/api/admin/direct-message", (req, res) => {
  const { username, message } = req.body;
  const adminUser = req.auth ? req.auth.user : "Unknown";

  if (!username || !message) {
    return res.status(400).json({ error: "Username and message are required" });
  }

  const directMessage = deviceManager.sendDirectMessage(username, message, adminUser);
  console.log(chalk.blue(`💬 Direct message sent by ${adminUser} to ${username}: ${message}`));

  res.json({ success: true, message: directMessage });
});

// Audit and security endpoints
app.get("/api/admin/audit-log", (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const auditLog = deviceManager.getAuditLog(limit);
  res.json({ auditLog });
});

app.get("/api/admin/security-alerts", (req, res) => {
  const alerts = deviceManager.detectSuspiciousActivity();
  res.json({ alerts });
});

// User message endpoints
app.get("/api/user/messages", (req, res) => {
  const username = req.auth ? req.auth.user : "Unknown";
  const messages = deviceManager.getMessagesForUser(username);
  res.json({ messages });
});

app.post("/api/user/mark-message-read", (req, res) => {
  const { messageId } = req.body;
  deviceManager.markMessageAsRead(messageId);
  res.json({ success: true });
});

app.get("/api/user/announcements", (req, res) => {
  const announcements = deviceManager.getRecentAnnouncements();
  res.json({ announcements });
});

// Admin endpoint to view device status
app.get("/api/admin/devices", (_req, res) => {
  res.json({
    approved: deviceManager.getApprovedDevices(),
    pending: deviceManager.getPendingDevices(),
    blocked: deviceManager.getBlockedDevices(),
    pendingDetails: deviceManager.getPendingDeviceInfo(),
  });
});

app.use((_req, res) => {
  res.status(404).sendFile(path.join(__dirname, "static", "404.html"));
});

app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, "static", "404.html"));
});

server.on("request", (req, res) => {
  if (bareServer.shouldRoute(req)) {
    bareServer.routeRequest(req, res);
  } else {
    app(req, res);
  }
});

server.on("upgrade", (req, socket, head) => {
  if (bareServer.shouldRoute(req)) {
    bareServer.routeUpgrade(req, socket, head);
  } else {
    socket.end();
  }
});

server.on("listening", () => {
  console.log(chalk.green(`🌍 Server is running on http://localhost:${PORT}`));
});

server.listen({ port: PORT });
