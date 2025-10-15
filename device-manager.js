import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

class DeviceManager {
  constructor() {
    this.devicesFile = path.join(process.cwd(), "devices.json");
    this.devices = this.loadDevices();
  }

  loadDevices() {
    try {
      if (fs.existsSync(this.devicesFile)) {
        const data = fs.readFileSync(this.devicesFile, "utf8");
        return JSON.parse(data);
      }
    } catch (error) {
      console.error("Error loading devices:", error);
    }
    return {
      approved: [],
      pending: [],
      blocked: [],
    };
  }

  saveDevices() {
    try {
      fs.writeFileSync(this.devicesFile, JSON.stringify(this.devices, null, 2));
    } catch (error) {
      console.error("Error saving devices:", error);
    }
  }

  generateDeviceFingerprint(req) {
    const userAgent = req.get("User-Agent") || "";
    const acceptLanguage = req.get("Accept-Language") || "";
    const acceptEncoding = req.get("Accept-Encoding") || "";
    const connection = req.get("Connection") || "";
    const ip = req.ip || req.connection.remoteAddress || "";

    // Create a more robust fingerprint
    const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}|${connection}|${ip}`;
    return crypto.createHash("sha256").update(fingerprintData).digest("hex");
  }

  getDeviceInfo(req) {
    const fingerprint = this.generateDeviceFingerprint(req);
    const userAgent = req.get("User-Agent") || "Unknown";
    const ip = req.ip || req.connection.remoteAddress || "Unknown";
    const timestamp = new Date().toISOString();
    const username = req.auth ? req.auth.user : "Unknown";
    const sessionId = this.generateSessionId(username);
    const acceptLanguage = req.get("Accept-Language") || "Unknown";
    const acceptEncoding = req.get("Accept-Encoding") || "Unknown";
    const connection = req.get("Connection") || "Unknown";

    return {
      fingerprint,
      userAgent,
      ip,
      timestamp,
      username,
      sessionId,
      acceptLanguage,
      acceptEncoding,
      connection,
      status: this.getDeviceStatus(fingerprint),
    };
  }

  generateSessionId(username) {
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString("hex");
    return `${username}_${timestamp}_${random}`;
  }

  getDeviceStatus(fingerprint) {
    if (this.devices.approved.includes(fingerprint)) {
      return "approved";
    } else if (this.devices.blocked.includes(fingerprint)) {
      return "blocked";
    } else if (this.devices.pending.includes(fingerprint)) {
      return "pending";
    }
    return "new";
  }

  addPendingDevice(deviceInfo) {
    if (!this.devices.pending.includes(deviceInfo.fingerprint)) {
      this.devices.pending.push(deviceInfo.fingerprint);
      this.saveDevices();
    }
  }

  getPendingDeviceInfo() {
    return this.devices.pendingDetails || [];
  }

  addPendingDeviceWithDetails(deviceInfo) {
    if (!this.devices.pending.includes(deviceInfo.fingerprint)) {
      this.devices.pending.push(deviceInfo.fingerprint);

      // Store detailed info for admin review
      if (!this.devices.pendingDetails) {
        this.devices.pendingDetails = [];
      }

      // Remove any existing entry for this fingerprint
      this.devices.pendingDetails = this.devices.pendingDetails.filter(d => d.fingerprint !== deviceInfo.fingerprint);

      // Add new entry with comprehensive logging
      this.devices.pendingDetails.push({
        fingerprint: deviceInfo.fingerprint,
        username: deviceInfo.username,
        ip: deviceInfo.ip,
        userAgent: deviceInfo.userAgent,
        timestamp: deviceInfo.timestamp,
        sessionId: deviceInfo.sessionId,
        acceptLanguage: deviceInfo.acceptLanguage,
        acceptEncoding: deviceInfo.acceptEncoding,
        connection: deviceInfo.connection,
      });

      this.saveDevices();
    }
  }

  // Session management methods
  addActiveSession(deviceInfo) {
    if (!this.devices.activeSessions) {
      this.devices.activeSessions = [];
    }

    // Remove any existing session for this sessionId
    this.devices.activeSessions = this.devices.activeSessions.filter(s => s.sessionId !== deviceInfo.sessionId);

    // Add new active session
    this.devices.activeSessions.push({
      sessionId: deviceInfo.sessionId,
      username: deviceInfo.username,
      fingerprint: deviceInfo.fingerprint,
      ip: deviceInfo.ip,
      userAgent: deviceInfo.userAgent,
      loginTime: deviceInfo.timestamp,
      lastActivity: deviceInfo.timestamp,
      status: "active",
    });

    this.saveDevices();
  }

  updateSessionActivity(sessionId) {
    if (this.devices.activeSessions) {
      const session = this.devices.activeSessions.find(s => s.sessionId === sessionId);
      if (session) {
        session.lastActivity = new Date().toISOString();
        this.saveDevices();
      }
    }
  }

  terminateSession(sessionId) {
    if (this.devices.activeSessions) {
      this.devices.activeSessions = this.devices.activeSessions.filter(s => s.sessionId !== sessionId);
      this.saveDevices();
    }
  }

  getActiveSessions() {
    return this.devices.activeSessions || [];
  }

  getSessionsByUsername(username) {
    return (this.devices.activeSessions || []).filter(s => s.username === username);
  }

  getSessionsByDevice(fingerprint) {
    return (this.devices.activeSessions || []).filter(s => s.fingerprint === fingerprint);
  }

  // Security analysis methods
  detectSuspiciousActivity() {
    const alerts = [];
    const sessions = this.getActiveSessions();

    // Check for multiple sessions from same username
    const sessionsByUser = {};
    sessions.forEach(session => {
      if (!sessionsByUser[session.username]) {
        sessionsByUser[session.username] = [];
      }
      sessionsByUser[session.username].push(session);
    });

    Object.entries(sessionsByUser).forEach(([username, userSessions]) => {
      if (userSessions.length > 1) {
        alerts.push({
          type: "multiple_sessions",
          severity: "warning",
          message: `User ${username} has ${userSessions.length} active sessions`,
          username,
          sessions: userSessions.map(s => s.sessionId),
        });
      }
    });

    // Check for multiple usernames from same device
    const sessionsByDevice = {};
    sessions.forEach(session => {
      if (!sessionsByDevice[session.fingerprint]) {
        sessionsByDevice[session.fingerprint] = [];
      }
      sessionsByDevice[session.fingerprint].push(session);
    });

    Object.entries(sessionsByDevice).forEach(([fingerprint, deviceSessions]) => {
      const uniqueUsers = [...new Set(deviceSessions.map(s => s.username))];
      if (uniqueUsers.length > 1) {
        alerts.push({
          type: "multiple_users_device",
          severity: "high",
          message: `Device ${fingerprint.substring(0, 16)}... has sessions from multiple users: ${uniqueUsers.join(", ")}`,
          fingerprint,
          users: uniqueUsers,
        });
      }
    });

    return alerts;
  }

  approveDevice(fingerprint) {
    // Remove from pending
    this.devices.pending = this.devices.pending.filter(f => f !== fingerprint);

    // Remove from pending details
    if (this.devices.pendingDetails) {
      this.devices.pendingDetails = this.devices.pendingDetails.filter(d => d.fingerprint !== fingerprint);
    }

    // Add to approved
    if (!this.devices.approved.includes(fingerprint)) {
      this.devices.approved.push(fingerprint);
    }
    this.saveDevices();
  }

  blockDevice(fingerprint) {
    // Remove from pending
    this.devices.pending = this.devices.pending.filter(f => f !== fingerprint);

    // Remove from pending details
    if (this.devices.pendingDetails) {
      this.devices.pendingDetails = this.devices.pendingDetails.filter(d => d.fingerprint !== fingerprint);
    }

    // Add to blocked
    if (!this.devices.blocked.includes(fingerprint)) {
      this.devices.blocked.push(fingerprint);
    }
    this.saveDevices();
  }

  isDeviceApproved(fingerprint) {
    return this.devices.approved.includes(fingerprint);
  }

  isDeviceBlocked(fingerprint) {
    return this.devices.blocked.includes(fingerprint);
  }

  isDevicePending(fingerprint) {
    return this.devices.pending.includes(fingerprint);
  }

  getPendingDevices() {
    return this.devices.pending;
  }

  getApprovedDevices() {
    return this.devices.approved;
  }

  getBlockedDevices() {
    return this.devices.blocked;
  }

  // Audit logging methods
  logAdminAction(adminUser, action, target, details = {}) {
    if (!this.devices.auditLog) {
      this.devices.auditLog = [];
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      adminUser,
      action,
      target,
      details,
      id: crypto.randomBytes(8).toString("hex"),
    };

    this.devices.auditLog.push(logEntry);

    // Keep only last 1000 audit entries
    if (this.devices.auditLog.length > 1000) {
      this.devices.auditLog = this.devices.auditLog.slice(-1000);
    }

    this.saveDevices();
    return logEntry;
  }

  getAuditLog(limit = 100) {
    const logs = this.devices.auditLog || [];
    return logs.slice(-limit).reverse();
  }

  // Communication methods
  sendAnnouncement(message, adminUser) {
    if (!this.devices.announcements) {
      this.devices.announcements = [];
    }

    const announcement = {
      id: crypto.randomBytes(8).toString("hex"),
      message,
      adminUser,
      timestamp: new Date().toISOString(),
      type: "announcement",
    };

    this.devices.announcements.push(announcement);
    this.saveDevices();

    this.logAdminAction(adminUser, "send_announcement", "all_users", { message });
    return announcement;
  }

  sendDirectMessage(username, message, adminUser) {
    if (!this.devices.messages) {
      this.devices.messages = [];
    }

    const directMessage = {
      id: crypto.randomBytes(8).toString("hex"),
      username,
      message,
      adminUser,
      timestamp: new Date().toISOString(),
      type: "direct_message",
      read: false,
    };

    this.devices.messages.push(directMessage);
    this.saveDevices();

    this.logAdminAction(adminUser, "send_direct_message", username, { message });
    return directMessage;
  }

  getMessagesForUser(username) {
    return (this.devices.messages || []).filter(m => m.username === username && !m.read);
  }

  markMessageAsRead(messageId) {
    if (this.devices.messages) {
      const message = this.devices.messages.find(m => m.id === messageId);
      if (message) {
        message.read = true;
        this.saveDevices();
      }
    }
  }

  getRecentAnnouncements(limit = 5) {
    const announcements = this.devices.announcements || [];
    return announcements.slice(-limit).reverse();
  }
}

export default DeviceManager;
