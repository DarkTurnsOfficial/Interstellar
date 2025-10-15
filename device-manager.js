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

    return {
      fingerprint,
      userAgent,
      ip,
      timestamp,
      status: this.getDeviceStatus(fingerprint),
    };
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

  approveDevice(fingerprint) {
    // Remove from pending
    this.devices.pending = this.devices.pending.filter(f => f !== fingerprint);
    // Add to approved
    if (!this.devices.approved.includes(fingerprint)) {
      this.devices.approved.push(fingerprint);
    }
    this.saveDevices();
  }

  blockDevice(fingerprint) {
    // Remove from pending
    this.devices.pending = this.devices.pending.filter(f => f !== fingerprint);
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
}

export default DeviceManager;
