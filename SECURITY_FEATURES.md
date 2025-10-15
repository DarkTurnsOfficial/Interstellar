# Security Features - Device Approval System

This document describes the new device approval system implemented to enhance the security of the Interstellar web proxy.

## Overview

The device approval system adds an additional layer of security by requiring manual approval for each new device that attempts to access the proxy. This prevents unauthorized access and gives you complete control over which devices can use your proxy.

## Features

### 1. Device Fingerprinting
- Each device is uniquely identified using a combination of:
  - User Agent string
  - Accept-Language header
  - Accept-Encoding header
  - Connection type
  - IP address
- A SHA-256 hash is generated from this information to create a unique device fingerprint

### 2. Device States
- **New**: First-time device attempting to access the proxy
- **Pending**: Device waiting for approval
- **Approved**: Device has been approved and can access the proxy
- **Blocked**: Device has been denied and is permanently blocked

### 3. Approval Interface
- When a new device attempts to access the proxy, it's redirected to `/device-approval`
- The interface shows device information including IP address, user agent, and timestamp
- You can approve or deny the device with a single click
- Denied devices are permanently blocked and cannot access the proxy again

### 4. Admin Panel
- Access the admin panel at `/admin` to view all device statuses
- See statistics for approved, pending, and blocked devices
- Monitor device activity in real-time
- Auto-refreshes every 30 seconds

## How It Works

1. **First Access**: When a new device tries to access the proxy, it's automatically redirected to the approval page
2. **Device Information**: The system displays the device's fingerprint, IP address, user agent, and timestamp
3. **Approval Decision**: You can either:
   - **Approve**: Device is added to the approved list and can access the proxy
   - **Deny**: Device is permanently blocked and will see an access denied message
4. **Persistence**: All device states are saved to `devices.json` and persist across server restarts

## API Endpoints

- `GET /api/device-info` - Get current device information
- `POST /api/approve-device` - Approve a device
- `POST /api/block-device` - Block a device
- `GET /api/admin/devices` - Get all device statuses (admin only)

## Files Added/Modified

### New Files
- `device-manager.js` - Core device management logic
- `static/device-approval.html` - Device approval interface
- `static/admin.html` - Admin panel for device management
- `devices.json` - Persistent storage for device states (auto-generated)

### Modified Files
- `index.js` - Added device approval middleware and API endpoints

## Security Considerations

1. **Device Fingerprinting**: While robust, device fingerprints can change if users modify their browser settings or use different browsers
2. **IP Address Changes**: Users with dynamic IP addresses may appear as new devices
3. **VPN/Proxy Usage**: Users behind VPNs or corporate proxies may share IP addresses
4. **Browser Updates**: Major browser updates may change the user agent string

## Usage Instructions

1. Start the server as usual: `npm start`
2. When a new device accesses the proxy, you'll be redirected to the approval page
3. Review the device information and click "Approve Device" or "Deny Device"
4. Use the admin panel at `/admin` to monitor all devices
5. Blocked devices will see an access denied message and cannot access the proxy

## Troubleshooting

- If you accidentally block a device, you can manually edit `devices.json` to remove it from the blocked list
- If a device fingerprint changes (due to browser updates, etc.), the device will appear as new and require re-approval
- The system logs all device activities to the console for monitoring

## Future Enhancements

Potential improvements could include:
- Email notifications for new device requests
- Time-based device approvals (auto-expire after X days)
- Device grouping by IP ranges
- More detailed device information collection
- Integration with existing authentication systems
