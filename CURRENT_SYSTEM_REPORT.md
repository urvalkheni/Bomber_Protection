# Bomber Protection - Current System Report

Date: 2026-03-06
Project: `com.smsshield.bomberprotection`

## 1. Device Matrix (Fill/Confirm)

Status: partially prefilled from your input, hardware-only fields must be confirmed on device.

- Device Brand: Xiaomi
- Model: Poco X6
- Android Version: Android 14
- OS Layer: HyperOS
- Security Patch: `TODO: confirm from Settings > Security & Privacy > Security update`
- Region: India
- Dual SIM: `TODO: Yes/No`
- Carrier: `TODO: Jio / Airtel / VI`

## 2. Default SMS App Proof

Path:
- Settings
- Apps
- Default Apps
- SMS App

Expected:
- `SMS Shield (com.smsshield.bomberprotection)`

Current app behavior:
- `MainActivity` requests SMS role at launch.
- Full blocking control requires this app to remain default SMS app.

## 3. Real Attack Dataset Format (100+ messages)

Implemented forensic JSON export now includes campaign and decision fields while keeping sender/body.

Example row shape:

```json
[
  {
    "timestamp": "2026-03-06T12:46:02",
    "sender": "VM-MARUTI-S",
    "cluster": "VM",
    "decision": "QUARANTINED",
    "reason": "template_reuse_rotation",
    "message_hash": "otp_template_12ab34cd",
    "campaign_id": "otp_template_12ab34cd_krxg2",
    "escalation": "ATTACK",
    "body": "5279 is your OTP to submit your query"
  }
]
```

Masking guidance for shared reports:
- Phone numbers should be masked, for example `XXXXXX6254`.

## 4. CSV Export Format

Implemented CSV header:

```csv
timestamp,sender,cluster,decision,reason,message_hash,campaign_id,escalation
```

Example row:

```csv
2026-03-06T12:46:02,VM-MARUTI-S,VM,QUARANTINED,cluster_lockdown_traffic,otp_template_12ab34cd,otp_template_12ab34cd_krxg2,LOCKDOWN
```

## 5. Permission State (Code + Device Check)

Manifest-declared:
- `RECEIVE_SMS`
- `READ_SMS`
- `SEND_SMS`
- `READ_CONTACTS`
- `POST_NOTIFICATIONS`

Runtime/device verification path:
- Settings
- Apps
- SMS Shield
- Permissions

## 6. Delivery Path Analysis (Device Observation)

You should classify observed OTP visibility as:
- A) Only SMS inbox
- B) Notification banner
- C) Bank/app notifications
- D) Email

Engineering note:
- HyperOS can surface vendor-level notification behavior even when SMS delivery is suppressed.
- Quarantined messages are now logged and can be restored from logs (long press on `QUARANTINED` row).

## 7. Policy Target

Current code default:
- Strict protection enabled (`strict_policy=true` by default)

Operational profiles:
- Option A: Play Store compliant (conservative filtering)
- Option B: Private side-load (full firewall style controls)

Current implementation is aligned closer to Option B for bomber-defense testing.

## 8. Attack Mode UX

Escalation states implemented:
- `NORMAL`
- `SUSPICIOUS`
- `ATTACK`
- `LOCKDOWN`

Lockdown behavior implemented:
- During lockdown, only contacts + whitelist are allowed.
- Lockdown duration is configurable (default 5 minutes via `SettingsStore`).

## 9. Contacts Trust Model

Trusted:
- Contacts lookup (`READ_CONTACTS` dependent)
- Manual whitelist entries

Untrusted:
- Unknown numeric/non-contact senders
- Rotating enterprise sender campaigns (`[A-Z]{2}-[A-Z0-9]+`)
- High entropy sender sets

## 10. False Positive Policy

Current default profile:
- Strict protection (better bomber defense, higher false-positive risk)

Behavioral controls in engine:
- `BLOCKED` for high-confidence attack patterns
- `SILENCED` for suspicious bursts
- `QUARANTINED` for high-risk traffic with restore path

## 11. Why Messages Still Appear (Root Cause Mapping)

Resolved in v2 engine design:
- Rotating sender IDs: handled through cluster + template + entropy scoring.
- Enterprise DLT routes: explicitly parsed and scored via enterprise regex.
- High threshold gap: replaced with adaptive scoring and lower practical trigger points.

Residual real-world caveat:
- If SMS role is not default, Android delivery pipeline limits interception authority.

## 12. v2 Architecture Status (Implemented)

Implemented layers:
1. Global rate detection (sliding windows 60s/120s)
2. Cluster detection (`VM`, `JK`, `BZ`, etc.)
3. Template similarity via numeric-token-stripped hash
4. Sender entropy detection
5. Escalation and lockdown enforcement

Persistence added (Room):
- `sender_cluster_reputation`
- `campaign_fingerprint`
- `attack_logs` extended with `campaignId`

Forensic exports:
- CSV and JSON include `timestamp`, `sender`, `cluster`, `decision`, `reason`, `message_hash`, `campaign_id`, `escalation`

Dashboard counters:
- `BLOCKED`, `SILENCED`, `QUARANTINED`, `Attackers`

---
This report reflects the codebase state after the v2 rotating-sender defense upgrade in this workspace.
