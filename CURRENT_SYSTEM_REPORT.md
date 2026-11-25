# Bomber Protection - Current System Report

Date: 2026-03-06
Project: `com.smsshield.bomberprotection`

## 1. Device Matrix (Placeholder / Template)

Status: anonymized placeholder values — update with final target test device details after development is complete.

- Device Brand: `<Device_Brand_Placeholder>` (e.g., `Generic OEM`)
- Model: `<Device_Model_Placeholder>` (e.g., `Test Device A`)
- Android Version: `Android 14 (API 34)`
- OS Layer: `<OS_Layer_Placeholder>` (e.g., `AOSP / OEM Skin`)
- Security Patch: `<YYYY-MM-DD>`
- Region: `<Region_Placeholder>`
- Dual SIM: `<Yes/No>`
- Carrier: `<Carrier_Placeholder>`

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
- `WRITE_SMS`
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

## 13. Dummy Statistics & Benchmark Metrics (Placeholder)

> [!NOTE]
> All metrics below are **dummy placeholder statistics** for template/reporting purposes until final end-to-end testing is completed.

| Metric | Dummy Value | Notes |
| :--- | :--- | :--- |
| **Total SMS Processed** | `150` | Simulated mixed normal + burst traffic |
| **`ALLOW`** | `32` | Contacts, whitelisted, and expected OTPs |
| **`SILENCED`** | `24` | Suspicious bursts muted without quarantine |
| **`QUARANTINED`** | `68` | High-risk rotating-sender / template-reuse messages |
| **`BLOCKED`** | `26` | High-confidence attack / lockdown drops |
| **Unique Sender Clusters** | `6` | e.g., `VM`, `JK`, `BZ` (synthetic) |
| **Detected Campaigns** | `3` | Grouped via `campaign_id` / `message_hash` |
| **False Positive Rate (Est.)** | `< 2.0%` | Placeholder target under `strict_policy=true` |
| **Lockdown Triggers** | `2` | 5-minute default lockdown activations |

---
This report reflects the codebase state after the v2 rotating-sender defense upgrade in this workspace (with personal device details anonymized and placeholder statistics added).
