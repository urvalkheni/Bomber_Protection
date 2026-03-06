# Bomber Protection - Current System Report

Date: 2026-03-06
Project: `com.smsshield.bomberprotection`

## 1. Current App Components

### Core Detection Path
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java`
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogStore.java`
- `app/src/main/java/com/smsshield/bomberprotection/SettingsStore.java`

### UI Screens
- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java`
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogActivity.java`
- `app/src/main/java/com/smsshield/bomberprotection/WhitelistActivity.java`

### SMS Role Eligibility Stubs
- `app/src/main/java/com/smsshield/bomberprotection/ComposeSmsActivity.java`
- `app/src/main/java/com/smsshield/bomberprotection/HeadlessSmsSendService.java`
- `app/src/main/java/com/smsshield/bomberprotection/MmsReceiver.java`

## 2. Permissions and Manifest State

From `app/src/main/AndroidManifest.xml`:
- Declared permissions: `RECEIVE_SMS`, `READ_SMS`, `SEND_SMS`, `READ_CONTACTS`, `POST_NOTIFICATIONS`
- SMS deliver receiver declared with `android.permission.BROADCAST_SMS`
- MMS receiver declared with `android.permission.BROADCAST_WAP_PUSH`

Key lines:
- `app/src/main/AndroidManifest.xml:5`
- `app/src/main/AndroidManifest.xml:6`
- `app/src/main/AndroidManifest.xml:7`
- `app/src/main/AndroidManifest.xml:8`
- `app/src/main/AndroidManifest.xml:9`
- `app/src/main/AndroidManifest.xml:59`
- `app/src/main/AndroidManifest.xml:68`

## 3. Runtime Behavior Implemented Today

### Receiver Processing
In `SmsReceiver`:
- Handles only `SMS_DELIVER_ACTION`
- Reconstructs multipart body
- Calls `ShieldEngine.evaluate(...)`
- For `BLOCKED` and `SILENCED`, calls `abortBroadcast()` + `setResultCode(0)` and writes log
- For `ALLOWED`, only writes log

Key lines:
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java:12`
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java:30`
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java:31`
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java:32`
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java:39`
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java:43`

### Shield Decision Rules
In `ShieldEngine`:
- Per sender limit: `>5 SMS in 60s`
- Global limit: `>20 SMS in 30s`
- Contacts-only mode can block non-contact and non-whitelisted senders
- Suspicious prefix list: `VK`, `AD`, `JD`; if same sender reaches >=3, action is `silence`
- OTP keyword rule: if message body contains OTP keywords and same sender reaches >=3, action is `block`

Key lines:
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java:22`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java:25`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java:77`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java:86`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java:94`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java:98`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java:103`

### Settings and Control Surface
In `MainActivity`:
- Shield ON/OFF toggle
- Contacts-only toggle
- Requests default SMS role
- Requests `READ_CONTACTS` and optionally `POST_NOTIFICATIONS`
- Displays summary counters and status

Key lines:
- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java:33`
- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java:34`
- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java:56`
- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java:80`
- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java:83`
- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java:111`

## 4. Data and Logging in Current System

`AttackLogStore` stores:
- Full recent logs in SharedPreferences JSON (`logs`)
- Max retained log entries: 200
- Daily counters: `blocked_today`, unique `attackers_today`
- Note: only `BLOCKED` increments daily counters; `SILENCED` and `ALLOWED` do not increment blocked count

Key lines:
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogStore.java:20`
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogStore.java:24`
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogStore.java:96`
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogStore.java:108`
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogStore.java:144`

## 5. Why Messages Are Still Coming (Current Likely Cause)

Based on current rules and your screenshot pattern (`VM-*`, `JD-*`, multiple different senders):

1. Most rules are sender-local.
- Per-sender and OTP burst rules require multiple messages from the same sender in short time.
- If attacker rotates sender IDs, sender-local thresholds do not trigger.

2. Global threshold is very high for real-world OTP bombing.
- Current global block starts only after more than 20 messages in 30 seconds.
- Typical attacks with 3-10 messages over 1-2 minutes will pass.

3. Suspicious prefix list is narrow.
- Only `VK`, `AD`, `JD` are handled today.
- Senders like `VM-*`, `BZ-*`, etc. are not covered unless they hit other limits.

4. Contacts-only mode is optional.
- If contacts-only is OFF, non-contact senders are allowed unless flood rules trigger.

5. The app does not currently implement a full inbox/provider management flow for default SMS behavior.
- Receiver and role stubs exist, but compose/service/mms handlers are minimal stubs.

## 6. Current Build/DevOps Status

- Java is available on system (`JDK 21` detected).
- Gradle wrapper script/folder is missing in repository (`gradlew.bat` and `gradle/wrapper` not present).
- Result: reproducible CLI build could not be executed from this workspace as-is.

## 7. Risk Summary Before Upgrade

High impact gaps:
- Rotating-sender OTP bombs likely bypass current logic.
- Thresholds are tuned too loosely for user-level protection.
- Prefix intelligence is static and very limited.

Medium impact gaps:
- Dashboard stats may under-represent effective suppression because `SILENCED` does not count as blocked.
- No long-term persistent database for richer analytics (only SharedPreferences JSON).

Low impact gaps:
- Whitelist UX is basic but functional.
- Log screen is functional but non-filterable and non-exportable.

## 8. Baseline Snapshot of What Exists Today

Present and working:
- Shield toggles and settings persistence
- Basic SMS receive and evaluate flow
- Rule-based block/silence/allow decisions
- Daily counters and attack log UI
- Whitelist add/remove
- SMS role request flow

Not fully implemented for advanced protection:
- Adaptive sender-cluster detection
- Country/operator/sender normalization intelligence
- Rule tuning per attack pattern
- Exportable reporting / forensic dashboard
- Complete default-SMS app feature set

---
This report captures the current implementation state before upgrade work.
