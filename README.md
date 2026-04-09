# SMS Shield (Bomber Protection)
Android SMS flood-defense app that helps reduce OTP and spam bomber attacks by filtering suspicious inbound SMS traffic in real time.

## 1. Title + Tagline
SMS Shield (Bomber Protection)

Real-time SMS filtering and quarantine system for Android, designed to reduce OTP flood abuse and sender-rotation spam.

## 2. 🚀 Overview
SMS Shield is an Android app built to detect suspicious incoming SMS patterns and decide whether to allow, silence, or quarantine messages.

It was built to handle real-world SMS bomber behavior, where many similar OTP messages arrive quickly from rotating sender IDs.

In real life, this can be used by users who receive repeated OTP spam or message floods and want stronger inbox control. The app also keeps forensic logs so users can review decisions and restore quarantined messages when needed.

## 3. 🔥 Features (Implemented)
- Shield ON/OFF toggle
	Turns the filtering engine on or off from the main screen.

- Contacts + whitelist protection mode
	Optional mode that allows contacts and manually whitelisted senders, while suppressing unknown traffic.

- Real-time SMS decision engine
	Every incoming SMS is evaluated by ShieldEngine and classified as ALLOW, SILENCED, or QUARANTINED.

- Multi-signal risk analysis
	Uses real signals from code: global rate windows, sender-cluster volume, template reuse, sender entropy, and stored cluster reputation.

- Escalation states
	Tracks threat level as NORMAL, SUSPICIOUS, ATTACK, or LOCKDOWN, with cooldown and lockdown timers.

- OTP-aware selection logic
	Detects OTP-style messages, groups similar OTP campaigns, and prefers a safer primary OTP while quarantining risky duplicates.

- User OTP intent window
	"Expect OTP" button creates a temporary trust window (global or service-scoped) to reduce false positives when user expects an OTP.

- Manual whitelist management
	Add/remove sender IDs or numbers in a dedicated whitelist screen.

- Learned trusted senders
	Unknown senders can be auto-promoted to trusted after repeated successful safe OTP deliveries.

- Attack logs dashboard
	Stores recent actions with sender, reason, escalation, cluster, hash, and campaign ID.

- Export logs
	Export forensic logs to CSV and JSON from the logs screen.

- Restore from quarantine
	Long-press quarantined log entries to restore the message back to inbox.

- OEM notification hardening
	Includes notification suppression and a NotificationListenerService path to reduce SMS notification leaks on some OEM ROMs.

- Default SMS role request
	Requests default SMS app role on launch, which is required for reliable interception.

## 4. 🛠 Tech Stack
- Language
	Java 17

- Android
	Android SDK 34 (minSdk 26, targetSdk 34)
	AndroidX AppCompat
	Material Components
	ConstraintLayout

- Data layer
	Room (local SQLite persistence)

- Build and automation
	Gradle (Android Gradle Plugin 8.5.0)
	GitHub Actions workflow for debug APK build

## 5. 📂 Project Structure
Top-level:
- app/
	Main Android application module.

- .github/workflows/build-debug-apk.yml
	CI workflow that builds and uploads a debug APK artifact.

- build.gradle, settings.gradle, gradle.properties
	Root Gradle configuration.

- build/ and app/build/
	Generated build outputs and reports.

Inside app/src/main:
- AndroidManifest.xml
	App components, permissions, SMS/MMS receivers, notification listener, and services.

- java/com/smsshield/bomberprotection/
	Core Java source package.

Important classes:
- MainActivity.java
	Main dashboard, shield toggles, runtime permission requests, default SMS role request, OTP intent dialog.

- SmsReceiver.java
	Entry point for incoming SMS delivery broadcasts. Calls ShieldEngine and logs decisions.

- ShieldEngine.java
	Core decision engine (risk scoring, trust scoring, escalation, campaign fingerprinting, OTP routing logic).

- AttackLogStore.java
	Logging, daily stats, export CSV/JSON, quarantine grouping, restore-to-inbox flow.

- AttackLogActivity.java
	UI for viewing logs, exporting data, restoring quarantined messages, and marking sender trusted.

- WhitelistActivity.java
	UI for adding/removing trusted senders.

- SettingsStore.java
	SharedPreferences-backed settings and OTP intent windows.

- ShieldDatabase.java + DAO/Entity classes
	Room database and tables: attack_logs, sender_cluster_reputation, campaign_fingerprint.

- SmsNotificationSuppressor.java + OemSmsNotificationListenerService.java
	Notification hardening helpers for OEM SMS notification behavior.

- MmsReceiver.java, ComposeSmsActivity.java, HeadlessSmsSendService.java
	Required role/intent compatibility stubs used by SMS role integration.

Resources:
- res/layout/
	UI layouts (main, logs, whitelist).

- res/values/strings.xml
	User-facing text labels and messages.

- res/values/themes.xml
	App theme configuration.

## 6. ⚙️ Setup & Installation
Prerequisites:
- Android Studio (latest stable recommended)
- JDK 17
- Android SDK Platform 34 and Build Tools 34.0.0
- ADB (optional, for device install via terminal)
- Gradle CLI if building from terminal (this repository does not include gradlew wrapper files)

Steps:

~~~bash
git clone <your-repo-url>
cd Bomber_Protection
~~~

What this does:
- Clones the repository and moves into project root.

Build debug APK (terminal path):

~~~bash
gradle :app:assembleDebug
~~~

What this does:
- Compiles the Android app and creates app/build/outputs/apk/debug/app-debug.apk.

Install on connected device:

~~~bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
~~~

What this does:
- Installs or updates the debug APK on your Android phone.

Alternative (recommended for beginners):
- Open the folder in Android Studio.
- Let Gradle sync.
- Run the app on a device/emulator from the Run button.

First launch checklist:
1. Grant requested permissions (contacts, notifications where applicable).
2. Accept prompt to set SMS Shield as default SMS app.
3. Enable Shield Mode in the app.

## 7. 🧪 Usage Examples
Start the app manually with ADB:

~~~bash
adb shell am start -n com.smsshield.bomberprotection/.MainActivity
~~~

This opens the main dashboard where you can enable the shield and view stats.

Open logs screen directly:

~~~bash
adb shell am start -n com.smsshield.bomberprotection/.AttackLogActivity
~~~

This opens attack logs where you can export CSV/JSON and review quarantined items.

Typical in-app usage flow:
1. Turn on Shield Mode.
2. Optionally enable Contacts + Whitelist mode.
3. Tap Expect OTP before requesting an OTP from a service.
4. Review Attack Logs if messages were silenced/quarantined.
5. Long-press a quarantined log row to restore message or mark sender trusted.

## 8. 📊 Example Output
Main stats panel example:

~~~text
Blocked: 3
Silenced: 4
Quarantined: 11
Attackers: 6
Escalation: ATTACK
Panic Mode: Yes
Default SMS App: Yes
Permissions: Granted
OTP Intent: Active (96s left)
~~~

Log row example:

~~~text
[QUARANTINED] VM-MARUTI-S
otp_non_primary_quarantine | escalation=ATTACK | cluster=VM
hash=otp_template_12ab34cd | campaign=otp_template_12ab34cd_maruti_sim_unknown_krxg2
09 Apr 14:21:08
5279 is your OTP to submit your query
~~~

CSV export header example:

~~~csv
timestamp,sender,cluster,decision,reason,message_hash,campaign_id,escalation
~~~

JSON export object example:

~~~json
{
	"timestamp": "2026-04-09T14:21:08",
	"sender": "VM-MARUTI-S",
	"cluster": "VM",
	"decision": "QUARANTINED",
	"reason": "otp_non_primary_quarantine",
	"message_hash": "otp_template_12ab34cd",
	"campaign_id": "otp_template_12ab34cd_maruti_sim_unknown_krxg2",
	"escalation": "ATTACK",
	"body": "5279 is your OTP to submit your query"
}
~~~

## 9. 🧠 How It Works
Input -> Processing -> Output

1. Input
- Android delivers incoming SMS to SmsReceiver.

2. Processing
- SmsReceiver extracts sender/body/sim context.
- ShieldEngine calculates risk and trust using:
	message frequency windows,
	sender cluster trends,
	template reuse,
	entropy (rotating senders),
	reputation history from Room,
	user settings (contacts-only, expect OTP window).
- Engine chooses decision and escalation.

3. Output
- ALLOW: message proceeds.
- SILENCED/QUARANTINED: broadcast is suppressed, event is logged.
- Optional filtered-OTP notification is shown.
- User can review/export logs and restore quarantined messages.

## 10. 🔐 Limitations / Notes
- Default SMS role is mandatory for reliable SMS interception and suppression.
- MMS analysis is not implemented; MmsReceiver is currently a stub.
- ComposeSmsActivity and HeadlessSmsSendService are minimal compatibility stubs.
- Filtering is heuristic-based, so false positives/false negatives are still possible.
- Room uses allowMainThreadQueries, which is simple for this project but not ideal for high-scale production workloads.
- Repository currently does not include gradlew/gradlew.bat and gradle/wrapper, so CLI builds need a local Gradle installation.

## 11. 🎯 Learning Outcomes
This project demonstrates:
- Android SMS role integration and broadcast handling
- Threat scoring and escalation design for security filtering
- Practical heuristic defense against sender-rotation OTP spam
- Local persistence design with Room (entities, DAO, migration)
- Forensic logging/export workflows (CSV/JSON)
- Defensive UX patterns for trust controls and recovery (restore, whitelist, trusted sender)

## 12. 🚀 Future Improvements
- Add real MMS parsing and filtering path
- Move database operations off main thread (Repository + background executors)
- Add automated tests for ShieldEngine decision rules
- Add configurable policy profiles (strict, balanced, permissive)

## 13. ⚠️ Disclaimer
This project is for defensive and ethical use only.

It is intended to protect users from spam and bomber-style SMS abuse. Do not use it to interfere with lawful communications or to bypass platform/security policies.
