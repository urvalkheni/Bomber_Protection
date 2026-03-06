# SMS Shield (Bomber Protection)

Android app with an ON/OFF shield switch to detect and block SMS flooding patterns.

## Features

- Shield mode toggle (ON/OFF)
- Contacts-only mode (allow contacts + whitelist, block others)
- Per-sender rate limit: block when `>5 SMS / 60s`
- Global flood limit: block when `>20 SMS / 30s`
- Suspicious sender pattern handling (`VK`, `AD`, `JD`)
- OTP-style spam burst detection
- Attack logs (blocked/silenced/allowed with reason and timestamp)
- Whitelist manager
- Default SMS role request on startup

## Project Structure

- `app/src/main/java/com/smsshield/bomberprotection/MainActivity.java`
- `app/src/main/java/com/smsshield/bomberprotection/SmsReceiver.java`
- `app/src/main/java/com/smsshield/bomberprotection/ShieldEngine.java`
- `app/src/main/java/com/smsshield/bomberprotection/AttackLogStore.java`
- `app/src/main/java/com/smsshield/bomberprotection/WhitelistActivity.java`
- `app/src/main/AndroidManifest.xml`

## Build

Open the folder in Android Studio and run a standard build (`Build > Make Project`).

If you have Gradle wrapper generated locally, you can also build APK via terminal with:

```bash
./gradlew assembleDebug
```

## Install On POCO X6

1. Enable Developer options and USB debugging on device.
2. Connect phone via USB.
3. Install APK:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

4. Open app and grant requested permissions.
5. Accept prompt to make this app the default SMS app.

## Important Android Note

On modern Android, robust SMS interception works only when this app is the default SMS app.
