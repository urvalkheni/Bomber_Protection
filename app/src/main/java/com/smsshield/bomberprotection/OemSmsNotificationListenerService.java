package com.smsshield.bomberprotection;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import java.util.Locale;

public class OemSmsNotificationListenerService extends NotificationListenerService {
    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null) {
            return;
        }
        if (!SettingsStore.isShieldOn(this)) {
            return;
        }

        String packageName = sbn.getPackageName() == null ? "" : sbn.getPackageName().toLowerCase(Locale.US);
        if (!looksLikeSmsSource(packageName)) {
            return;
        }

        // Optional hardening path: if OEM posts an SMS notification after the
        // broadcast was already suppressed, remove it from the shade.
        cancelNotification(sbn.getKey());
    }

    private boolean looksLikeSmsSource(String packageName) {
        return packageName.contains("mms")
            || packageName.contains("messag")
            || packageName.contains("telephony")
            || packageName.contains("sms")
            || packageName.contains("hyperos");
    }
}
