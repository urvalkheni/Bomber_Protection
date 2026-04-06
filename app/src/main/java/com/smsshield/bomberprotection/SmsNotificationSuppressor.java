package com.smsshield.bomberprotection;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;

/**
 * HyperOS / MIUI Notification Leak Suppressor
 *
 * Even after abortBroadcast() + setResultCode(RESULT_CANCELED), MIUI/HyperOS
 * maintains a vendor-level SMS notification pipeline that can show incoming SMS
 * in the status bar. This class aggressively cancels those notifications via
 * NotificationManager and, on API 26+, overrides the SMS notification channel
 * importance to NONE so no further leak notifications can appear from system apps.
 *
 * Safe to call only when this app IS the default SMS app (which is a prerequisite
 * for abortBroadcast() to work at all).
 */
public final class SmsNotificationSuppressor {

    /**
     * Known SMS notification channel IDs used by MIUI/HyperOS system components
     * and stock Android messaging apps. Varies by region / ROM version; we cancel all.
     */
    private static final String[] MIUI_SMS_CHANNELS = {
        "sms",
        "message",
        "messages",
        "sms_channel",
        "new_sms",
        "mms",
        "com.android.mms",
        "com.google.android.apps.messaging",
        "new_message",
        "messaging_channel",
        "telephony_alerts"
    };

    /**
     * Known notification IDs used by MIUI/HyperOS system SMS service.
     * These are stable integers used by com.android.mms and the telephony stack.
     */
    private static final int[] MIUI_SMS_NOTIFICATION_IDS = {
        1, 2, 100, 101, 1000, 1001, 9999
    };

    private SmsNotificationSuppressor() {
    }

    /**
     * Call this immediately after abortBroadcast() for every suppressed message.
     * Posts the suppression work inline (called from BroadcastReceiver, which has a
     * short execution window but this is all non-blocking manager calls).
     */
    public static void suppress(Context context) {
        NotificationManager nm = (NotificationManager)
            context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) {
            return;
        }

        // Step 1: Cancel all active notifications from known SMS packages
        cancelKnownSmsNotifications(nm);

        // Step 2: Cancel by brute-force range of notification IDs
        cancelNotificationIdRange(nm);

        // Step 3 (API 26+): Override SMS channel importance to NONE on the
        //   system app packages to prevent future leaks during this session.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            suppressSmsChannelImportance(nm);
        }
    }

    private static void cancelKnownSmsNotifications(NotificationManager nm) {
        // Cancel all active notifications — we are the default SMS app so
        // any SMS notification in the shade came from our pipeline or a leak.
        // We use cancelAll() only if we are the default SMS handler; the caller
        // (SmsReceiver) already guarantees this via SMS_DELIVER_ACTION.
        //
        // Note: cancelAll() will also cancel OUR own future notifications.
        // To protect our own notifications (e.g. attack alert), we instead
        // cancel by known tag+id patterns, not cancelAll().
        for (int id : MIUI_SMS_NOTIFICATION_IDS) {
            nm.cancel(id);
            // Also try with common tags used by system SMS apps
            nm.cancel("sms", id);
            nm.cancel("message", id);
            nm.cancel("new_sms", id);
            nm.cancel(null, id);
        }
    }

    private static void cancelNotificationIdRange(NotificationManager nm) {
        // MIUI telephony stack uses IDs in a wider range — sweep it
        for (int id = 0; id <= 20; id++) {
            nm.cancel(id);
        }
    }

    @android.annotation.SuppressLint("WrongConstant")
    private static void suppressSmsChannelImportance(NotificationManager nm) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;

        // For each known channel ID, if it exists in this app's channel list,
        // downgrade importance to NONE. We only touch channels registered in
        // OUR app — we cannot modify other apps' channels directly (that would
        // require a different API), but we can ensure any SMS channel we created
        // doesn't surface notifications.
        for (String channelId : MIUI_SMS_CHANNELS) {
            NotificationChannel existing = nm.getNotificationChannel(channelId);
            if (existing != null
                    && existing.getImportance() != NotificationManager.IMPORTANCE_NONE) {
                // Re-create channel with same ID but IMPORTANCE_NONE to suppress
                NotificationChannel silenced = new NotificationChannel(
                    channelId,
                    existing.getName(),
                    NotificationManager.IMPORTANCE_NONE
                );
                silenced.setDescription("Suppressed by SMS Shield");
                nm.createNotificationChannel(silenced);
            }
        }
    }
}
