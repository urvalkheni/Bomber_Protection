package com.smsshield.bomberprotection;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;

public final class OtpFilterNotifier {
    private static final String PREF = "otp_filter_notifications";
    private static final String KEY_LAST_MS = "last_ms";
    private static final String KEY_COUNT = "count";

    private static final long AGGREGATION_WINDOW_MS = 120_000L;
    private static final String CHANNEL_ID = "otp_filtered_channel";
    private static final int NOTIFICATION_ID = 4102;

    private OtpFilterNotifier() {
    }

    public static void notifyFilteredOtp(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
            && ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return;
        }

        Context appContext = context.getApplicationContext();
        ensureChannel(appContext);

        SharedPreferences prefs = appContext.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        long nowMs = System.currentTimeMillis();
        long lastMs = prefs.getLong(KEY_LAST_MS, 0L);
        int count = prefs.getInt(KEY_COUNT, 0);

        if (nowMs - lastMs > AGGREGATION_WINDOW_MS) {
            count = 0;
        }
        count += 1;
        prefs.edit()
            .putLong(KEY_LAST_MS, nowMs)
            .putInt(KEY_COUNT, count)
            .apply();

        Intent logsIntent = new Intent(appContext, AttackLogActivity.class);
        logsIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        PendingIntent contentIntent = PendingIntent.getActivity(
            appContext,
            0,
            logsIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        NotificationCompat.Builder builder = new NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(appContext.getString(R.string.filtered_otp_notification_title))
            .setContentText(appContext.getString(R.string.filtered_otp_notification_text, count))
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_STATUS);

        NotificationManagerCompat.from(appContext).notify(NOTIFICATION_ID, builder.build());
    }

    private static void ensureChannel(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }

        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }

        NotificationChannel existing = manager.getNotificationChannel(CHANNEL_ID);
        if (existing != null) {
            return;
        }

        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.filtered_otp_notification_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        );
        channel.setDescription(context.getString(R.string.filtered_otp_notification_channel_desc));
        manager.createNotificationChannel(channel);
    }
}
