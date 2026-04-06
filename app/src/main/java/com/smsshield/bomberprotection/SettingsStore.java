package com.smsshield.bomberprotection;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class SettingsStore {
    private static final String PREF = "shield_settings";
    private static final String KEY_SHIELD_ON = "shield_on";
    private static final String KEY_CONTACTS_ONLY = "contacts_only";
    private static final String KEY_WHITELIST = "whitelist";
    private static final String KEY_LOCKDOWN_MINUTES = "lockdown_minutes";
    private static final String KEY_LOCKDOWN_UNTIL_MS = "lockdown_until_ms";
    private static final String KEY_STRICT_POLICY = "strict_policy";
    private static final String KEY_EXPECT_OTP_UNTIL_MS = "expect_otp_until_ms";
    private static final String KEY_LEARNED_TRUSTED_SENDERS = "learned_trusted_senders";
    private static final String KEY_EXPECT_OTP_MAX_MESSAGES = "expect_otp_max_messages";
    private static final String KEY_ATTACK_COOLDOWN_MS = "attack_cooldown_ms";
    private static final String KEY_SENDER_SUCCESS_PREFIX = "sender_success_";
    private static final String KEY_EXPECT_OTP_SERVICE_WINDOWS = "expect_otp_service_windows";
    private static final String GLOBAL_INTENT_SERVICE = "__global__";

    private SettingsStore() {
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public static boolean isShieldOn(Context context) {
        return prefs(context).getBoolean(KEY_SHIELD_ON, true);
    }

    public static void setShieldOn(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_SHIELD_ON, enabled).apply();
    }

    public static boolean isContactsOnly(Context context) {
        return prefs(context).getBoolean(KEY_CONTACTS_ONLY, false);
    }

    public static void setContactsOnly(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_CONTACTS_ONLY, enabled).apply();
    }

    public static Set<String> getWhitelist(Context context) {
        Set<String> raw = prefs(context).getStringSet(KEY_WHITELIST, Collections.emptySet());
        return new HashSet<>(raw);
    }

    public static Set<String> getLearnedTrustedSenders(Context context) {
        Set<String> raw = prefs(context).getStringSet(KEY_LEARNED_TRUSTED_SENDERS, Collections.emptySet());
        return new HashSet<>(raw);
    }

    public static void addWhitelist(Context context, String number) {
        Set<String> list = getWhitelist(context);
        list.add(number);
        prefs(context).edit().putStringSet(KEY_WHITELIST, list).apply();
    }

    public static void removeWhitelist(Context context, String number) {
        Set<String> list = getWhitelist(context);
        list.remove(number);
        prefs(context).edit().putStringSet(KEY_WHITELIST, list).apply();
    }

    public static void addLearnedTrustedSender(Context context, String sender) {
        if (sender == null) {
            return;
        }
        String safeSender = sender.trim();
        if (safeSender.isEmpty()) {
            return;
        }

        Set<String> list = getLearnedTrustedSenders(context);
        list.add(safeSender);
        prefs(context).edit().putStringSet(KEY_LEARNED_TRUSTED_SENDERS, list).apply();

        // Clear historical counters once sender is explicitly trusted.
        prefs(context).edit().remove(successCounterKey(safeSender)).apply();
    }

    public static void removeLearnedTrustedSender(Context context, String sender) {
        if (sender == null) {
            return;
        }
        Set<String> list = getLearnedTrustedSenders(context);
        list.remove(sender.trim());
        prefs(context).edit().putStringSet(KEY_LEARNED_TRUSTED_SENDERS, list).apply();
    }

    public static int getLockdownMinutes(Context context) {
        return Math.max(1, prefs(context).getInt(KEY_LOCKDOWN_MINUTES, 5));
    }

    public static void setLockdownMinutes(Context context, int minutes) {
        prefs(context).edit().putInt(KEY_LOCKDOWN_MINUTES, Math.max(1, minutes)).apply();
    }

    public static long getLockdownUntilMs(Context context) {
        return prefs(context).getLong(KEY_LOCKDOWN_UNTIL_MS, 0L);
    }

    public static void setLockdownUntilMs(Context context, long untilMs) {
        prefs(context).edit().putLong(KEY_LOCKDOWN_UNTIL_MS, untilMs).apply();
    }

    public static boolean isStrictPolicy(Context context) {
        return prefs(context).getBoolean(KEY_STRICT_POLICY, true);
    }

    public static void setStrictPolicy(Context context, boolean strict) {
        prefs(context).edit().putBoolean(KEY_STRICT_POLICY, strict).apply();
    }

    public static void startExpectOtpWindow(Context context) {
        startExpectOtpWindowForService(context, GLOBAL_INTENT_SERVICE, 120_000L);
    }

    public static void startExpectOtpWindow(Context context, long durationMs) {
        startExpectOtpWindowForService(context, GLOBAL_INTENT_SERVICE, durationMs);
    }

    public static void startExpectOtpWindowForService(Context context, String serviceKey) {
        startExpectOtpWindowForService(context, serviceKey, 120_000L);
    }

    public static void startExpectOtpWindowForService(Context context, String serviceKey, long durationMs) {
        long safeDurationMs = Math.max(30_000L, durationMs);
        long untilMs = System.currentTimeMillis() + safeDurationMs;

        String normalized = normalizeServiceKey(serviceKey);
        Map<String, Long> windows = getServiceIntentWindows(context);
        windows.put(normalized, untilMs);
        putServiceIntentWindows(context, windows);

        if (GLOBAL_INTENT_SERVICE.equals(normalized)) {
            prefs(context).edit().putLong(KEY_EXPECT_OTP_UNTIL_MS, untilMs).apply();
        }
    }

    public static long getExpectOtpUntilMs(Context context) {
        return prefs(context).getLong(KEY_EXPECT_OTP_UNTIL_MS, 0L);
    }

    public static boolean isExpectOtpWindowActive(Context context, long nowMs) {
        if (nowMs < getExpectOtpUntilMs(context)) {
            return true;
        }
        Map<String, Long> windows = getServiceIntentWindows(context);
        for (Long untilMs : windows.values()) {
            if (untilMs != null && nowMs < untilMs) {
                return true;
            }
        }
        return false;
    }

    public static boolean isExpectOtpWindowActive(Context context, long nowMs, String serviceKey) {
        String normalized = normalizeServiceKey(serviceKey);
        Map<String, Long> windows = getServiceIntentWindows(context);
        Long specificUntil = windows.get(normalized);
        if (specificUntil != null && nowMs < specificUntil) {
            return true;
        }

        Long globalUntil = windows.get(GLOBAL_INTENT_SERVICE);
        if (globalUntil != null && nowMs < globalUntil) {
            return true;
        }

        return nowMs < getExpectOtpUntilMs(context);
    }

    public static long getExpectOtpRemainingMs(Context context, long nowMs) {
        Map<String, Long> windows = getServiceIntentWindows(context);
        Long globalUntil = windows.get(GLOBAL_INTENT_SERVICE);
        long fromMap = globalUntil == null ? 0L : Math.max(0L, globalUntil - nowMs);
        long fromLegacy = Math.max(0L, getExpectOtpUntilMs(context) - nowMs);
        return Math.max(fromMap, fromLegacy);
    }

    public static long getExpectOtpRemainingMs(Context context, long nowMs, String serviceKey) {
        String normalized = normalizeServiceKey(serviceKey);
        Map<String, Long> windows = getServiceIntentWindows(context);

        long specific = 0L;
        Long specificUntil = windows.get(normalized);
        if (specificUntil != null) {
            specific = Math.max(0L, specificUntil - nowMs);
        }

        Long globalUntil = windows.get(GLOBAL_INTENT_SERVICE);
        long global = globalUntil == null ? 0L : Math.max(0L, globalUntil - nowMs);
        long legacyGlobal = Math.max(0L, getExpectOtpUntilMs(context) - nowMs);
        return Math.max(specific, Math.max(global, legacyGlobal));
    }

    public static void clearExpectOtpWindow(Context context) {
        prefs(context).edit().putLong(KEY_EXPECT_OTP_UNTIL_MS, 0L).apply();
        Map<String, Long> windows = getServiceIntentWindows(context);
        windows.remove(GLOBAL_INTENT_SERVICE);
        putServiceIntentWindows(context, windows);
    }

    public static void clearExpectOtpWindow(Context context, String serviceKey) {
        Map<String, Long> windows = getServiceIntentWindows(context);
        windows.remove(normalizeServiceKey(serviceKey));
        putServiceIntentWindows(context, windows);
    }

    public static int getExpectOtpMaxMessages(Context context) {
        int configured = prefs(context).getInt(KEY_EXPECT_OTP_MAX_MESSAGES, 2);
        return Math.max(1, Math.min(configured, 2));
    }

    public static void setExpectOtpMaxMessages(Context context, int maxMessages) {
        int safe = Math.max(1, Math.min(maxMessages, 2));
        prefs(context).edit().putInt(KEY_EXPECT_OTP_MAX_MESSAGES, safe).apply();
    }

    public static long getAttackCooldownMs(Context context) {
        long configured = prefs(context).getLong(KEY_ATTACK_COOLDOWN_MS, 180_000L);
        return Math.max(30_000L, configured);
    }

    public static void setAttackCooldownMs(Context context, long cooldownMs) {
        prefs(context).edit().putLong(KEY_ATTACK_COOLDOWN_MS, Math.max(30_000L, cooldownMs)).apply();
    }

    public static int incrementSenderSuccessCount(Context context, String sender) {
        if (sender == null) {
            return 0;
        }
        String safeSender = sender.trim();
        if (safeSender.isEmpty()) {
            return 0;
        }

        String key = successCounterKey(safeSender);
        SharedPreferences p = prefs(context);
        int next = p.getInt(key, 0) + 1;
        p.edit().putInt(key, next).apply();
        return next;
    }

    public static int getSenderSuccessCount(Context context, String sender) {
        if (sender == null) {
            return 0;
        }
        String safeSender = sender.trim();
        if (safeSender.isEmpty()) {
            return 0;
        }
        return prefs(context).getInt(successCounterKey(safeSender), 0);
    }

    public static void clearSenderSuccessCount(Context context, String sender) {
        if (sender == null) {
            return;
        }
        prefs(context).edit().remove(successCounterKey(sender.trim())).apply();
    }

    private static String successCounterKey(String sender) {
        return KEY_SENDER_SUCCESS_PREFIX + sender.toLowerCase(Locale.US);
    }

    private static String normalizeServiceKey(String serviceKey) {
        if (serviceKey == null) {
            return GLOBAL_INTENT_SERVICE;
        }
        String normalized = serviceKey.trim().toLowerCase(Locale.US);
        if (normalized.isEmpty()) {
            return GLOBAL_INTENT_SERVICE;
        }
        return normalized;
    }

    private static Map<String, Long> getServiceIntentWindows(Context context) {
        Set<String> raw = prefs(context).getStringSet(KEY_EXPECT_OTP_SERVICE_WINDOWS, Collections.emptySet());
        Map<String, Long> out = new HashMap<>();
        for (String item : raw) {
            int sep = item.indexOf('|');
            if (sep <= 0 || sep >= item.length() - 1) {
                continue;
            }
            String key = item.substring(0, sep);
            String value = item.substring(sep + 1);
            try {
                out.put(key, Long.parseLong(value));
            } catch (NumberFormatException ignored) {
            }
        }

        long nowMs = System.currentTimeMillis();
        out.entrySet().removeIf(entry -> entry.getValue() == null || entry.getValue() <= nowMs);
        return out;
    }

    private static void putServiceIntentWindows(Context context, Map<String, Long> windows) {
        Set<String> encoded = new HashSet<>();
        for (Map.Entry<String, Long> entry : windows.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            encoded.add(entry.getKey() + "|" + entry.getValue());
        }
        prefs(context).edit().putStringSet(KEY_EXPECT_OTP_SERVICE_WINDOWS, encoded).apply();
    }
}
