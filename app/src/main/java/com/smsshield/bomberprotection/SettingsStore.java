package com.smsshield.bomberprotection;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class SettingsStore {
    private static final String PREF = "shield_settings";
    private static final String KEY_SHIELD_ON = "shield_on";
    private static final String KEY_CONTACTS_ONLY = "contacts_only";
    private static final String KEY_WHITELIST = "whitelist";
    private static final String KEY_LOCKDOWN_MINUTES = "lockdown_minutes";
    private static final String KEY_LOCKDOWN_UNTIL_MS = "lockdown_until_ms";
    private static final String KEY_STRICT_POLICY = "strict_policy";

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
}
