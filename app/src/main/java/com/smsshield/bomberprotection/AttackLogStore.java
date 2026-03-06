package com.smsshield.bomberprotection;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AttackLogStore {
    private static final String PREF = "attack_logs";
    private static final String KEY_LOGS = "logs";
    private static final String KEY_DAY = "day";
    private static final String KEY_BLOCKED_TODAY = "blocked_today";
    private static final String KEY_ATTACKERS_TODAY = "attackers_today";
    private static final int MAX_LOG_ITEMS = 200;

    private AttackLogStore() {
    }

    public static final class LogItem {
        public final String sender;
        public final String body;
        public final long timestamp;
        public final String action;
        public final String reason;

        public LogItem(String sender, String body, long timestamp, String action, String reason) {
            this.sender = sender;
            this.body = body;
            this.timestamp = timestamp;
            this.action = action;
            this.reason = reason;
        }
    }

    public static final class Stats {
        public final int blockedToday;
        public final int attackersToday;

        public Stats(int blockedToday, int attackersToday) {
            this.blockedToday = blockedToday;
            this.attackersToday = attackersToday;
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private static String today() {
        return new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date());
    }

    private static void ensureDay(Context context) {
        SharedPreferences p = prefs(context);
        String day = p.getString(KEY_DAY, "");
        String now = today();
        if (!now.equals(day)) {
            p.edit()
                .putString(KEY_DAY, now)
                .putInt(KEY_BLOCKED_TODAY, 0)
                .putStringSet(KEY_ATTACKERS_TODAY, new HashSet<>())
                .apply();
        }
    }

    public static synchronized void addLog(Context context, String sender, String body, String action, String reason) {
        ensureDay(context);
        SharedPreferences p = prefs(context);

        JSONArray array;
        try {
            array = new JSONArray(p.getString(KEY_LOGS, "[]"));
        } catch (JSONException e) {
            array = new JSONArray();
        }

        JSONObject obj = new JSONObject();
        try {
            obj.put("sender", sender == null ? "" : sender);
            obj.put("body", body == null ? "" : body);
            obj.put("timestamp", System.currentTimeMillis());
            obj.put("action", action);
            obj.put("reason", reason == null ? "" : reason);
            array.put(0, obj);

            if (array.length() > MAX_LOG_ITEMS) {
                JSONArray trimmed = new JSONArray();
                for (int i = 0; i < MAX_LOG_ITEMS; i++) {
                    trimmed.put(array.optJSONObject(i));
                }
                array = trimmed;
            }
        } catch (JSONException ignored) {
        }

        SharedPreferences.Editor editor = p.edit().putString(KEY_LOGS, array.toString());

        if ("BLOCKED".equals(action)) {
            int blocked = p.getInt(KEY_BLOCKED_TODAY, 0) + 1;
            Set<String> attackers = new HashSet<>(p.getStringSet(KEY_ATTACKERS_TODAY, new HashSet<>()));
            if (sender != null && !sender.isEmpty()) {
                attackers.add(sender);
            }
            editor.putInt(KEY_BLOCKED_TODAY, blocked);
            editor.putStringSet(KEY_ATTACKERS_TODAY, attackers);
        }

        editor.apply();
    }

    public static List<LogItem> getLogs(Context context) {
        List<LogItem> out = new ArrayList<>();
        SharedPreferences p = prefs(context);
        try {
            JSONArray array = new JSONArray(p.getString(KEY_LOGS, "[]"));
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.optJSONObject(i);
                if (item == null) {
                    continue;
                }
                out.add(new LogItem(
                    item.optString("sender", ""),
                    item.optString("body", ""),
                    item.optLong("timestamp", 0L),
                    item.optString("action", ""),
                    item.optString("reason", "")
                ));
            }
        } catch (JSONException ignored) {
        }
        return out;
    }

    public static Stats getStats(Context context) {
        ensureDay(context);
        SharedPreferences p = prefs(context);
        int blocked = p.getInt(KEY_BLOCKED_TODAY, 0);
        int attackers = p.getStringSet(KEY_ATTACKERS_TODAY, new HashSet<>()).size();
        return new Stats(blocked, attackers);
    }
}
