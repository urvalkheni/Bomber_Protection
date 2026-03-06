package com.smsshield.bomberprotection;

import android.content.Context;

import androidx.annotation.NonNull;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public final class AttackLogStore {
    private static final int MAX_LOG_ITEMS = 200;

    private AttackLogStore() {
    }

    public static final class LogItem {
        public final String sender;
        public final String body;
        public final long timestamp;
        public final String action;
        public final String reason;
        public final String escalation;
        public final String cluster;

        public LogItem(String sender, String body, long timestamp, String action, String reason,
                       String escalation, String cluster) {
            this.sender = sender;
            this.body = body;
            this.timestamp = timestamp;
            this.action = action;
            this.reason = reason;
            this.escalation = escalation;
            this.cluster = cluster;
        }
    }

    public static final class Stats {
        public final int blockedToday;
        public final int silencedToday;
        public final int suppressedToday;
        public final int attackersToday;

        public Stats(int blockedToday, int silencedToday, int suppressedToday, int attackersToday) {
            this.blockedToday = blockedToday;
            this.silencedToday = silencedToday;
            this.suppressedToday = suppressedToday;
            this.attackersToday = attackersToday;
        }
    }

    private static AttackLogDao dao(Context context) {
        return ShieldDatabase.get(context).attackLogDao();
    }

    private static long startOfTodayMs() {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        return calendar.getTimeInMillis();
    }

    private static String sanitize(String value) {
        return value == null ? "" : value;
    }

    public static synchronized void addLog(Context context, String sender, String body, String action,
                                           String reason) {
        addLog(context, sender, body, action, reason, "NORMAL", "UNKNOWN", "");
    }

    public static synchronized void addLog(Context context, String sender, String body, String action,
                                           String reason, String escalation, String cluster,
                                           String templateHash) {
        AttackLogEntity entity = new AttackLogEntity(
            System.currentTimeMillis(),
            sanitize(sender),
            sanitize(body),
            sanitize(action),
            sanitize(reason),
            sanitize(escalation),
            sanitize(cluster),
            sanitize(templateHash)
        );

        AttackLogDao attackLogDao = dao(context);
        attackLogDao.insert(entity);
        attackLogDao.trimTo(MAX_LOG_ITEMS);
    }

    public static List<LogItem> getLogs(Context context) {
        List<AttackLogEntity> records = dao(context).recent(MAX_LOG_ITEMS);
        List<LogItem> out = new ArrayList<>();
        for (AttackLogEntity item : records) {
            out.add(new LogItem(
                item.sender,
                item.body,
                item.timestamp,
                item.action,
                item.reason,
                item.escalation,
                item.cluster
            ));
        }
        return out;
    }

    public static Stats getStats(Context context) {
        long since = startOfTodayMs();
        AttackLogDao attackLogDao = dao(context);
        int blocked = attackLogDao.countByActionSince(since, "BLOCKED");
        int silenced = attackLogDao.countByActionSince(since, "SILENCED");
        int suppressed = attackLogDao.countByActionSince(since, "SUPPRESSED");
        int attackers = attackLogDao.uniqueAttackersSince(since);
        return new Stats(blocked, silenced, suppressed, attackers);
    }

    public static File exportJson(Context context) throws IOException, JSONException {
        List<AttackLogEntity> all = dao(context).all();
        JSONArray array = new JSONArray();
        for (AttackLogEntity item : all) {
            JSONObject obj = new JSONObject();
            obj.put("timestamp", item.timestamp);
            obj.put("sender", item.sender);
            obj.put("action", item.action);
            obj.put("reason", item.reason);
            obj.put("escalation", item.escalation);
            obj.put("cluster", item.cluster);
            obj.put("body", item.body);
            array.put(obj);
        }

        String name = "attack_logs_" + stamp() + ".json";
        File target = new File(exportDir(context), name);
        writeText(target, array.toString(2));
        return target;
    }

    public static File exportCsv(Context context) throws IOException {
        List<AttackLogEntity> all = dao(context).all();
        StringBuilder csv = new StringBuilder();
        csv.append("timestamp,sender,action,reason,escalation,cluster,body\n");
        for (AttackLogEntity item : all) {
            csv.append(item.timestamp).append(',')
                .append(csvCell(item.sender)).append(',')
                .append(csvCell(item.action)).append(',')
                .append(csvCell(item.reason)).append(',')
                .append(csvCell(item.escalation)).append(',')
                .append(csvCell(item.cluster)).append(',')
                .append(csvCell(item.body)).append('\n');
        }

        String name = "attack_logs_" + stamp() + ".csv";
        File target = new File(exportDir(context), name);
        writeText(target, csv.toString());
        return target;
    }

    private static String stamp() {
        return new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
    }

    private static File exportDir(Context context) {
        File dir = new File(context.getExternalFilesDir(null), "exports");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    private static void writeText(File file, @NonNull String text) throws IOException {
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String csvCell(String value) {
        String safe = sanitize(value).replace("\"", "\"\"");
        return "\"" + safe + "\"";
    }
}
