package com.smsshield.bomberprotection;

import android.content.ContentValues;
import android.content.Context;
import android.provider.Telephony;

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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AttackLogStore {
    private static final int MAX_LOG_ITEMS = 200;
    private static final Pattern OTP_PATTERN = Pattern.compile("\\b\\d{4,8}\\b");
    private static final Pattern DOMAIN_CAPTURE_PATTERN = Pattern.compile("(?:https?://)?([a-z0-9-]+(?:\\.[a-z0-9-]+)+)", Pattern.CASE_INSENSITIVE);

    private AttackLogStore() {
    }

    public static final class LogItem {
        public final long id;
        public final String sender;
        public final String body;
        public final long timestamp;
        public final String action;
        public final String reason;
        public final String escalation;
        public final String cluster;
        public final String messageHash;
        public final String campaignId;

        public LogItem(long id, String sender, String body, long timestamp, String action, String reason,
                       String escalation, String cluster, String messageHash, String campaignId) {
            this.id = id;
            this.sender = sender;
            this.body = body;
            this.timestamp = timestamp;
            this.action = action;
            this.reason = reason;
            this.escalation = escalation;
            this.cluster = cluster;
            this.messageHash = messageHash;
            this.campaignId = campaignId;
        }
    }

    public static final class Stats {
        public final int blockedToday;
        public final int silencedToday;
        public final int quarantinedToday;
        public final int attackersToday;

        public Stats(int blockedToday, int silencedToday, int quarantinedToday, int attackersToday) {
            this.blockedToday = blockedToday;
            this.silencedToday = silencedToday;
            this.quarantinedToday = quarantinedToday;
            this.attackersToday = attackersToday;
        }
    }

    public static final class QuarantineGroup {
        public final String serviceIdentity;
        public final String messageHash;
        public final int count;
        public final long latestTimestamp;

        public QuarantineGroup(String serviceIdentity, String messageHash, int count, long latestTimestamp) {
            this.serviceIdentity = serviceIdentity;
            this.messageHash = messageHash;
            this.count = count;
            this.latestTimestamp = latestTimestamp;
        }
    }

    private static final class GroupAccumulator {
        String serviceIdentity;
        String messageHash;
        int count;
        long latestTimestamp;
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
        addLog(context, sender, body, action, reason, "NORMAL", "UNKNOWN", "", "");
    }

    public static synchronized void addLog(Context context, String sender, String body, String action,
                                           String reason, String escalation, String cluster,
                                           String messageHash, String campaignId) {
        AttackLogEntity entity = new AttackLogEntity(
            System.currentTimeMillis(),
            sanitize(sender),
            sanitize(body),
            sanitize(action),
            sanitize(reason),
            sanitize(escalation),
            sanitize(cluster),
            sanitize(messageHash),
            sanitize(campaignId)
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
                item.id,
                item.sender,
                item.body,
                item.timestamp,
                item.action,
                item.reason,
                item.escalation,
                item.cluster,
                item.templateHash,
                item.campaignId
            ));
        }
        return out;
    }

    public static List<QuarantineGroup> getQuarantineOtpGroups(Context context) {
        List<AttackLogEntity> records = dao(context).recent(MAX_LOG_ITEMS);
        Map<String, GroupAccumulator> grouped = new HashMap<>();

        for (AttackLogEntity item : records) {
            if (!"QUARANTINED".equals(item.action)) {
                continue;
            }
            if (!isOtpBody(item.body)) {
                continue;
            }

            String serviceIdentity = extractServiceIdentity(item.body, item.sender, item.cluster);
            String messageHash = sanitize(item.templateHash);
            String key = serviceIdentity + "::" + messageHash;

            GroupAccumulator acc = grouped.get(key);
            if (acc == null) {
                acc = new GroupAccumulator();
                acc.serviceIdentity = serviceIdentity;
                acc.messageHash = messageHash;
                grouped.put(key, acc);
            }

            acc.count += 1;
            acc.latestTimestamp = Math.max(acc.latestTimestamp, item.timestamp);
        }

        List<QuarantineGroup> out = new ArrayList<>();
        for (GroupAccumulator acc : grouped.values()) {
            out.add(new QuarantineGroup(
                acc.serviceIdentity,
                acc.messageHash,
                acc.count,
                acc.latestTimestamp
            ));
        }

        Collections.sort(out, (left, right) -> {
            if (left.count != right.count) {
                return Integer.compare(right.count, left.count);
            }
            return Long.compare(right.latestTimestamp, left.latestTimestamp);
        });
        return out;
    }

    public static Stats getStats(Context context) {
        long since = startOfTodayMs();
        AttackLogDao attackLogDao = dao(context);
        int blocked = attackLogDao.countByActionSince(since, "BLOCKED");
        int silenced = attackLogDao.countByActionSince(since, "SILENCED");
        int quarantined = attackLogDao.countByActionSince(since, "QUARANTINED");
        int attackers = attackLogDao.uniqueAttackersSince(since);
        return new Stats(blocked, silenced, quarantined, attackers);
    }

    public static File exportJson(Context context) throws IOException, JSONException {
        List<AttackLogEntity> all = dao(context).all();
        JSONArray array = new JSONArray();
        for (AttackLogEntity item : all) {
            JSONObject obj = new JSONObject();
            obj.put("timestamp", toIso(item.timestamp));
            obj.put("sender", item.sender);
            obj.put("cluster", item.cluster);
            obj.put("decision", item.action);
            obj.put("reason", item.reason);
            obj.put("message_hash", item.templateHash);
            obj.put("campaign_id", item.campaignId);
            obj.put("escalation", item.escalation);
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
        csv.append("timestamp,sender,cluster,decision,reason,message_hash,campaign_id,escalation\n");
        for (AttackLogEntity item : all) {
            csv.append(csvCell(toIso(item.timestamp))).append(',')
                .append(csvCell(item.sender)).append(',')
                .append(csvCell(item.cluster)).append(',')
                .append(csvCell(item.action)).append(',')
                .append(csvCell(item.reason)).append(',')
                .append(csvCell(item.templateHash)).append(',')
                .append(csvCell(item.campaignId)).append(',')
                .append(csvCell(item.escalation)).append('\n');
        }

        String name = "attack_logs_" + stamp() + ".csv";
        File target = new File(exportDir(context), name);
        writeText(target, csv.toString());
        return target;
    }

    private static String stamp() {
        return new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
    }

    private static String toIso(long epochMs) {
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(new Date(epochMs));
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

    private static boolean isOtpBody(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        return OTP_PATTERN.matcher(body).find();
    }

    private static String extractServiceIdentity(String body, String sender, String cluster) {
        String domain = extractDomain(body);
        if (!domain.isEmpty()) {
            return domain;
        }

        String senderSafe = sanitize(sender).trim();
        if (!senderSafe.isEmpty()) {
            return senderSafe;
        }

        String clusterSafe = sanitize(cluster).trim();
        return clusterSafe.isEmpty() ? "unknown" : clusterSafe;
    }

    private static String extractDomain(String body) {
        if (body == null || body.isEmpty()) {
            return "";
        }
        Matcher matcher = DOMAIN_CAPTURE_PATTERN.matcher(body);
        if (!matcher.find()) {
            return "";
        }

        String domain = matcher.group(1);
        if (domain == null) {
            return "";
        }

        String normalized = domain.toLowerCase(Locale.US);
        if (normalized.startsWith("www.")) {
            return normalized.substring(4);
        }
        return normalized;
    }

    public static synchronized boolean restoreQuarantined(Context context, long logId) {
        AttackLogDao attackLogDao = dao(context);
        AttackLogEntity record = attackLogDao.byId(logId);
        if (record == null || !"QUARANTINED".equals(record.action)) {
            return false;
        }

        ContentValues values = new ContentValues();
        values.put(Telephony.Sms.ADDRESS, record.sender);
        values.put(Telephony.Sms.BODY, record.body);
        values.put(Telephony.Sms.DATE, System.currentTimeMillis());
        values.put(Telephony.Sms.READ, 0);
        values.put(Telephony.Sms.TYPE, Telephony.Sms.MESSAGE_TYPE_INBOX);

        try {
            if (context.getContentResolver().insert(Telephony.Sms.Inbox.CONTENT_URI, values) == null) {
                return false;
            }
            attackLogDao.updateDecision(logId, "RESTORED", "restored_from_quarantine");
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }
}
