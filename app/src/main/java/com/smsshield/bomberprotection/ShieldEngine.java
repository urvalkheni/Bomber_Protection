package com.smsshield.bomberprotection;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.provider.ContactsContract;
import android.telephony.PhoneNumberUtils;

import androidx.core.content.ContextCompat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ShieldEngine {
    private static final long WINDOW_60S_MS = 60_000L;
    private static final long WINDOW_120S_MS = 120_000L;

    private static final int SUSPICIOUS_LIMIT_60S = 6;
    private static final int ATTACK_LIMIT_120S = 10;
    private static final int LOCKDOWN_LIMIT_120S = 15;

    private static final int CLUSTER_SUSPICIOUS_60S = 4;
    private static final int CLUSTER_ATTACK_120S = 7;
    private static final int CLUSTER_LOCKDOWN_120S = 10;

    private static final Pattern OTP_TOKEN_PATTERN = Pattern.compile("\\b\\d{4,8}\\b");
    private static final Pattern PREFIX_PATTERN = Pattern.compile("^(?:[A-Z]{2,8})(?:-[A-Z0-9]{1,10})?$");

    private static final Deque<Long> global60 = new ArrayDeque<>();
    private static final Deque<Long> global120 = new ArrayDeque<>();

    private static final Map<String, Deque<Long>> cluster60 = new HashMap<>();
    private static final Map<String, Deque<Long>> cluster120 = new HashMap<>();
    private static final Map<String, Deque<Long>> template120 = new HashMap<>();
    private static final Map<String, Deque<SenderEvent>> templateSender120 = new HashMap<>();
    private static final Deque<SenderEvent> senderEvents120 = new ArrayDeque<>();
    private static final Map<String, TokenBucket> unknownSenderBuckets = new HashMap<>();

    private static volatile EscalationLevel currentEscalation = EscalationLevel.NORMAL;

    private ShieldEngine() {
    }

    public enum EscalationLevel {
        NORMAL,
        SUSPICIOUS,
        ATTACK,
        LOCKDOWN
    }

    public enum Action {
        ALLOW,
        BLOCKED,
        SILENCED,
        SUPPRESSED
    }

    public static final class Decision {
        public final Action action;
        public final String reason;
        public final EscalationLevel escalation;
        public final boolean panicMode;
        public final String cluster;
        public final String templateHash;

        public Decision(Action action, String reason, EscalationLevel escalation,
                        boolean panicMode, String cluster, String templateHash) {
            this.action = action;
            this.reason = reason;
            this.escalation = escalation;
            this.panicMode = panicMode;
            this.cluster = cluster;
            this.templateHash = templateHash;
        }

        public boolean shouldSuppressDelivery() {
            return action != Action.ALLOW;
        }

        public static Decision allow(EscalationLevel escalation, boolean panicMode,
                                     String cluster, String templateHash) {
            return new Decision(Action.ALLOW, "allowed", escalation, panicMode, cluster, templateHash);
        }

        public static Decision blocked(String reason, EscalationLevel escalation, boolean panicMode,
                                       String cluster, String templateHash) {
            return new Decision(Action.BLOCKED, reason, escalation, panicMode, cluster, templateHash);
        }

        public static Decision silenced(String reason, EscalationLevel escalation, boolean panicMode,
                                        String cluster, String templateHash) {
            return new Decision(Action.SILENCED, reason, escalation, panicMode, cluster, templateHash);
        }

        public static Decision suppressed(String reason, EscalationLevel escalation, boolean panicMode,
                                          String cluster, String templateHash) {
            return new Decision(Action.SUPPRESSED, reason, escalation, panicMode, cluster, templateHash);
        }
    }

    private static final class SenderEvent {
        final String sender;
        final long timeMs;

        SenderEvent(String sender, long timeMs) {
            this.sender = sender;
            this.timeMs = timeMs;
        }
    }

    private static final class TokenBucket {
        final double capacity;
        final double refillPerMs;
        double tokens;
        long lastMs;

        TokenBucket(double capacity, double refillPerSecond, long nowMs) {
            this.capacity = capacity;
            this.refillPerMs = refillPerSecond / 1000.0;
            this.tokens = capacity;
            this.lastMs = nowMs;
        }

        boolean tryConsume(long nowMs, double amount) {
            long elapsed = Math.max(0L, nowMs - lastMs);
            tokens = Math.min(capacity, tokens + elapsed * refillPerMs);
            lastMs = nowMs;
            if (tokens >= amount) {
                tokens -= amount;
                return true;
            }
            return false;
        }
    }

    public static synchronized Decision evaluate(Context context, String sender, String body, long nowMs) {
        if (!SettingsStore.isShieldOn(context)) {
            return Decision.allow(currentEscalation, false, "UNKNOWN", "");
        }

        String safeSender = sender == null ? "" : sender.trim();
        String safeBody = body == null ? "" : body.trim();
        String cluster = clusterKey(safeSender);
        String templateHash = templateHash(safeBody);

        pushTime(global60, nowMs, WINDOW_60S_MS);
        pushTime(global120, nowMs, WINDOW_120S_MS);

        pushCluster(cluster60, cluster, nowMs, WINDOW_60S_MS);
        pushCluster(cluster120, cluster, nowMs, WINDOW_120S_MS);

        pushTime(template120.computeIfAbsent(templateHash, key -> new ArrayDeque<>()), nowMs, WINDOW_120S_MS);
        pushTemplateSender(templateHash, safeSender, nowMs);

        pushSenderEvent(safeSender, nowMs);
        trimMaps(nowMs);

        EscalationLevel escalation = deriveEscalation(global60.size(), global120.size());
        currentEscalation = escalation;
        boolean panicMode = escalation == EscalationLevel.ATTACK || escalation == EscalationLevel.LOCKDOWN;

        boolean trusted = isWhitelisted(context, safeSender) || isContact(context, safeSender);

        if (SettingsStore.isContactsOnly(context) && !trusted) {
            return Decision.blocked("contacts-only mode", escalation, panicMode, cluster, templateHash);
        }

        // Panic mode: during attack/lockdown, allow contacts/whitelist only.
        if (panicMode && !trusted) {
            return Decision.suppressed("panic mode contacts-only", escalation, panicMode, cluster, templateHash);
        }

        if (!trusted && !consumeUnknownToken(safeSender, nowMs)) {
            return Decision.suppressed("token bucket limited unknown sender", escalation, panicMode, cluster, templateHash);
        }

        int clusterCount60 = count(cluster60, cluster);
        int clusterCount120 = count(cluster120, cluster);
        if (clusterCount120 >= CLUSTER_LOCKDOWN_120S) {
            return Decision.suppressed("cluster lockdown traffic", escalation, panicMode, cluster, templateHash);
        }
        if (clusterCount120 >= CLUSTER_ATTACK_120S) {
            return Decision.blocked("cluster attack traffic", escalation, panicMode, cluster, templateHash);
        }
        if (clusterCount60 >= CLUSTER_SUSPICIOUS_60S) {
            return Decision.silenced("cluster suspicious burst", escalation, panicMode, cluster, templateHash);
        }

        boolean hasOtpToken = containsOtpToken(safeBody);
        if (hasOtpToken) {
            int templateCount = template120.get(templateHash).size();
            int templateUniqueSenders = uniqueTemplateSenders(templateHash, nowMs);
            if (templateCount >= 4 && templateUniqueSenders >= 3) {
                return Decision.suppressed("rotating sender OTP template", escalation, panicMode, cluster, templateHash);
            }
        }

        EntropySnapshot entropy = senderEntropy(nowMs);
        if (entropy.uniqueSenders >= 6 && entropy.entropyBits >= 2.2d) {
            return Decision.suppressed("high sender entropy rotation", escalation, panicMode, cluster, templateHash);
        }

        if (escalation == EscalationLevel.LOCKDOWN && !trusted) {
            return Decision.suppressed("global lockdown", escalation, panicMode, cluster, templateHash);
        }
        if (escalation == EscalationLevel.ATTACK && !trusted) {
            return Decision.blocked("global attack threshold", escalation, panicMode, cluster, templateHash);
        }
        if (escalation == EscalationLevel.SUSPICIOUS && isEnterpriseSenderFormat(safeSender) && !trusted) {
            return Decision.silenced("suspicious enterprise sender burst", escalation, panicMode, cluster, templateHash);
        }

        return Decision.allow(escalation, panicMode, cluster, templateHash);
    }

    public static EscalationLevel getCurrentEscalation() {
        return currentEscalation;
    }

    public static boolean isPanicModeActive() {
        return currentEscalation == EscalationLevel.ATTACK || currentEscalation == EscalationLevel.LOCKDOWN;
    }

    private static void pushTime(Deque<Long> queue, long nowMs, long windowMs) {
        trim(queue, nowMs, windowMs);
        queue.addLast(nowMs);
    }

    private static void pushCluster(Map<String, Deque<Long>> bucketMap, String cluster, long nowMs, long windowMs) {
        Deque<Long> queue = bucketMap.computeIfAbsent(cluster, key -> new ArrayDeque<>());
        pushTime(queue, nowMs, windowMs);
    }

    private static void pushTemplateSender(String templateHash, String sender, long nowMs) {
        Deque<SenderEvent> queue = templateSender120.computeIfAbsent(templateHash, key -> new ArrayDeque<>());
        trimSenderEvents(queue, nowMs, WINDOW_120S_MS);
        queue.addLast(new SenderEvent(sender, nowMs));
    }

    private static void pushSenderEvent(String sender, long nowMs) {
        trimSenderEvents(senderEvents120, nowMs, WINDOW_120S_MS);
        senderEvents120.addLast(new SenderEvent(sender, nowMs));
    }

    private static void trim(Deque<Long> queue, long nowMs, long windowMs) {
        while (!queue.isEmpty() && nowMs - queue.peekFirst() > windowMs) {
            queue.removeFirst();
        }
    }

    private static void trimSenderEvents(Deque<SenderEvent> queue, long nowMs, long windowMs) {
        while (!queue.isEmpty() && nowMs - queue.peekFirst().timeMs > windowMs) {
            queue.removeFirst();
        }
    }

    private static void trimMaps(long nowMs) {
        cleanupQueueMap(cluster60, nowMs, WINDOW_60S_MS);
        cleanupQueueMap(cluster120, nowMs, WINDOW_120S_MS);
        cleanupQueueMap(template120, nowMs, WINDOW_120S_MS);

        ArrayList<String> emptyTemplates = new ArrayList<>();
        for (Map.Entry<String, Deque<SenderEvent>> entry : templateSender120.entrySet()) {
            trimSenderEvents(entry.getValue(), nowMs, WINDOW_120S_MS);
            if (entry.getValue().isEmpty()) {
                emptyTemplates.add(entry.getKey());
            }
        }
        for (String key : emptyTemplates) {
            templateSender120.remove(key);
        }
    }

    private static void cleanupQueueMap(Map<String, Deque<Long>> map, long nowMs, long windowMs) {
        ArrayList<String> empty = new ArrayList<>();
        for (Map.Entry<String, Deque<Long>> entry : map.entrySet()) {
            trim(entry.getValue(), nowMs, windowMs);
            if (entry.getValue().isEmpty()) {
                empty.add(entry.getKey());
            }
        }
        for (String key : empty) {
            map.remove(key);
        }
    }

    private static int count(Map<String, Deque<Long>> map, String key) {
        Deque<Long> queue = map.get(key);
        return queue == null ? 0 : queue.size();
    }

    private static EscalationLevel deriveEscalation(int count60, int count120) {
        if (count120 >= LOCKDOWN_LIMIT_120S) {
            return EscalationLevel.LOCKDOWN;
        }
        if (count120 >= ATTACK_LIMIT_120S) {
            return EscalationLevel.ATTACK;
        }
        if (count60 >= SUSPICIOUS_LIMIT_60S) {
            return EscalationLevel.SUSPICIOUS;
        }
        return EscalationLevel.NORMAL;
    }

    private static boolean containsOtpToken(String body) {
        Matcher matcher = OTP_TOKEN_PATTERN.matcher(body);
        return matcher.find();
    }

    private static String clusterKey(String sender) {
        if (sender == null || sender.isEmpty()) {
            return "UNKNOWN";
        }

        String upper = sender.toUpperCase(Locale.US).trim();
        int dash = upper.indexOf('-');
        if (dash > 0) {
            String head = upper.substring(0, dash).replaceAll("[^A-Z]", "");
            if (!head.isEmpty()) {
                return head;
            }
        }

        String letters = upper.replaceAll("[^A-Z]", "");
        if (!letters.isEmpty()) {
            return letters.substring(0, Math.min(3, letters.length()));
        }

        if (upper.matches("^[0-9+]+$")) {
            return "NUMERIC";
        }
        return "UNKNOWN";
    }

    private static String templateHash(String body) {
        String canonical = body.toLowerCase(Locale.US)
            .replaceAll("\\d", "")
            .replaceAll("\\s+", " ")
            .trim();

        if (canonical.isEmpty()) {
            canonical = "empty";
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < Math.min(bytes.length, 8); i++) {
                hex.append(String.format(Locale.US, "%02x", bytes[i]));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(canonical.hashCode());
        }
    }

    private static int uniqueTemplateSenders(String templateHash, long nowMs) {
        Deque<SenderEvent> queue = templateSender120.get(templateHash);
        if (queue == null) {
            return 0;
        }

        trimSenderEvents(queue, nowMs, WINDOW_120S_MS);
        Set<String> unique = new HashSet<>();
        for (SenderEvent event : queue) {
            unique.add(event.sender);
        }
        return unique.size();
    }

    private static final class EntropySnapshot {
        final int uniqueSenders;
        final double entropyBits;

        EntropySnapshot(int uniqueSenders, double entropyBits) {
            this.uniqueSenders = uniqueSenders;
            this.entropyBits = entropyBits;
        }
    }

    private static EntropySnapshot senderEntropy(long nowMs) {
        trimSenderEvents(senderEvents120, nowMs, WINDOW_120S_MS);
        if (senderEvents120.isEmpty()) {
            return new EntropySnapshot(0, 0.0d);
        }

        Map<String, Integer> frequencies = new HashMap<>();
        for (SenderEvent event : senderEvents120) {
            int count = frequencies.containsKey(event.sender) ? frequencies.get(event.sender) : 0;
            frequencies.put(event.sender, count + 1);
        }

        double total = senderEvents120.size();
        double entropy = 0.0d;
        for (Integer count : frequencies.values()) {
            double p = count / total;
            entropy += -p * (Math.log(p) / Math.log(2));
        }

        return new EntropySnapshot(frequencies.size(), entropy);
    }

    private static boolean consumeUnknownToken(String sender, long nowMs) {
        String key = sender == null || sender.isEmpty() ? "UNKNOWN" : sender;
        TokenBucket bucket = unknownSenderBuckets.get(key);
        if (bucket == null) {
            bucket = new TokenBucket(4.0d, 0.25d, nowMs);
            unknownSenderBuckets.put(key, bucket);
        }
        return bucket.tryConsume(nowMs, 1.0d);
    }

    private static boolean isEnterpriseSenderFormat(String sender) {
        if (sender == null || sender.isEmpty()) {
            return false;
        }
        return PREFIX_PATTERN.matcher(sender.toUpperCase(Locale.US)).matches();
    }

    private static boolean isWhitelisted(Context context, String sender) {
        Set<String> white = SettingsStore.getWhitelist(context);
        for (String w : white) {
            if (PhoneNumberUtils.compare(sender, w) || sender.equalsIgnoreCase(w)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isContact(Context context, String sender) {
        if (sender == null || sender.isEmpty()) {
            return false;
        }
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS)
            != PackageManager.PERMISSION_GRANTED) {
            return false;
        }

        String normalized = PhoneNumberUtils.normalizeNumber(sender);
        if (normalized == null || normalized.isEmpty()) {
            normalized = sender;
        }

        String[] projection = new String[]{ContactsContract.PhoneLookup._ID};
        try (android.database.Cursor cursor = context.getContentResolver().query(
            android.net.Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, android.net.Uri.encode(normalized)),
            projection,
            null,
            null,
            null
        )) {
            return cursor != null && cursor.moveToFirst();
        } catch (Exception ignored) {
            return false;
        }
    }
}
