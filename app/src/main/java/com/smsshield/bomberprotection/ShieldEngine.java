package com.smsshield.bomberprotection;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
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

    private static final int SUSPICIOUS_SCORE = 4;
    private static final int ATTACK_SCORE = 7;
    private static final int LOCKDOWN_SCORE = 10;

    private static final Pattern OTP_TOKEN_PATTERN = Pattern.compile("\\b\\d{4,8}\\b");
    private static final Pattern ENTERPRISE_PATTERN = Pattern.compile("^[A-Z]{2}-[A-Z0-9]+$");

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
        QUARANTINED
    }

    public static final class Decision {
        public final Action action;
        public final String reason;
        public final EscalationLevel escalation;
        public final boolean panicMode;
        public final String cluster;
        public final String messageHash;
        public final String campaignId;

        public Decision(Action action, String reason, EscalationLevel escalation,
                        boolean panicMode, String cluster, String messageHash,
                        String campaignId) {
            this.action = action;
            this.reason = reason;
            this.escalation = escalation;
            this.panicMode = panicMode;
            this.cluster = cluster;
            this.messageHash = messageHash;
            this.campaignId = campaignId;
        }

        public boolean shouldSuppressDelivery() {
            return action != Action.ALLOW;
        }

        public static Decision allow(EscalationLevel escalation, boolean panicMode,
                                     String cluster, String messageHash, String campaignId) {
            return new Decision(Action.ALLOW, "allowed", escalation, panicMode, cluster, messageHash, campaignId);
        }

        public static Decision blocked(String reason, EscalationLevel escalation, boolean panicMode,
                                       String cluster, String messageHash, String campaignId) {
            return new Decision(Action.BLOCKED, reason, escalation, panicMode, cluster, messageHash, campaignId);
        }

        public static Decision silenced(String reason, EscalationLevel escalation, boolean panicMode,
                                        String cluster, String messageHash, String campaignId) {
            return new Decision(Action.SILENCED, reason, escalation, panicMode, cluster, messageHash, campaignId);
        }

        public static Decision quarantined(String reason, EscalationLevel escalation, boolean panicMode,
                                           String cluster, String messageHash, String campaignId) {
            return new Decision(Action.QUARANTINED, reason, escalation, panicMode, cluster, messageHash, campaignId);
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

    private static final class EntropySnapshot {
        final int uniqueSenders;
        final double entropyBits;
        final int totalEvents;

        EntropySnapshot(int uniqueSenders, double entropyBits, int totalEvents) {
            this.uniqueSenders = uniqueSenders;
            this.entropyBits = entropyBits;
            this.totalEvents = totalEvents;
        }
    }

    public static synchronized Decision evaluate(Context context, String sender, String body, long nowMs) {
        if (!SettingsStore.isShieldOn(context)) {
            return Decision.allow(currentEscalation, false, "UNKNOWN", "", "");
        }

        String safeSender = sender == null ? "" : sender.trim();
        String safeBody = body == null ? "" : body.trim();
        String cluster = clusterKey(safeSender);
        String messageHash = messageHash(safeBody);
        String campaignId = buildCampaignId(messageHash, nowMs);

        pushTime(global60, nowMs, WINDOW_60S_MS);
        pushTime(global120, nowMs, WINDOW_120S_MS);
        pushCluster(cluster60, cluster, nowMs, WINDOW_60S_MS);
        pushCluster(cluster120, cluster, nowMs, WINDOW_120S_MS);
        pushTime(template120.computeIfAbsent(messageHash, key -> new ArrayDeque<>()), nowMs, WINDOW_120S_MS);
        pushTemplateSender(messageHash, safeSender, nowMs);
        pushSenderEvent(safeSender, nowMs);
        trimMaps(nowMs);

        int globalCount60 = global60.size();
        int globalCount120 = global120.size();
        int clusterCount60 = count(cluster60, cluster);
        int clusterCount120 = count(cluster120, cluster);
        int templateCount120 = count(template120, messageHash);
        int templateUniqueSenders = uniqueTemplateSenders(messageHash, nowMs);
        EntropySnapshot entropy = senderEntropy(nowMs);

        int reputationRisk = loadReputationRisk(context, cluster);

        // ─── BAD CLUSTER FAST-PATH ──────────────────────────────────────────────
        // If this cluster has a ≥70% bad-action history (reputationRisk == 3) and
        // the sender is not trusted, skip full scoring and quarantine immediately.
        // This prevents accumulatively-scored clusters from ever slipping through.
        if (reputationRisk >= 3 && !isWhitelisted(context, safeSender) && !isContact(context, safeSender)) {
            EscalationLevel fastEscalation = EscalationLevel.ATTACK;
            currentEscalation = fastEscalation;
            Decision fastDecision = Decision.quarantined(
                "bad_cluster_reputation_fastpath", fastEscalation, true, cluster, messageHash, campaignId);
            persistClusterReputation(context, cluster, fastDecision.action, nowMs);
            persistCampaignFingerprint(context, campaignId, messageHash, cluster, fastEscalation, templateUniqueSenders, nowMs);
            return fastDecision;
        }
        // ───────────────────────────────────────────────────────────────────────

        int riskScore = computeRiskScore(
            globalCount60,
            globalCount120,
            clusterCount120,
            templateCount120,
            templateUniqueSenders,
            entropy,
            isEnterpriseSenderFormat(safeSender),
            containsOtpToken(safeBody),
            reputationRisk
        );

        EscalationLevel escalation = deriveEscalation(globalCount60, globalCount120, clusterCount120, riskScore);
        currentEscalation = escalation;

        if (escalation == EscalationLevel.LOCKDOWN) {
            long untilMs = nowMs + SettingsStore.getLockdownMinutes(context) * 60_000L;
            SettingsStore.setLockdownUntilMs(context, untilMs);
        }

        if (nowMs < SettingsStore.getLockdownUntilMs(context) && escalation != EscalationLevel.LOCKDOWN) {
            escalation = EscalationLevel.LOCKDOWN;
            currentEscalation = EscalationLevel.LOCKDOWN;
        }

        boolean panicMode = escalation == EscalationLevel.ATTACK || escalation == EscalationLevel.LOCKDOWN;
        boolean strictPolicy = SettingsStore.isStrictPolicy(context);
        boolean trusted = isWhitelisted(context, safeSender) || isContact(context, safeSender);

        Decision decision;
        if (SettingsStore.isContactsOnly(context) && !trusted) {
            decision = strictPolicy
                ? Decision.blocked("contacts_only_policy", escalation, panicMode, cluster, messageHash, campaignId)
                : Decision.silenced("contacts_only_policy", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (escalation == EscalationLevel.LOCKDOWN && !trusted) {
            decision = Decision.quarantined("lockdown_contacts_only", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (panicMode && !trusted && strictPolicy) {
            decision = Decision.quarantined("panic_mode_untrusted", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && !consumeUnknownToken(safeSender, nowMs)) {
            decision = Decision.quarantined("unknown_sender_rate_limit", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && clusterCount120 >= CLUSTER_LOCKDOWN_120S) {
            decision = Decision.quarantined("cluster_lockdown_traffic", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && clusterCount120 >= CLUSTER_ATTACK_120S) {
            decision = Decision.blocked("cluster_attack_traffic", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && clusterCount60 >= CLUSTER_SUSPICIOUS_60S) {
            decision = Decision.silenced("cluster_suspicious_burst", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && templateCount120 >= 5) {
            // Single-condition template block: same template seen 5+ times in 120s
            // regardless of how many unique senders — campaign bombardment pattern.
            decision = Decision.quarantined("template_high_frequency", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && templateCount120 >= 4 && templateUniqueSenders >= 3) {
            decision = Decision.quarantined("template_reuse_rotation", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && entropy.totalEvents > 5
                && (double) entropy.uniqueSenders / entropy.totalEvents > 0.70d) {
            // Entropy ratio check: if >70% of messages in 120s come from distinct
            // senders, this is a rotating-sender attack even if absolute counts are low.
            decision = Decision.quarantined("high_sender_entropy_ratio", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && entropy.uniqueSenders >= 6 && entropy.entropyBits >= 2.2d) {
            decision = Decision.quarantined("high_sender_entropy", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && riskScore >= LOCKDOWN_SCORE - 1) {
            decision = Decision.quarantined("adaptive_risk_score", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!trusted && escalation == EscalationLevel.SUSPICIOUS && isEnterpriseSenderFormat(safeSender)) {
            decision = Decision.silenced("suspicious_enterprise_sender", escalation, panicMode, cluster, messageHash, campaignId);
        } else {
            decision = Decision.allow(escalation, panicMode, cluster, messageHash, campaignId);
        }

        if (isMiuiHyperOsDevice() && !trusted && decision.action == Action.BLOCKED) {
            decision = Decision.quarantined("miui_pipeline_resilience", escalation, panicMode, cluster, messageHash, campaignId);
        }

        persistClusterReputation(context, cluster, decision.action, nowMs);
        persistCampaignFingerprint(context, campaignId, messageHash, cluster, escalation, templateUniqueSenders, nowMs);
        return decision;
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

    private static EscalationLevel deriveEscalation(int count60, int count120, int clusterCount120, int riskScore) {
        if (count120 >= LOCKDOWN_LIMIT_120S || clusterCount120 >= CLUSTER_LOCKDOWN_120S || riskScore >= LOCKDOWN_SCORE) {
            return EscalationLevel.LOCKDOWN;
        }
        if (count120 >= ATTACK_LIMIT_120S || clusterCount120 >= CLUSTER_ATTACK_120S || riskScore >= ATTACK_SCORE) {
            return EscalationLevel.ATTACK;
        }
        if (count60 >= SUSPICIOUS_LIMIT_60S || riskScore >= SUSPICIOUS_SCORE) {
            return EscalationLevel.SUSPICIOUS;
        }
        return EscalationLevel.NORMAL;
    }

    private static int computeRiskScore(int globalCount60, int globalCount120, int clusterCount120,
                                        int templateCount120, int templateUniqueSenders,
                                        EntropySnapshot entropy, boolean enterpriseSender,
                                        boolean hasOtpToken, int reputationRisk) {
        int score = reputationRisk;

        if (globalCount60 >= SUSPICIOUS_LIMIT_60S) {
            score += 2;
        }
        if (globalCount120 >= ATTACK_LIMIT_120S) {
            score += 3;
        }
        if (clusterCount120 >= CLUSTER_ATTACK_120S) {
            score += 3;
        } else if (clusterCount120 >= CLUSTER_SUSPICIOUS_60S) {
            score += 1;
        }

        if (templateCount120 >= 3) {
            score += 2;
        }
        if (templateCount120 >= 5) {
            score += 2;
        }
        if (templateUniqueSenders >= 3) {
            score += 2;
        }

        if (entropy.uniqueSenders >= 5) {
            score += 2;
        }
        if (entropy.uniqueSenders >= 8) {
            score += 2;
        }
        if (entropy.entropyBits >= 2.2d) {
            score += 2;
        }
        if (entropy.entropyBits >= 2.8d) {
            score += 1;
        }

        if (enterpriseSender && hasOtpToken) {
            score += 1;
        }
        return score;
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

    private static String messageHash(String body) {
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
            return "otp_template_" + hex;
        } catch (NoSuchAlgorithmException e) {
            return "otp_template_" + Integer.toHexString(canonical.hashCode());
        }
    }

    private static String buildCampaignId(String messageHash, long nowMs) {
        long windowBucket = nowMs / WINDOW_120S_MS;
        return messageHash + "_" + Long.toString(windowBucket, 36);
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

    private static EntropySnapshot senderEntropy(long nowMs) {
        trimSenderEvents(senderEvents120, nowMs, WINDOW_120S_MS);
        if (senderEvents120.isEmpty()) {
            return new EntropySnapshot(0, 0.0d, 0);
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

        return new EntropySnapshot(frequencies.size(), entropy, senderEvents120.size());
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
        return ENTERPRISE_PATTERN.matcher(sender.toUpperCase(Locale.US)).matches();
    }

    private static boolean isMiuiHyperOsDevice() {
        String brand = Build.BRAND == null ? "" : Build.BRAND.toLowerCase(Locale.US);
        String manufacturer = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER.toLowerCase(Locale.US);
        return brand.contains("xiaomi")
            || brand.contains("redmi")
            || brand.contains("poco")
            || manufacturer.contains("xiaomi");
    }

    private static int loadReputationRisk(Context context, String cluster) {
        SenderClusterReputationEntity entity = ShieldDatabase.get(context)
            .senderClusterReputationDao()
            .byCluster(cluster);

        if (entity == null || entity.totalCount < 5) {
            return 0;
        }

        double suspiciousRatio = (double) (entity.blockedCount + entity.silencedCount + entity.quarantinedCount)
            / (double) entity.totalCount;

        if (suspiciousRatio >= 0.7d) {
            return 3;
        }
        if (suspiciousRatio >= 0.45d) {
            return 2;
        }
        if (suspiciousRatio >= 0.3d) {
            return 1;
        }
        return 0;
    }

    private static void persistClusterReputation(Context context, String cluster, Action action, long nowMs) {
        SenderClusterReputationDao dao = ShieldDatabase.get(context).senderClusterReputationDao();
        SenderClusterReputationEntity entity = dao.byCluster(cluster);
        if (entity == null) {
            entity = new SenderClusterReputationEntity(cluster, 0, 0, 0, 0, nowMs);
        }

        entity.totalCount += 1;
        entity.lastSeenMs = nowMs;
        if (action == Action.BLOCKED) {
            entity.blockedCount += 1;
        } else if (action == Action.SILENCED) {
            entity.silencedCount += 1;
        } else if (action == Action.QUARANTINED) {
            entity.quarantinedCount += 1;
        }
        dao.upsert(entity);
    }

    private static void persistCampaignFingerprint(Context context, String campaignId, String messageHash,
                                                   String cluster, EscalationLevel escalation,
                                                   int uniqueSenderCount, long nowMs) {
        CampaignFingerprintDao dao = ShieldDatabase.get(context).campaignFingerprintDao();
        CampaignFingerprintEntity entity = dao.byCampaignId(campaignId);
        if (entity == null) {
            entity = new CampaignFingerprintEntity(
                campaignId,
                messageHash,
                cluster,
                escalation.name(),
                nowMs,
                nowMs,
                0,
                uniqueSenderCount
            );
        }

        entity.lastSeenMs = nowMs;
        entity.totalCount += 1;
        entity.uniqueSenderCount = Math.max(entity.uniqueSenderCount, uniqueSenderCount);
        if (escalation.ordinal() > EscalationLevel.valueOf(entity.highestEscalation).ordinal()) {
            entity.highestEscalation = escalation.name();
        }
        if (entity.topCluster.equals("UNKNOWN") && !cluster.equals("UNKNOWN")) {
            entity.topCluster = cluster;
        }
        dao.upsert(entity);
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
