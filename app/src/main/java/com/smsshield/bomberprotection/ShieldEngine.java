package com.smsshield.bomberprotection;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.ContactsContract;
import android.provider.Telephony;
import android.telephony.PhoneNumberUtils;

import androidx.core.content.ContextCompat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
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
    private static final int PRIMARY_OTP_UPGRADE_MARGIN = 15;
    private static final int AUTO_TRUST_AFTER_SUCCESS_COUNT = 3;
    private static final int MAX_OTP_OVERRIDE_ALLOWANCES_PER_GROUP = 1;
    private static final long PROTECTED_LATE_OVERRIDE_WINDOW_MS = 60_000L;
    private static final int HIGH_CONFIDENCE_PRIORITY_SCORE = 70;

    private static final long OTP_SELECTION_WINDOW_MS = 120_000L;
    private static final int CAMPAIGN_LOCK_MIN_EVENTS = 7;
    private static final double CAMPAIGN_LOCK_ENTROPY_RATIO = 0.70d;

    private static final Pattern OTP_TOKEN_PATTERN = Pattern.compile("\\b\\d{4,8}\\b");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("\\b(?:https?://)?(?:[a-z0-9-]+\\.)+[a-z]{2,}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL_DOMAIN_CAPTURE_PATTERN = Pattern.compile("(?:https?://)?([a-z0-9-]+(?:\\.[a-z0-9-]+)+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ENTERPRISE_PATTERN = Pattern.compile("^[A-Z]{2}-[A-Z0-9]+$");

    private static final Set<String> TRUSTED_SERVICE_TOKENS = new HashSet<>(Arrays.asList(
        "HDFC", "SBI", "ICICI", "AXIS", "KOTAK", "PNB", "BOB", "IDFC", "CANARA", "YESBNK",
        "UNIONB", "INDUSB", "AUBANK", "PAYTM", "PHONEPE", "BHIM", "GPAY", "AMZN", "AMAZON",
        "FLIPKART", "MYNTRA", "MEESHO", "SWIGGY", "ZOMATO", "OLA", "UBER", "AIRTEL", "JIO",
        "VI", "BSNL", "TATAPLAY", "GOOGL", "GOOGLE", "META", "WHATSAPP", "TELEGRAM", "APPLE",
        "MSFT", "MICROSOFT", "AMAZN", "NETFLIX", "ADOBE", "PAYPAL", "STRIPE", "GITHUB",
        "LINKEDIN", "INSTAGRAM", "FACEBOOK"
    ));

    private static final Deque<Long> global60 = new ArrayDeque<>();
    private static final Deque<Long> global120 = new ArrayDeque<>();

    private static final Map<String, Deque<Long>> cluster60 = new HashMap<>();
    private static final Map<String, Deque<Long>> cluster120 = new HashMap<>();
    private static final Map<String, Deque<Long>> template120 = new HashMap<>();
    private static final Map<String, Deque<SenderEvent>> templateSender120 = new HashMap<>();
    private static final Deque<SenderEvent> senderEvents120 = new ArrayDeque<>();
    private static final Map<String, TokenBucket> unknownSenderBuckets = new HashMap<>();
    private static final Map<String, OtpGroupState> otpGroups = new HashMap<>();
    private static final Map<String, Deque<Long>> intentOtpAllowances120ByService = new HashMap<>();
    private static final Deque<Long> allowedOtpGlobal120 = new ArrayDeque<>();
    private static final Deque<Long> campaignLockAllowedOtp120 = new ArrayDeque<>();

    private static volatile EscalationLevel currentEscalation = EscalationLevel.NORMAL;
    private static volatile long attackCooldownUntilMs = 0L;

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

        public static Decision allowed(String reason, EscalationLevel escalation, boolean panicMode,
                                       String cluster, String messageHash, String campaignId) {
            return new Decision(Action.ALLOW, reason, escalation, panicMode, cluster, messageHash, campaignId);
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

    private static final class OtpGroupState {
        long lastSeenMs;
        int seenCount;
        int allowedCount;
        int overrideCount;
        int primaryScore;
        long primarySelectedAtMs;
        String primarySender;

        OtpGroupState(long nowMs) {
            this.lastSeenMs = nowMs;
            this.seenCount = 0;
            this.allowedCount = 0;
            this.overrideCount = 0;
            this.primaryScore = Integer.MIN_VALUE;
            this.primarySelectedAtMs = 0L;
            this.primarySender = "";
        }
    }

    public static synchronized Decision evaluate(Context context, String sender, String body, long nowMs) {
        return evaluate(context, sender, body, "sim_unknown", nowMs);
    }

    public static synchronized Decision evaluate(Context context, String sender, String body,
                                                 String simContext, long nowMs) {
        if (!SettingsStore.isShieldOn(context)) {
            return Decision.allow(currentEscalation, false, "UNKNOWN", "", "");
        }

        String safeSender = sender == null ? "" : sender.trim();
        String safeBody = body == null ? "" : body.trim();
        String cluster = clusterKey(safeSender);
        String messageHash = messageHash(safeBody);
        String safeSimContext = sanitizeSimContext(simContext);
        String serviceIdentity = resolveServiceIdentity(safeBody, safeSender, cluster);
        String otpGroupKey = buildOtpGroupKey(messageHash, serviceIdentity, safeSimContext);
        String campaignId = buildCampaignId(messageHash, serviceIdentity, safeSimContext, nowMs);

        pushTime(global60, nowMs, WINDOW_60S_MS);
        pushTime(global120, nowMs, WINDOW_120S_MS);
        pushCluster(cluster60, cluster, nowMs, WINDOW_60S_MS);
        pushCluster(cluster120, cluster, nowMs, WINDOW_120S_MS);
        pushTime(template120.computeIfAbsent(otpGroupKey, key -> new ArrayDeque<>()), nowMs, WINDOW_120S_MS);
        pushTemplateSender(otpGroupKey, safeSender, nowMs);
        pushSenderEvent(safeSender, nowMs);
        trimMaps(nowMs);

        int globalCount60 = global60.size();
        int globalCount120 = global120.size();
        int clusterCount120 = count(cluster120, cluster);
        int templateCount120 = count(template120, otpGroupKey);
        int templateUniqueSenders = uniqueTemplateSenders(otpGroupKey, nowMs);
        EntropySnapshot entropy = senderEntropy(nowMs);
        double entropyRatio = entropy.totalEvents == 0
            ? 0.0d
            : (double) entropy.uniqueSenders / (double) entropy.totalEvents;

        int reputationRisk = loadReputationRisk(context, cluster);
        boolean hasOtpToken = containsOtpToken(safeBody);
        boolean hasDomain = containsDomain(safeBody);
        boolean trustedByWhitelist = isWhitelisted(context, safeSender);
        boolean trustedByLearned = isLearnedTrustedSender(context, safeSender);
        boolean trustedByContact = isContact(context, safeSender);
        boolean trustedByKnownService = isKnownServiceSender(safeSender, cluster);
        boolean userRequestedOtp = hasOtpToken
            && SettingsStore.isExpectOtpWindowActive(context, nowMs, serviceIdentity);
        int senderSuccessCount = SettingsStore.getSenderSuccessCount(context, safeSender);
        int senderRecentCount = senderRecentFrequency(safeSender, nowMs);
        boolean behavioralTrustPromotion = senderSuccessCount >= 2
            && senderRecentCount <= 2
            && !hasDomain
            && !trustedByKnownService;
        boolean trustedSender = trustedByWhitelist || trustedByLearned || trustedByContact;

        int riskScore = computeRiskScore(
            globalCount60,
            globalCount120,
            clusterCount120,
            templateCount120,
            templateUniqueSenders,
            entropy,
            entropyRatio,
            isEnterpriseSenderFormat(safeSender),
            hasOtpToken,
            hasDomain,
            reputationRisk
        );

        int trustScore = computeTrustScore(
            trustedByWhitelist,
            trustedByLearned,
            trustedByContact,
            trustedByKnownService,
            userRequestedOtp,
            hasDomain,
            hasOtpToken,
            globalCount60,
            templateCount120,
            clusterCount120,
            entropyRatio,
            reputationRisk,
            senderSuccessCount,
            senderRecentCount,
            behavioralTrustPromotion
        );
        int confidenceScore = trustScore - (riskScore * 10);

        EscalationLevel escalation = deriveEscalation(globalCount60, globalCount120, clusterCount120, riskScore);
        escalation = applyAttackCooldown(context, escalation, nowMs);
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
        boolean campaignLockMode = hasOtpToken
            && entropy.totalEvents >= CAMPAIGN_LOCK_MIN_EVENTS
            && entropyRatio > CAMPAIGN_LOCK_ENTROPY_RATIO;

        if (campaignLockMode) {
            escalation = maxEscalation(escalation, EscalationLevel.ATTACK);
            currentEscalation = escalation;
            panicMode = true;
            attackCooldownUntilMs = Math.max(
                attackCooldownUntilMs,
                nowMs + SettingsStore.getAttackCooldownMs(context)
            );
        }

        Decision decision;
        if (SettingsStore.isContactsOnly(context) && !trustedSender && !userRequestedOtp) {
            decision = strictPolicy
                ? Decision.quarantined("contacts_only_policy", escalation, panicMode, cluster, messageHash, campaignId)
                : Decision.silenced("contacts_only_policy", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (hasOtpToken) {
            decision = evaluateOtpDecision(
                context,
                safeSender,
                cluster,
                messageHash,
                otpGroupKey,
                serviceIdentity,
                campaignId,
                escalation,
                panicMode,
                trustedSender,
                trustedByKnownService,
                userRequestedOtp,
                hasDomain,
                riskScore,
                trustScore,
                confidenceScore,
                templateCount120,
                entropyRatio,
                campaignLockMode,
                nowMs
            );
        } else if (trustedSender) {
            decision = Decision.allowed("trusted_sender", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (reputationRisk >= 3) {
            decision = Decision.quarantined("bad_cluster_reputation", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (!consumeUnknownToken(safeSender, nowMs)) {
            decision = Decision.quarantined("unknown_sender_rate_limit", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (escalation == EscalationLevel.LOCKDOWN || riskScore >= LOCKDOWN_SCORE + 1 || confidenceScore <= -55) {
            decision = Decision.quarantined("extreme_flood_quarantine", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (riskScore >= ATTACK_SCORE
                || clusterCount120 >= CLUSTER_ATTACK_120S
                || templateCount120 >= 5
                || (entropy.totalEvents > 5 && entropyRatio > 0.70d)) {
            decision = Decision.quarantined("high_risk_quarantine", escalation, panicMode, cluster, messageHash, campaignId);
        } else if (riskScore >= SUSPICIOUS_SCORE || escalation == EscalationLevel.SUSPICIOUS || confidenceScore < 0) {
            decision = strictPolicy
                ? Decision.quarantined("suspicious_quarantine", escalation, panicMode, cluster, messageHash, campaignId)
                : Decision.silenced("suspicious_silence", escalation, panicMode, cluster, messageHash, campaignId);
        } else {
            decision = Decision.allow(escalation, panicMode, cluster, messageHash, campaignId);
        }

        if (isMiuiHyperOsDevice() && decision.action == Action.BLOCKED) {
            decision = Decision.quarantined("miui_pipeline_resilience", escalation, panicMode, cluster, messageHash, campaignId);
        }

        if (decision.action == Action.ALLOW && hasOtpToken
            && !trustedByWhitelist && !trustedByLearned && !trustedByContact) {
            int successCount = SettingsStore.incrementSenderSuccessCount(context, safeSender);
            if (successCount >= AUTO_TRUST_AFTER_SUCCESS_COUNT) {
                SettingsStore.addLearnedTrustedSender(context, safeSender);
                SettingsStore.clearSenderSuccessCount(context, safeSender);
            }
        }

        persistClusterReputation(context, cluster, decision.action, nowMs);
        persistCampaignFingerprint(context, campaignId, messageHash, cluster, escalation, templateUniqueSenders, nowMs);
        return decision;
    }

    private static Decision evaluateOtpDecision(Context context, String sender, String cluster,
                                                String messageHash, String otpGroupKey,
                                                String serviceIdentity, String campaignId,
                                                EscalationLevel escalation, boolean panicMode,
                                                boolean trustedSender, boolean trustedByKnownService,
                                                boolean userRequestedOtp, boolean hasDomain,
                                                int riskScore, int trustScore, int confidenceScore,
                                                int templateCount120, double entropyRatio,
                                                boolean campaignLockMode, long nowMs) {
        trimOtpSelectionState(nowMs);

        OtpGroupState group = otpGroups.get(otpGroupKey);
        if (group == null) {
            group = new OtpGroupState(nowMs);
            otpGroups.put(otpGroupKey, group);
        }
        group.lastSeenMs = nowMs;
        group.seenCount += 1;

        int priorityScore = computeOtpPriorityScore(
            trustedSender,
            trustedByKnownService,
            hasDomain,
            group.seenCount,
            templateCount120,
            entropyRatio,
            riskScore,
            trustScore,
            confidenceScore
        );
        boolean highConfidenceOtp = isHighConfidenceOtp(priorityScore, trustScore, riskScore, confidenceScore);

        int intentMax = SettingsStore.getExpectOtpMaxMessages(context);
        Deque<Long> serviceIntentAllowances = intentOtpAllowances120ByService
            .computeIfAbsent(serviceIdentity, key -> new ArrayDeque<>());
        int usedIntentAllowance = countRecent(serviceIntentAllowances, nowMs, OTP_SELECTION_WINDOW_MS);
        if (userRequestedOtp && usedIntentAllowance >= intentMax) {
            return Decision.quarantined("otp_intent_window_limit_" + serviceIdentity, escalation, panicMode, cluster, messageHash, campaignId);
        }

        int usedCampaignAllowance = countRecent(campaignLockAllowedOtp120, nowMs, OTP_SELECTION_WINDOW_MS);

        if (group.allowedCount == 0) {
            if (campaignLockMode && usedCampaignAllowance >= 1 && !highConfidenceOtp) {
                return Decision.quarantined("campaign_lock_global_otp_limit", escalation, panicMode, cluster, messageHash, campaignId);
            }

            if (!trustedSender && !userRequestedOtp && riskScore >= LOCKDOWN_SCORE + 1 && !highConfidenceOtp) {
                return Decision.quarantined("otp_primary_high_risk", escalation, panicMode, cluster, messageHash, campaignId);
            }

            group.allowedCount = 1;
            group.primaryScore = priorityScore;
            group.primarySelectedAtMs = nowMs;
            group.primarySender = sender;
            registerAllowedOtp(userRequestedOtp, campaignLockMode, serviceIdentity, nowMs);
            return Decision.allowed("otp_primary_selected", escalation, panicMode, cluster, messageHash, campaignId);
        }

        boolean sameSenderAsPrimary = senderMatches(sender, group.primarySender);
        boolean betterCandidate = priorityScore >= group.primaryScore + PRIMARY_OTP_UPGRADE_MARGIN;
        boolean withinProtectedLateWindow = group.primarySelectedAtMs > 0L
            && (nowMs - group.primarySelectedAtMs) <= PROTECTED_LATE_OVERRIDE_WINDOW_MS;
        boolean protectedLateOverride = betterCandidate && highConfidenceOtp && withinProtectedLateWindow;

        if (campaignLockMode && usedCampaignAllowance >= 1 && !protectedLateOverride) {
            return Decision.quarantined("campaign_lock_global_otp_limit", escalation, panicMode, cluster, messageHash, campaignId);
        }

        // Protected late override works even under campaign lock when confidence is very high.
        if (protectedLateOverride && group.overrideCount < MAX_OTP_OVERRIDE_ALLOWANCES_PER_GROUP) {
            String previousPrimarySender = group.primarySender;
            group.overrideCount += 1;
            group.allowedCount += 1;
            group.primaryScore = priorityScore;
            group.primarySelectedAtMs = nowMs;
            group.primarySender = sender;
            registerAllowedOtp(userRequestedOtp, false, serviceIdentity, nowMs);
            removePriorPrimaryOtpFromInbox(context, previousPrimarySender, messageHash, nowMs);
            return Decision.allowed("otp_primary_override_protected", escalation, panicMode, cluster, messageHash, campaignId);
        }

        // Standard late better OTP override outside protected lock handling.
        if (betterCandidate && group.overrideCount < MAX_OTP_OVERRIDE_ALLOWANCES_PER_GROUP) {
            String previousPrimarySender = group.primarySender;
            group.overrideCount += 1;
            group.allowedCount += 1;
            group.primaryScore = priorityScore;
            group.primarySelectedAtMs = nowMs;
            group.primarySender = sender;
            registerAllowedOtp(userRequestedOtp, false, serviceIdentity, nowMs);
            removePriorPrimaryOtpFromInbox(context, previousPrimarySender, messageHash, nowMs);
            return Decision.allowed("otp_primary_override_late", escalation, panicMode, cluster, messageHash, campaignId);
        }

        if (userRequestedOtp && group.allowedCount < intentMax && (sameSenderAsPrimary || betterCandidate)) {
            group.allowedCount += 1;
            if (betterCandidate) {
                group.primaryScore = priorityScore;
                group.primarySelectedAtMs = nowMs;
                group.primarySender = sender;
            }
            registerAllowedOtp(true, false, serviceIdentity, nowMs);
            return Decision.allowed(
                sameSenderAsPrimary ? "otp_resend_same_sender" : "otp_primary_upgrade",
                escalation,
                panicMode,
                cluster,
                messageHash,
                campaignId
            );
        }

        return Decision.quarantined("otp_non_primary_quarantine", escalation, panicMode, cluster, messageHash, campaignId);
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

    private static EscalationLevel applyAttackCooldown(Context context, EscalationLevel escalation, long nowMs) {
        if (escalation == EscalationLevel.ATTACK || escalation == EscalationLevel.LOCKDOWN) {
            long untilMs = nowMs + SettingsStore.getAttackCooldownMs(context);
            attackCooldownUntilMs = Math.max(attackCooldownUntilMs, untilMs);
            return escalation;
        }

        if (nowMs < attackCooldownUntilMs && escalation.ordinal() < EscalationLevel.ATTACK.ordinal()) {
            return EscalationLevel.ATTACK;
        }
        return escalation;
    }

    private static EscalationLevel maxEscalation(EscalationLevel left, EscalationLevel right) {
        return left.ordinal() >= right.ordinal() ? left : right;
    }

    private static int computeOtpPriorityScore(boolean trustedSender, boolean trustedByKnownService,
                                               boolean hasDomain, int seenInGroup,
                                               int templateCount120, double entropyRatio,
                                               int riskScore, int trustScore, int confidenceScore) {
        int score = 0;
        if (trustedSender) {
            score += 40;
        }
        if (trustedByKnownService) {
            score += 30;
        }
        if (hasDomain) {
            score += 30;
        }
        if (seenInGroup == 1) {
            score += 4;
        }

        if (entropyRatio > 0.70d) {
            score -= 30;
        }
        if (templateCount120 >= 5) {
            score -= 25;
        } else if (templateCount120 >= 3) {
            score -= 12;
        }
        if (riskScore >= ATTACK_SCORE) {
            score -= 20;
        }

        score += trustScore / 6;
        score += confidenceScore / 12;
        return score;
    }

    private static boolean isHighConfidenceOtp(int priorityScore, int trustScore,
                                               int riskScore, int confidenceScore) {
        return priorityScore >= HIGH_CONFIDENCE_PRIORITY_SCORE
            || (trustScore >= 55 && riskScore <= ATTACK_SCORE)
            || confidenceScore >= 35;
    }

    private static void trimOtpSelectionState(long nowMs) {
        trim(allowedOtpGlobal120, nowMs, OTP_SELECTION_WINDOW_MS);
        trim(campaignLockAllowedOtp120, nowMs, OTP_SELECTION_WINDOW_MS);

        ArrayList<String> emptyIntentServices = new ArrayList<>();
        for (Map.Entry<String, Deque<Long>> entry : intentOtpAllowances120ByService.entrySet()) {
            trim(entry.getValue(), nowMs, OTP_SELECTION_WINDOW_MS);
            if (entry.getValue().isEmpty()) {
                emptyIntentServices.add(entry.getKey());
            }
        }
        for (String key : emptyIntentServices) {
            intentOtpAllowances120ByService.remove(key);
        }

        ArrayList<String> expired = new ArrayList<>();
        for (Map.Entry<String, OtpGroupState> entry : otpGroups.entrySet()) {
            if (nowMs - entry.getValue().lastSeenMs > OTP_SELECTION_WINDOW_MS) {
                expired.add(entry.getKey());
            }
        }
        for (String key : expired) {
            otpGroups.remove(key);
        }
    }

    private static int countRecent(Deque<Long> queue, long nowMs, long windowMs) {
        trim(queue, nowMs, windowMs);
        return queue.size();
    }

    private static void registerAllowedOtp(boolean fromIntentWindow, boolean fromCampaignLock,
                                           String serviceIdentity, long nowMs) {
        allowedOtpGlobal120.addLast(nowMs);
        trim(allowedOtpGlobal120, nowMs, OTP_SELECTION_WINDOW_MS);

        if (fromIntentWindow) {
            Deque<Long> queue = intentOtpAllowances120ByService
                .computeIfAbsent(serviceIdentity, key -> new ArrayDeque<>());
            queue.addLast(nowMs);
            trim(queue, nowMs, OTP_SELECTION_WINDOW_MS);
        }

        if (fromCampaignLock) {
            campaignLockAllowedOtp120.addLast(nowMs);
            trim(campaignLockAllowedOtp120, nowMs, OTP_SELECTION_WINDOW_MS);
        }
    }

    private static int computeRiskScore(int globalCount60, int globalCount120, int clusterCount120,
                                        int templateCount120, int templateUniqueSenders,
                                        EntropySnapshot entropy, double entropyRatio,
                                        boolean enterpriseSender, boolean hasOtpToken,
                                        boolean hasDomain, int reputationRisk) {
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
        if (entropy.totalEvents > 5 && entropyRatio > 0.70d) {
            score += 2;
        }

        if (enterpriseSender && hasOtpToken) {
            score += 1;
        }
        if (hasOtpToken && !hasDomain) {
            score += 1;
        }
        return score;
    }

    private static int computeTrustScore(boolean trustedByWhitelist, boolean trustedByLearned,
                                         boolean trustedByContact, boolean trustedByKnownService,
                                         boolean userRequestedOtp, boolean hasDomain,
                                         boolean hasOtpToken, int globalCount60,
                                         int templateCount120, int clusterCount120,
                                         double entropyRatio, int reputationRisk,
                                         int senderSuccessCount, int senderRecentCount,
                                         boolean behavioralTrustPromotion) {
        int score = 0;

        if (trustedByWhitelist) {
            score += 45;
        }
        if (trustedByLearned) {
            score += 35;
        }
        if (trustedByContact) {
            score += 30;
        }
        if (trustedByKnownService) {
            score += 25;
        }
        if (userRequestedOtp) {
            score += 35;
        }
        if (hasDomain) {
            score += 10;
        }
        if (hasOtpToken && globalCount60 <= 2) {
            score += 8;
        }
        if (senderSuccessCount >= 1 && senderRecentCount <= 2) {
            score += 6;
        }
        if (behavioralTrustPromotion) {
            score += 20;
        }

        if (templateCount120 >= 5) {
            score -= 30;
        } else if (templateCount120 >= 3) {
            score -= 15;
        }

        if (clusterCount120 >= CLUSTER_ATTACK_120S) {
            score -= 25;
        } else if (clusterCount120 >= CLUSTER_SUSPICIOUS_60S) {
            score -= 12;
        }

        if (entropyRatio > 0.70d) {
            score -= 20;
        }
        if (reputationRisk >= 2) {
            score -= 15;
        }
        return score;
    }

    private static boolean containsOtpToken(String body) {
        Matcher matcher = OTP_TOKEN_PATTERN.matcher(body);
        return matcher.find();
    }

    private static boolean containsDomain(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        Matcher matcher = DOMAIN_PATTERN.matcher(body);
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

    private static boolean isKnownServiceSender(String sender, String cluster) {
        return !extractKnownServiceToken(sender, cluster).isEmpty();
    }

    private static String resolveServiceIdentity(String body, String sender, String cluster) {
        String domain = extractDomain(body);
        if (!domain.isEmpty()) {
            return domain;
        }

        String token = extractKnownServiceToken(sender, cluster);
        if (!token.isEmpty()) {
            return token.toLowerCase(Locale.US);
        }

        String normalizedCluster = normalizeSenderToken(cluster);
        if (!normalizedCluster.isEmpty()) {
            return normalizedCluster.toLowerCase(Locale.US);
        }

        String normalizedSender = normalizeSenderToken(sender);
        if (!normalizedSender.isEmpty()) {
            return normalizedSender.toLowerCase(Locale.US);
        }

        return "unknown";
    }

    private static String buildOtpGroupKey(String messageHash, String serviceIdentity,
                                           String simContext) {
        return simContext + "::" + serviceIdentity + "::" + messageHash;
    }

    private static String extractDomain(String body) {
        if (body == null || body.isEmpty()) {
            return "";
        }
        Matcher matcher = URL_DOMAIN_CAPTURE_PATTERN.matcher(body);
        if (!matcher.find()) {
            return "";
        }

        String rawDomain = matcher.group(1);
        if (rawDomain == null) {
            return "";
        }

        String normalized = rawDomain.toLowerCase(Locale.US);
        if (normalized.startsWith("www.")) {
            normalized = normalized.substring(4);
        }
        return normalized;
    }

    private static String extractKnownServiceToken(String sender, String cluster) {
        String normalizedSender = normalizeSenderToken(sender);
        String normalizedCluster = normalizeSenderToken(cluster);
        for (String token : TRUSTED_SERVICE_TOKENS) {
            if (normalizedSender.contains(token) || normalizedCluster.contains(token)) {
                return token;
            }
        }
        return "";
    }

    private static String normalizeSenderToken(String value) {
        if (value == null) {
            return "";
        }
        return value.toUpperCase(Locale.US).replaceAll("[^A-Z0-9]", "");
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

    private static String buildCampaignId(String messageHash, String serviceIdentity,
                                          String simContext, long nowMs) {
        long windowBucket = nowMs / WINDOW_120S_MS;
        return messageHash + "_" + serviceIdentity + "_" + simContext + "_" + Long.toString(windowBucket, 36);
    }

    private static String sanitizeSimContext(String simContext) {
        if (simContext == null) {
            return "sim_unknown";
        }
        String normalized = simContext.trim().toLowerCase(Locale.US);
        if (normalized.isEmpty()) {
            return "sim_unknown";
        }
        return normalized.replaceAll("[^a-z0-9_:-]", "_");
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
            int count = frequencies.getOrDefault(event.sender, 0);
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

    private static int senderRecentFrequency(String sender, long nowMs) {
        if (sender == null || sender.isEmpty()) {
            return 0;
        }

        trimSenderEvents(senderEvents120, nowMs, WINDOW_120S_MS);
        int count = 0;
        for (SenderEvent event : senderEvents120) {
            if (senderMatches(sender, event.sender)) {
                count += 1;
            }
        }
        return count;
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

    private static void removePriorPrimaryOtpFromInbox(Context context, String previousSender,
                                                       String expectedMessageHash, long nowMs) {
        if (previousSender == null || previousSender.trim().isEmpty()) {
            return;
        }

        long sinceMs = nowMs - OTP_SELECTION_WINDOW_MS;
        String[] projection = new String[]{
            Telephony.Sms._ID,
            Telephony.Sms.ADDRESS,
            Telephony.Sms.BODY,
            Telephony.Sms.DATE
        };

        String selection = Telephony.Sms.DATE + " >= ?";
        String[] args = new String[]{Long.toString(sinceMs)};

        try (android.database.Cursor cursor = context.getContentResolver().query(
            Telephony.Sms.Inbox.CONTENT_URI,
            projection,
            selection,
            args,
            Telephony.Sms.DATE + " DESC"
        )) {
            if (cursor == null) {
                return;
            }

            int idIndex = cursor.getColumnIndex(Telephony.Sms._ID);
            int addressIndex = cursor.getColumnIndex(Telephony.Sms.ADDRESS);
            int bodyIndex = cursor.getColumnIndex(Telephony.Sms.BODY);
            if (idIndex < 0 || addressIndex < 0 || bodyIndex < 0) {
                return;
            }

            while (cursor.moveToNext()) {
                String address = cursor.getString(addressIndex);
                if (!senderMatches(previousSender, address)) {
                    continue;
                }

                String body = cursor.getString(bodyIndex);
                String rowHash = messageHash(body == null ? "" : body);
                if (!expectedMessageHash.equals(rowHash)) {
                    continue;
                }

                long id = cursor.getLong(idIndex);
                android.net.Uri uri = android.content.ContentUris.withAppendedId(Telephony.Sms.CONTENT_URI, id);
                context.getContentResolver().delete(uri, null, null);
                return;
            }
        } catch (Exception ignored) {
        }
    }

    private static boolean isWhitelisted(Context context, String sender) {
        Set<String> white = SettingsStore.getWhitelist(context);
        for (String w : white) {
            if (senderMatches(sender, w)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isLearnedTrustedSender(Context context, String sender) {
        Set<String> learned = SettingsStore.getLearnedTrustedSenders(context);
        for (String trustedSender : learned) {
            if (senderMatches(sender, trustedSender)) {
                return true;
            }
        }
        return false;
    }

    private static boolean senderMatches(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        return PhoneNumberUtils.compare(left, right) || left.equalsIgnoreCase(right);
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
