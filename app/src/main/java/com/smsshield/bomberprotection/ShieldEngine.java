package com.smsshield.bomberprotection;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.provider.ContactsContract;
import android.telephony.PhoneNumberUtils;

import androidx.core.content.ContextCompat;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class ShieldEngine {
    private static final int PER_SENDER_LIMIT = 5;
    private static final long PER_SENDER_WINDOW_MS = 60_000L;

    private static final int GLOBAL_LIMIT = 20;
    private static final long GLOBAL_WINDOW_MS = 30_000L;

    private static final Set<String> SUSPICIOUS_PREFIXES = new HashSet<>();

    static {
        SUSPICIOUS_PREFIXES.add("VK");
        SUSPICIOUS_PREFIXES.add("AD");
        SUSPICIOUS_PREFIXES.add("JD");
    }

    private static final Map<String, Deque<Long>> senderBuckets = new HashMap<>();
    private static final Deque<Long> globalBucket = new ArrayDeque<>();

    private ShieldEngine() {
    }

    public static final class Decision {
        public final boolean block;
        public final boolean silence;
        public final String reason;

        public Decision(boolean block, boolean silence, String reason) {
            this.block = block;
            this.silence = silence;
            this.reason = reason;
        }

        public static Decision allow() {
            return new Decision(false, false, "allowed");
        }

        public static Decision block(String reason) {
            return new Decision(true, false, reason);
        }

        public static Decision silence(String reason) {
            return new Decision(false, true, reason);
        }
    }

    public static synchronized Decision evaluate(Context context, String sender, String body, long nowMs) {
        if (!SettingsStore.isShieldOn(context)) {
            return Decision.allow();
        }

        String safeSender = sender == null ? "" : sender.trim();
        String safeBody = body == null ? "" : body.trim();

        if (SettingsStore.isContactsOnly(context)
            && !isWhitelisted(context, safeSender)
            && !isContact(context, safeSender)) {
            return Decision.block("contacts-only mode");
        }

        if (isWhitelisted(context, safeSender)) {
            return Decision.allow();
        }

        trim(globalBucket, nowMs, GLOBAL_WINDOW_MS);
        globalBucket.addLast(nowMs);
        if (globalBucket.size() > GLOBAL_LIMIT) {
            return Decision.block("global flood >20 in 30s");
        }

        Deque<Long> senderQueue = senderBuckets.computeIfAbsent(safeSender, key -> new ArrayDeque<>());
        trim(senderQueue, nowMs, PER_SENDER_WINDOW_MS);
        senderQueue.addLast(nowMs);

        if (senderQueue.size() > PER_SENDER_LIMIT) {
            return Decision.block("sender flood >5 in 60s");
        }

        if (isSuspiciousPrefix(safeSender) && senderQueue.size() >= 3) {
            return Decision.silence("suspicious sender pattern");
        }

        if (containsOtpKeywords(safeBody) && senderQueue.size() >= 3) {
            return Decision.block("otp-like spam burst");
        }

        return Decision.allow();
    }

    private static void trim(Deque<Long> queue, long nowMs, long windowMs) {
        while (!queue.isEmpty() && nowMs - queue.peekFirst() > windowMs) {
            queue.removeFirst();
        }
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

    private static boolean isSuspiciousPrefix(String sender) {
        String upper = sender.toUpperCase(Locale.US);
        for (String prefix : SUSPICIOUS_PREFIXES) {
            if (upper.startsWith(prefix + "-") || upper.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsOtpKeywords(String body) {
        String lower = body.toLowerCase(Locale.US);
        List<String> keywords = new ArrayList<>();
        keywords.add("otp");
        keywords.add("verification code");
        keywords.add("login code");
        keywords.add("one time password");
        for (String keyword : keywords) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }
}
