package com.smsshield.bomberprotection;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SubscriptionManager;
import android.telephony.SmsMessage;

import java.util.regex.Pattern;

public class SmsReceiver extends BroadcastReceiver {
    private static final Pattern OTP_PATTERN = Pattern.compile("\\b\\d{4,8}\\b");

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_DELIVER_ACTION.equals(intent.getAction())) {
            return;
        }

        SmsMessage[] messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        if (messages == null || messages.length == 0) {
            return;
        }

        String sender = messages[0].getOriginatingAddress();
        StringBuilder bodyBuilder = new StringBuilder();
        for (SmsMessage sms : messages) {
            bodyBuilder.append(sms.getDisplayMessageBody());
        }
        String body = bodyBuilder.toString();
        String simContext = deriveSimContext(intent);

        ShieldEngine.Decision decision = ShieldEngine.evaluate(
            context,
            sender,
            body,
            simContext,
            System.currentTimeMillis()
        );
        if (decision.shouldSuppressDelivery()) {
            abortBroadcast();
            setResultCode(Activity.RESULT_CANCELED);
            SmsNotificationSuppressor.suppress(context);
            AttackLogStore.addLog(
                context,
                sender,
                body,
                decision.action.name(),
                decision.reason,
                decision.escalation.name(),
                decision.cluster,
                decision.messageHash,
                decision.campaignId
            );

            if (isOtpMessage(body)) {
                OtpFilterNotifier.notifyFilteredOtp(context);
            }
            return;
        }

        AttackLogStore.addLog(
            context,
            sender,
            body,
            decision.action.name(),
            decision.reason,
            decision.escalation.name(),
            decision.cluster,
            decision.messageHash,
            decision.campaignId
        );
    }

    private static boolean isOtpMessage(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        return OTP_PATTERN.matcher(body).find();
    }

    private static String deriveSimContext(Intent intent) {
        if (intent == null) {
            return "sim_unknown";
        }

        int subId = firstValidExtra(
            intent,
            SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX,
            "subscription",
            "subId"
        );
        int slot = firstValidExtra(
            intent,
            SubscriptionManager.EXTRA_SLOT_INDEX,
            "slot",
            "simSlot"
        );

        if (slot >= 0) {
            return "slot_" + slot;
        }
        if (subId != SubscriptionManager.INVALID_SUBSCRIPTION_ID && subId >= 0) {
            return "sub_" + subId;
        }
        return "sim_unknown";
    }

    private static int firstValidExtra(Intent intent, String... keys) {
        for (String key : keys) {
            if (key == null || key.isEmpty() || !intent.hasExtra(key)) {
                continue;
            }
            int value = intent.getIntExtra(key, Integer.MIN_VALUE);
            if (value != Integer.MIN_VALUE) {
                return value;
            }
        }
        return SubscriptionManager.INVALID_SUBSCRIPTION_ID;
    }
}
