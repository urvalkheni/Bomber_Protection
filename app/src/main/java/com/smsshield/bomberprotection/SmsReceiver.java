package com.smsshield.bomberprotection;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;

public class SmsReceiver extends BroadcastReceiver {
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

        ShieldEngine.Decision decision = ShieldEngine.evaluate(context, sender, body, System.currentTimeMillis());
        if (decision.block) {
            abortBroadcast();
            setResultCode(0);
            AttackLogStore.addLog(context, sender, body, "BLOCKED", decision.reason);
            return;
        }

        if (decision.silence) {
            abortBroadcast();
            setResultCode(0);
            AttackLogStore.addLog(context, sender, body, "SILENCED", decision.reason);
            return;
        }

        AttackLogStore.addLog(context, sender, body, "ALLOWED", decision.reason);
    }
}
