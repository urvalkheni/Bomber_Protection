package com.smsshield.bomberprotection;

import androidx.annotation.NonNull;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "attack_logs")
public class AttackLogEntity {
    @PrimaryKey(autoGenerate = true)
    public long id;

    public long timestamp;

    @NonNull
    public String sender;

    @NonNull
    public String body;

    @NonNull
    public String action;

    @NonNull
    public String reason;

    @NonNull
    public String escalation;

    @NonNull
    public String cluster;

    @NonNull
    public String templateHash;

    public AttackLogEntity(long timestamp, @NonNull String sender, @NonNull String body,
                           @NonNull String action, @NonNull String reason,
                           @NonNull String escalation, @NonNull String cluster,
                           @NonNull String templateHash) {
        this.timestamp = timestamp;
        this.sender = sender;
        this.body = body;
        this.action = action;
        this.reason = reason;
        this.escalation = escalation;
        this.cluster = cluster;
        this.templateHash = templateHash;
    }
}
