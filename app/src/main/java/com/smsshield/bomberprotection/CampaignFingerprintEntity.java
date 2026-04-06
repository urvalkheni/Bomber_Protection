package com.smsshield.bomberprotection;

import androidx.annotation.NonNull;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "campaign_fingerprint")
public class CampaignFingerprintEntity {
    @PrimaryKey
    @NonNull
    public String campaignId;

    @NonNull
    public String templateHash;

    @NonNull
    public String topCluster;

    @NonNull
    public String highestEscalation;

    public long firstSeenMs;
    public long lastSeenMs;
    public long totalCount;
    public long uniqueSenderCount;

    public CampaignFingerprintEntity(@NonNull String campaignId, @NonNull String templateHash,
                                     @NonNull String topCluster, @NonNull String highestEscalation,
                                     long firstSeenMs, long lastSeenMs,
                                     long totalCount, long uniqueSenderCount) {
        this.campaignId = campaignId;
        this.templateHash = templateHash;
        this.topCluster = topCluster;
        this.highestEscalation = highestEscalation;
        this.firstSeenMs = firstSeenMs;
        this.lastSeenMs = lastSeenMs;
        this.totalCount = totalCount;
        this.uniqueSenderCount = uniqueSenderCount;
    }
}
