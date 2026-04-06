package com.smsshield.bomberprotection;

import androidx.annotation.NonNull;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "sender_cluster_reputation")
public class SenderClusterReputationEntity {
    @PrimaryKey
    @NonNull
    public String cluster;

    public long totalCount;
    public long blockedCount;
    public long silencedCount;
    public long quarantinedCount;
    public long lastSeenMs;

    public SenderClusterReputationEntity(@NonNull String cluster, long totalCount, long blockedCount,
                                         long silencedCount, long quarantinedCount, long lastSeenMs) {
        this.cluster = cluster;
        this.totalCount = totalCount;
        this.blockedCount = blockedCount;
        this.silencedCount = silencedCount;
        this.quarantinedCount = quarantinedCount;
        this.lastSeenMs = lastSeenMs;
    }
}
