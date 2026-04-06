package com.smsshield.bomberprotection;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

@Dao
public interface CampaignFingerprintDao {
    @Query("SELECT * FROM campaign_fingerprint WHERE campaignId = :campaignId LIMIT 1")
    CampaignFingerprintEntity byCampaignId(String campaignId);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void upsert(CampaignFingerprintEntity entity);
}
