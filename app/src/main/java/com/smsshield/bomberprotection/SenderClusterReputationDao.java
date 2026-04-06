package com.smsshield.bomberprotection;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

@Dao
public interface SenderClusterReputationDao {
    @Query("SELECT * FROM sender_cluster_reputation WHERE cluster = :cluster LIMIT 1")
    SenderClusterReputationEntity byCluster(String cluster);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void upsert(SenderClusterReputationEntity entity);
}
