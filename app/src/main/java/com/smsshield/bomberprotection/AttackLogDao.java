package com.smsshield.bomberprotection;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.Query;

import java.util.List;

@Dao
public interface AttackLogDao {
    @Insert
    long insert(AttackLogEntity entity);

    @Query("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT :limit")
    List<AttackLogEntity> recent(int limit);

    @Query("DELETE FROM attack_logs WHERE id NOT IN (SELECT id FROM attack_logs ORDER BY timestamp DESC LIMIT :keep)")
    void trimTo(int keep);

    @Query("SELECT COUNT(*) FROM attack_logs WHERE timestamp >= :since AND action = :action")
    int countByActionSince(long since, String action);

    @Query("SELECT COUNT(DISTINCT sender) FROM attack_logs WHERE timestamp >= :since AND action IN ('BLOCKED', 'SUPPRESSED')")
    int uniqueAttackersSince(long since);

    @Query("SELECT * FROM attack_logs ORDER BY timestamp DESC")
    List<AttackLogEntity> all();
}
