package com.smsshield.bomberprotection;

import android.content.Context;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;
import androidx.room.migration.Migration;
import androidx.sqlite.db.SupportSQLiteDatabase;

@Database(
    entities = {
        AttackLogEntity.class,
        SenderClusterReputationEntity.class,
        CampaignFingerprintEntity.class
    },
    version = 2,
    exportSchema = false
)
public abstract class ShieldDatabase extends RoomDatabase {
    private static volatile ShieldDatabase instance;

    private static final Migration MIGRATION_1_2 = new Migration(1, 2) {
        @Override
        public void migrate(SupportSQLiteDatabase db) {
            db.execSQL("ALTER TABLE attack_logs ADD COLUMN campaignId TEXT NOT NULL DEFAULT ''");
            db.execSQL("CREATE TABLE IF NOT EXISTS sender_cluster_reputation (cluster TEXT NOT NULL, totalCount INTEGER NOT NULL, blockedCount INTEGER NOT NULL, silencedCount INTEGER NOT NULL, quarantinedCount INTEGER NOT NULL, lastSeenMs INTEGER NOT NULL, PRIMARY KEY(cluster))");
            db.execSQL("CREATE TABLE IF NOT EXISTS campaign_fingerprint (campaignId TEXT NOT NULL, templateHash TEXT NOT NULL, topCluster TEXT NOT NULL, highestEscalation TEXT NOT NULL, firstSeenMs INTEGER NOT NULL, lastSeenMs INTEGER NOT NULL, totalCount INTEGER NOT NULL, uniqueSenderCount INTEGER NOT NULL, PRIMARY KEY(campaignId))");
        }
    };

    public abstract AttackLogDao attackLogDao();

    public abstract SenderClusterReputationDao senderClusterReputationDao();

    public abstract CampaignFingerprintDao campaignFingerprintDao();

    public static ShieldDatabase get(Context context) {
        if (instance == null) {
            synchronized (ShieldDatabase.class) {
                if (instance == null) {
                    instance = Room.databaseBuilder(
                        context.getApplicationContext(),
                        ShieldDatabase.class,
                        "shield.db"
                    ).addMigrations(MIGRATION_1_2)
                        .allowMainThreadQueries()
                        .build();
                }
            }
        }
        return instance;
    }
}
