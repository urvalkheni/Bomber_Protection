package com.smsshield.bomberprotection;

import android.content.Context;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

@Database(entities = {AttackLogEntity.class}, version = 1, exportSchema = false)
public abstract class ShieldDatabase extends RoomDatabase {
    private static volatile ShieldDatabase instance;

    public abstract AttackLogDao attackLogDao();

    public static ShieldDatabase get(Context context) {
        if (instance == null) {
            synchronized (ShieldDatabase.class) {
                if (instance == null) {
                    instance = Room.databaseBuilder(
                        context.getApplicationContext(),
                        ShieldDatabase.class,
                        "shield.db"
                    ).allowMainThreadQueries().build();
                }
            }
        }
        return instance;
    }
}
