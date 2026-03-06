package com.smsshield.bomberprotection;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class AttackLogActivity extends AppCompatActivity {
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_logs);

        ListView listView = findViewById(R.id.listLogs);
        Button exportCsv = findViewById(R.id.buttonExportCsv);
        Button exportJson = findViewById(R.id.buttonExportJson);

        exportCsv.setOnClickListener(v -> {
            try {
                java.io.File file = AttackLogStore.exportCsv(this);
                Toast.makeText(this, getString(R.string.export_ok, file.getAbsolutePath()), Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.export_fail, e.getMessage()), Toast.LENGTH_LONG).show();
            }
        });

        exportJson.setOnClickListener(v -> {
            try {
                java.io.File file = AttackLogStore.exportJson(this);
                Toast.makeText(this, getString(R.string.export_ok, file.getAbsolutePath()), Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.export_fail, e.getMessage()), Toast.LENGTH_LONG).show();
            }
        });

        List<AttackLogStore.LogItem> items = AttackLogStore.getLogs(this);
        List<String> rows = new ArrayList<>();
        for (AttackLogStore.LogItem item : items) {
            String when = DateFormat.format("dd MMM HH:mm:ss", new Date(item.timestamp)).toString();
            rows.add("[" + item.action + "] " + item.sender + "\n"
                + item.reason + " | escalation=" + item.escalation + " | cluster=" + item.cluster + "\n"
                + when + "\n"
                + item.body);
        }

        if (rows.isEmpty()) {
            rows.add(getString(R.string.no_logs));
        }

        ArrayAdapter<String> adapter = new ArrayAdapter<>(
            this,
            android.R.layout.simple_list_item_1,
            rows
        );
        listView.setAdapter(adapter);
    }
}
