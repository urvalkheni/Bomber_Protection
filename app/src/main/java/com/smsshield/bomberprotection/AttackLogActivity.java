package com.smsshield.bomberprotection;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class AttackLogActivity extends AppCompatActivity {
    private List<AttackLogStore.LogItem> items;
    private int summaryRowsCount;

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

        items = AttackLogStore.getLogs(this);
        List<AttackLogStore.QuarantineGroup> groups = AttackLogStore.getQuarantineOtpGroups(this);
        List<String> rows = new ArrayList<>();

        for (AttackLogStore.QuarantineGroup group : groups) {
            String when = DateFormat.format("dd MMM HH:mm:ss", new Date(group.latestTimestamp)).toString();
            rows.add(getString(R.string.quarantine_group_row, group.serviceIdentity, group.count) + "\n"
                + getString(R.string.quarantine_group_latest, when));
        }
        summaryRowsCount = rows.size();

        for (AttackLogStore.LogItem item : items) {
            String when = DateFormat.format("dd MMM HH:mm:ss", new Date(item.timestamp)).toString();
            rows.add("[" + item.action + "] " + item.sender + "\n"
            + item.reason + " | escalation=" + item.escalation + " | cluster=" + item.cluster + "\n"
            + "hash=" + item.messageHash + " | campaign=" + item.campaignId + "\n"
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

        listView.setOnItemLongClickListener((parent, view, position, id) -> {
            if (position < summaryRowsCount) {
                return true;
            }

            int detailIndex = position - summaryRowsCount;
            if (detailIndex < 0 || detailIndex >= items.size()) {
                return true;
            }

            AttackLogStore.LogItem item = items.get(detailIndex);
            String[] options = new String[]{
                getString(R.string.restore_message),
                getString(R.string.mark_sender_trusted)
            };

            new AlertDialog.Builder(this)
                .setTitle(getString(R.string.log_action_title, item.sender))
                .setItems(options, (dialog, which) -> {
                    if (which == 0) {
                        if (!"QUARANTINED".equals(item.action)) {
                            Toast.makeText(this, R.string.restore_only_quarantined, Toast.LENGTH_SHORT).show();
                            return;
                        }

                        boolean ok = AttackLogStore.restoreQuarantined(this, item.id);
                        if (ok) {
                            Toast.makeText(this, R.string.restore_ok, Toast.LENGTH_SHORT).show();
                            recreate();
                        } else {
                            Toast.makeText(this, R.string.restore_fail, Toast.LENGTH_SHORT).show();
                        }
                        return;
                    }

                    SettingsStore.addLearnedTrustedSender(this, item.sender);
                    Toast.makeText(this, R.string.sender_trusted_ok, Toast.LENGTH_SHORT).show();
                })
                .show();
            return true;
        });
    }
}
