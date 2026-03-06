package com.smsshield.bomberprotection;

import android.os.Bundle;
import android.text.TextUtils;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class WhitelistActivity extends AppCompatActivity {
    private ArrayAdapter<String> adapter;
    private List<String> data;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_whitelist);

        EditText numberInput = findViewById(R.id.inputNumber);
        Button addButton = findViewById(R.id.buttonAdd);
        ListView listView = findViewById(R.id.listWhitelist);

        data = new ArrayList<>(SettingsStore.getWhitelist(this));
        Collections.sort(data);
        adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, data);
        listView.setAdapter(adapter);

        addButton.setOnClickListener(v -> {
            String number = numberInput.getText().toString().trim();
            if (TextUtils.isEmpty(number)) {
                Toast.makeText(this, R.string.enter_number, Toast.LENGTH_SHORT).show();
                return;
            }
            SettingsStore.addWhitelist(this, number);
            numberInput.setText("");
            reload();
        });

        listView.setOnItemLongClickListener((parent, view, position, id) -> {
            String number = data.get(position);
            SettingsStore.removeWhitelist(this, number);
            reload();
            return true;
        });
    }

    private void reload() {
        data.clear();
        data.addAll(SettingsStore.getWhitelist(this));
        Collections.sort(data);
        adapter.notifyDataSetChanged();
    }
}
