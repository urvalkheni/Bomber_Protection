package com.smsshield.bomberprotection;

import android.Manifest;
import android.app.role.RoleManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Telephony;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

public class MainActivity extends AppCompatActivity {
    private Switch shieldSwitch;
    private Switch contactsOnlySwitch;
    private TextView statsText;

    private final ActivityResultLauncher<String[]> permissionLauncher =
        registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), result -> refreshStats());

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        shieldSwitch = findViewById(R.id.switchShield);
        contactsOnlySwitch = findViewById(R.id.switchContactsOnly);
        statsText = findViewById(R.id.textStats);
        Button logsButton = findViewById(R.id.buttonLogs);
        Button whitelistButton = findViewById(R.id.buttonWhitelist);

        shieldSwitch.setChecked(SettingsStore.isShieldOn(this));
        contactsOnlySwitch.setChecked(SettingsStore.isContactsOnly(this));

        shieldSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            SettingsStore.setShieldOn(this, isChecked);
            refreshStats();
        });

        contactsOnlySwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            SettingsStore.setContactsOnly(this, isChecked);
            refreshStats();
        });

        logsButton.setOnClickListener(v -> startActivity(new Intent(this, AttackLogActivity.class)));
        whitelistButton.setOnClickListener(v -> startActivity(new Intent(this, WhitelistActivity.class)));

        requestRuntimePermissions();
        requestDefaultSmsRole();
        refreshStats();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStats();
    }

    private void requestRuntimePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissionLauncher.launch(new String[]{
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.POST_NOTIFICATIONS
            });
            return;
        }

        permissionLauncher.launch(new String[]{
            Manifest.permission.READ_CONTACTS
        });
    }

    private void requestDefaultSmsRole() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            RoleManager roleManager = getSystemService(RoleManager.class);
            if (roleManager != null && !roleManager.isRoleHeld(RoleManager.ROLE_SMS)) {
                Intent intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_SMS);
                startActivity(intent);
            }
            return;
        }

        String defaultSmsPackage = Telephony.Sms.getDefaultSmsPackage(this);
        if (!getPackageName().equals(defaultSmsPackage)) {
            Intent intent = new Intent(Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT);
            intent.putExtra(Telephony.Sms.Intents.EXTRA_PACKAGE_NAME, getPackageName());
            startActivity(intent);
        }
    }

    private void refreshStats() {
        AttackLogStore.Stats stats = AttackLogStore.getStats(this);
        boolean isDefaultSmsApp = getPackageName().equals(Telephony.Sms.getDefaultSmsPackage(this));
        String defaultStatus = isDefaultSmsApp
            ? getString(R.string.default_sms_yes)
            : getString(R.string.default_sms_no);

        String permissionStatus = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS)
            == PackageManager.PERMISSION_GRANTED
            ? getString(R.string.permission_ok)
            : getString(R.string.permission_missing);

        String summary = getString(
            R.string.stats_template,
            stats.blockedToday,
            stats.silencedToday,
            stats.suppressedToday,
            stats.attackersToday,
            ShieldEngine.getCurrentEscalation().name(),
            ShieldEngine.isPanicModeActive() ? getString(R.string.default_sms_yes) : getString(R.string.default_sms_no),
            defaultStatus,
            permissionStatus
        );
        statsText.setText(summary);
    }
}
