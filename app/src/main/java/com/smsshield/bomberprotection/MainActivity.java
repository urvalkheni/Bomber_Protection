package com.smsshield.bomberprotection;

import android.Manifest;
import android.app.role.RoleManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Telephony;
import android.text.InputType;
import android.text.TextUtils;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
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
        Button expectOtpButton = findViewById(R.id.buttonExpectOtp);
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

        expectOtpButton.setOnClickListener(v -> showExpectOtpDialog());

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
        boolean isDefaultSmsApp = isDefaultSmsApp();
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
            stats.quarantinedToday,
            stats.attackersToday,
            ShieldEngine.getCurrentEscalation().name(),
            ShieldEngine.isPanicModeActive() ? getString(R.string.default_sms_yes) : getString(R.string.default_sms_no),
            defaultStatus,
            permissionStatus,
            formatOtpIntentStatus()
        );
        statsText.setText(summary);
    }

    private String formatOtpIntentStatus() {
        long remainingMs = SettingsStore.getExpectOtpRemainingMs(this, System.currentTimeMillis());
        if (remainingMs <= 0L) {
            return getString(R.string.otp_window_inactive);
        }

        long seconds = Math.max(1L, remainingMs / 1000L);
        return getString(R.string.otp_window_active, seconds);
    }

    private void showExpectOtpDialog() {
        EditText serviceInput = new EditText(this);
        serviceInput.setHint(R.string.expect_otp_service_hint);
        serviceInput.setInputType(InputType.TYPE_CLASS_TEXT);
        serviceInput.setLayoutParams(new ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        new AlertDialog.Builder(this)
            .setTitle(R.string.expect_otp_dialog_title)
            .setMessage(R.string.expect_otp_dialog_message)
            .setView(serviceInput)
            .setNeutralButton(R.string.expect_otp_any_service, (dialog, which) -> {
                SettingsStore.startExpectOtpWindow(this);
                Toast.makeText(this, R.string.expect_otp_started, Toast.LENGTH_SHORT).show();
                refreshStats();
            })
            .setPositiveButton(R.string.expect_otp_start_service, (dialog, which) -> {
                String serviceKey = serviceInput.getText() == null
                    ? ""
                    : serviceInput.getText().toString().trim();

                if (TextUtils.isEmpty(serviceKey)) {
                    SettingsStore.startExpectOtpWindow(this);
                    Toast.makeText(this, R.string.expect_otp_started, Toast.LENGTH_SHORT).show();
                } else {
                    SettingsStore.startExpectOtpWindowForService(this, serviceKey);
                    Toast.makeText(this, getString(R.string.expect_otp_started_for_service, serviceKey), Toast.LENGTH_SHORT).show();
                }
                refreshStats();
            })
            .setNegativeButton(android.R.string.cancel, null)
            .show();
    }

    /**
     * Check if this app is the default SMS handler.
     * On API 29+ (Android 10+) the authoritative check is RoleManager.isRoleHeld().
     * HyperOS/MIUI can return incorrect package names from getDefaultSmsPackage(),
     * so we use the RoleManager path whenever available.
     */
    private boolean isDefaultSmsApp() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            RoleManager roleManager = getSystemService(RoleManager.class);
            return roleManager != null && roleManager.isRoleHeld(RoleManager.ROLE_SMS);
        }
        return getPackageName().equals(Telephony.Sms.getDefaultSmsPackage(this));
    }
}
