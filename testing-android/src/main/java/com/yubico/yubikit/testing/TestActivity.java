package com.yubico.yubikit.testing;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.yubico.yubikit.android.YubiKitManager;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable;
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.YubiKeyDevice;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Semaphore;

public class TestActivity extends AppCompatActivity {

    private TextView testNameText;
    private TextView statusText;
    private TextView bottomText;
    private ProgressBar progressBar;

    private YubiKitManager yubiKitManager;

    private final BlockingQueue<YubiKeyDevice> sessionQueue = new ArrayBlockingQueue<>(1);
    private final Semaphore lock = new Semaphore(0);

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.test_activity);

        testNameText = findViewById(R.id.testNameText);
        statusText = findViewById(R.id.statusText);
        bottomText = findViewById(R.id.bottomText);
        progressBar = findViewById(R.id.progressBar);

        yubiKitManager = new YubiKitManager(this);

        Logger.setLogger(new Logger() {
            @Override
            protected void logDebug(@NonNull String message) {
                Log.d("yubikit.test", message);
            }

            @Override
            protected void logError(@NonNull String message, @NonNull Throwable throwable) {
                Log.e("yubikit.test", message, throwable);
            }
        });

        yubiKitManager.startUsbDiscovery(new UsbConfiguration(), device -> {
            bottomText.setVisibility(View.VISIBLE);
            bottomText.setText(R.string.touch);
            setBusy(true);
            sessionQueue.add(device);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        try {
            yubiKitManager.startNfcDiscovery(new NfcConfiguration(), this, (session) -> {
                setBusy(true);
                sessionQueue.add(session);
            });
        } catch (NfcNotAvailable e) {
            if (e.isDisabled()) {
                Log.e("test", "NFC is disabled", e);
            } else {
                Log.e("test", "NFC is not supported", e);
            }
        }
    }

    @Override
    protected void onPause() {
        yubiKitManager.stopNfcDiscovery(this);
        super.onPause();
    }

    private void setBusy(boolean busy) {
        runOnUiThread(() -> {
            if (busy) {
                progressBar.setVisibility(View.VISIBLE);
            } else {
                progressBar.setVisibility(View.INVISIBLE);
            }
        });
    }

    public synchronized YubiKeyDevice awaitSession(String name) throws InterruptedException {
        YubiKeyDevice device = sessionQueue.peek();

        runOnUiThread(() -> {
            testNameText.setText(name);
            if (device instanceof UsbYubiKeyDevice) {
                statusText.setText(R.string.processing);
            } else {
                statusText.setText(R.string.tap_yubikey);
            }
        });

        return sessionQueue.take();

    }

    public synchronized void returnSession(YubiKeyDevice device) throws InterruptedException {
        runOnUiThread(() -> {
            if (device instanceof UsbYubiKeyDevice) {
                statusText.setText(R.string.processing);
            } else {
                statusText.setText(R.string.remove_yubikey);
            }
            setBusy(false);
        });
        if (device instanceof NfcYubiKeyDevice) {
            ((NfcYubiKeyDevice) device).remove(lock::release);
            lock.acquire();
        }
    }
}
