/*
 * Copyright (C) 2022-2023 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.testing;

import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.yubico.yubikit.android.YubiKitManager;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable;
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.core.YubiKeyDevice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Semaphore;

public class TestActivity extends AppCompatActivity {

    private TextView testClassNameText;
    private TextView testMethodNameText;
    private TextView statusText;
    private TextView bottomText;
    private ProgressBar progressBar;

    private YubiKitManager yubiKitManager;

    private final BlockingQueue<YubiKeyDevice> sessionQueue = new ArrayBlockingQueue<>(1);
    private final Semaphore lock = new Semaphore(0);

    private final static Logger logger = LoggerFactory.getLogger(TestActivity.class);

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.test_activity);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        testClassNameText = findViewById(R.id.testClassNameText);
        testMethodNameText = findViewById(R.id.testMethodNameText);
        statusText = findViewById(R.id.statusText);
        bottomText = findViewById(R.id.bottomText);
        progressBar = findViewById(R.id.progressBar);

        yubiKitManager = new YubiKitManager(this);

        yubiKitManager.startUsbDiscovery(new UsbConfiguration(), device -> {
            bottomText.setVisibility(View.VISIBLE);
            bottomText.setText(R.string.touch);
            sessionQueue.add(device);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        try {
            yubiKitManager.startNfcDiscovery(new NfcConfiguration().timeout(15000), this, sessionQueue::add);
        } catch (NfcNotAvailable e) {
            if (e.isDisabled()) {
                logger.error("NFC is disabled", e);
            } else {
                logger.error("NFC is not supported", e);
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

    public synchronized YubiKeyDevice awaitSession(String testClassName, String testMethodName) throws InterruptedException {
        YubiKeyDevice device = sessionQueue.peek();

        runOnUiThread(() -> {
            testClassNameText.setText(testClassName);
            testMethodNameText.setText(testMethodName);
            if (device == null) {
                statusText.setText(R.string.connect_or_tap);
            }
        });

        YubiKeyDevice connectedDevice = sessionQueue.take();
        runOnUiThread(() -> {
            if (connectedDevice instanceof UsbYubiKeyDevice) {
                statusText.setText(R.string.processing);
            } else {
                statusText.setText(R.string.processing_hold);
            }
        });
        setBusy(true);
        return connectedDevice;
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
