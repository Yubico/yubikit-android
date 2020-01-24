/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.otp;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.snackbar.Snackbar;
import com.yubico.yubikit.YubiKitManager;
import com.yubico.yubikit.exceptions.NfcDisabledException;
import com.yubico.yubikit.exceptions.NfcNotFoundException;
import com.yubico.yubikit.transport.nfc.NfcDeviceManager;
import com.yubico.yubikit.transport.nfc.NfcSession;
import com.yubico.yubikit.transport.nfc.NfcSessionListener;
import com.yubico.yubikit.transport.usb.UsbSession;
import com.yubico.yubikit.transport.usb.UsbSessionListener;

/**
 * Modal dialog activity that listens for NFC and USB events from yubikeys
 * and provides message on what action is expected from user
 */
public class OtpActivity extends AppCompatActivity {

    public static final String EXTRA_OTP = "otp";
    public static final String EXTRA_ERROR = "error";
    public static final int DEFAULT_TAG_IGNORE_TIMEOUT_MS = 1000;

    private View contentView;
    private TextView textView;
    private YubiKitManager manager;
    private boolean hasNfc = true;
    private int usbSessionCounter = 0;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.yubikit_otp_activity);
        setFinishOnTouchOutside(false);
        contentView = findViewById(R.id.yubikit_otp_content_view);
        textView = findViewById(R.id.yubikit_otp_text_view);
        textView.setClickable(true);
        textView.setOnKeyListener(new KeyListener(new KeyListener.OtpListener() {
            @Override
            public void onOtpReceived(String otpCredential) {
                returnSuccess(otpCredential);
            }
        }));

        manager = new YubiKitManager(this);
        manager.startUsbDiscovery(false, new UsbSessionListener() {
            @Override
            public void onSessionReceived(@NonNull UsbSession session, boolean hasPermission) {
                usbSessionCounter++;
                textView.setText(R.string.yubikit_otp_touch);
            }

            @Override
            public void onSessionRemoved(@NonNull UsbSession session) {
                usbSessionCounter--;
                if (usbSessionCounter == 0) {
                    if (hasNfc) {
                        textView.setText(R.string.yubikit_otp_plug_in_or_tap);
                    } else {
                        textView.setText(R.string.yubikit_otp_plug_in);
                    }
                }
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        try {
            manager.startNfcDiscovery(true, this, new NfcSessionListener() {
                @Override
                public void onSessionReceived(@NonNull NfcSession session) {
                    try {
                        final String credential = OtpParser.parseTag(session.getTag());
                        textView.setText(R.string.yubikit_otp_received_nfc_tag);

                        // API 24+ has NfcAdapter.ignore which allows to ignore the same tag for some period of time
                        // so we should be safe to close current activity and do not receive the same tag within another activity right away
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            NfcAdapter.getDefaultAdapter(getApplicationContext()).ignore(
                                    session.getTag(), DEFAULT_TAG_IGNORE_TIMEOUT_MS, null, null);
                            returnSuccess(credential);
                        } else {
                            // for lower versions its better to close activity after some delay
                            // so that user can remove security key from nfc reader
                            // and won't receive another nfc tag upon finishing of current activity
                            new Handler().postDelayed(new Runnable() {
                                @Override
                                public void run() {
                                    returnSuccess(credential);
                                }
                            }, DEFAULT_TAG_IGNORE_TIMEOUT_MS);
                        }
                    } catch (ParseTagException e) {
                        returnError(e);
                    }

                }
            });
        } catch (NfcDisabledException e) {
            Snackbar.make(contentView, e.getMessage(), Snackbar.LENGTH_LONG).setAction(R.string.yubikit_otp_enable_nfc, new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    startActivity(new Intent(NfcDeviceManager.NFC_SETTINGS_ACTION));
                }
            });
        } catch (NfcNotFoundException e) {
            hasNfc = false;
            textView.setText(R.string.yubikit_otp_plug_in);
        }
    }

    @Override
    protected void onPause() {
        manager.stopNfcDiscovery(this);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        manager.stopUsbDiscovery();
        textView.setClickable(false);
        textView.setOnKeyListener(null);
        super.onDestroy();
    }

    /**
     * Finishes activity with error results
     * @param e the error to be returned to parent activity
     */
    private void returnError(Throwable e) {
        Intent intent = new Intent();
        intent.putExtra(EXTRA_ERROR, e);
        setResult(Activity.RESULT_FIRST_USER, intent);
        finish();
    }

    /**
     * Finished activity with successful results
     * @param otp code that was received from yubikey
     */
    private void returnSuccess(String otp) {
        Intent intent = new Intent();
        intent.putExtra(EXTRA_OTP, otp);
        setResult(Activity.RESULT_OK, intent);
        finish();
    }
}
