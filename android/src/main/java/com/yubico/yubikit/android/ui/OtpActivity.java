package com.yubico.yubikit.android.ui;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.yubico.yubikit.android.R;
import com.yubico.yubikit.android.YubiKitManager;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcDeviceManager;
import com.yubico.yubikit.android.transport.nfc.NfcDisabledException;
import com.yubico.yubikit.android.transport.nfc.NfcNotFoundException;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbSession;
import com.yubico.yubikit.android.transport.usb.UsbSessionListener;
import com.yubico.yubikit.core.NdefUtils;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class OtpActivity extends Activity {
    public static final String EXTRA_OTP = "otp";
    public static final String EXTRA_ERROR = "error";

    private static final int DEFAULT_TAG_IGNORE_TIMEOUT_MS = 1000;

    private YubiKitManager manager;
    private OtpKeyListener keyListener;
    private TextView textView;
    private Button nfcBtn;

    private boolean hasNfc = true;
    private int usbSessionCounter = 0;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_otp);

        setFinishOnTouchOutside(false);

        textView = findViewById(R.id.yubikit_otp_text_view);

        manager = new YubiKitManager(this);
        manager.startUsbDiscovery(new UsbConfiguration().handlePermissions(false), new UsbSessionListener() {
            @Override
            public void onSessionReceived(@Nonnull UsbSession session, boolean hasPermission) {
                usbSessionCounter++;
                textView.setText(R.string.yubikit_otp_touch);
            }

            @Override
            public void onSessionRemoved(@Nonnull UsbSession session) {
                usbSessionCounter--;
                if (usbSessionCounter == 0) {
                    textView.setText(hasNfc ? R.string.yubikit_otp_plug_in_or_tap : R.string.yubikit_otp_plug_in);
                }
            }

            @Override
            public void onRequestPermissionsResult(@Nonnull UsbSession session, boolean isGranted) {
                // We don't need permissions to handle YubiOTP
            }
        });

        keyListener = new OtpKeyListener(new OtpKeyListener.OtpListener() {
            @Override
            public void onCaptureStarted() {
                textView.setText(R.string.yubikit_otp_wait);
            }

            @Override
            public void onCaptureComplete(String capture) {
                returnSuccess(capture);
            }
        });

        Button cancelBtn = findViewById(R.id.yubikit_otp_cancel_btn);
        cancelBtn.setFocusable(false);  //To avoid YubiKey keyboard input triggering.
        cancelBtn.setOnClickListener(v -> {
            setResult(Activity.RESULT_CANCELED);
            finish();
        });

        nfcBtn = findViewById(R.id.yubikit_otp_enable_nfc_btn);
        nfcBtn.setFocusable(false);  //To avoid YubiKey keyboard input triggering.
        nfcBtn.setOnClickListener(v -> {
            startActivity(new Intent(NfcDeviceManager.NFC_SETTINGS_ACTION));
        });
    }

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        return keyListener.onKeyEvent(event);
    }

    @Override
    protected void onResume() {
        super.onResume();

        nfcBtn.setVisibility(View.GONE);
        try {
            manager.startNfcDiscovery(new NfcConfiguration(), this, session -> {
                try {
                    String credential = NdefUtils.getNdefPayload(session.readNdef());
                    textView.setText(R.string.yubikit_otp_remove);

                    // Wait for the YubiKey to be removed before returning to avoid triggering a new tag discovery.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        NfcAdapter.getDefaultAdapter(getApplicationContext()).ignore(
                                session.getTag(), DEFAULT_TAG_IGNORE_TIMEOUT_MS, () -> returnSuccess(credential), null);
                    } else {
                        // Busy-wait for removal
                        try {
                            IsoDep isoDep = IsoDep.get(session.getTag());
                            isoDep.connect();
                            while (isoDep.isConnected()) {
                                Thread.sleep(DEFAULT_TAG_IGNORE_TIMEOUT_MS);
                            }
                        } catch (InterruptedException | IOException e) {
                            //Ignore
                        }
                        returnSuccess(credential);
                    }
                } catch (IOException e) {
                    returnError(e);
                }

            });
        } catch (NfcDisabledException e) {
            hasNfc = false;
            textView.setText(R.string.yubikit_otp_plug_in);
            nfcBtn.setVisibility(View.VISIBLE);
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
        super.onDestroy();
    }

    /**
     * Finishes activity with error results
     *
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
     *
     * @param otp code that was received from yubikey
     */
    private void returnSuccess(String otp) {
        Intent intent = new Intent();
        intent.putExtra(EXTRA_OTP, otp);
        setResult(Activity.RESULT_OK, intent);
        finish();
    }
}
