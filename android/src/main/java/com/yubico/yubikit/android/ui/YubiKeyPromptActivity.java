/*
 * Copyright (C) 2020 Yubico.
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

package com.yubico.yubikit.android.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import androidx.annotation.IdRes;
import androidx.annotation.LayoutRes;
import androidx.annotation.WorkerThread;
import com.yubico.yubikit.android.R;
import com.yubico.yubikit.android.YubiKitManager;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcDeviceManager;
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbDeviceListener;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Abstract base class for custom YubiKey dialogs.
 * <p>
 * Subclass this to create a dialog which prompts for a YubiKey, performs an action, and returns a result.
 * Use android:theme="@style/YubiKitPromptDialogTheme" when defining the Activity in your AndroidManifest.xml
 *
 * @param <T> the connection subclass used to determine suitability of a connected YubiKey.
 */
public abstract class YubiKeyPromptActivity<T extends YubiKeyConnection> extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final Class<T> connectionType;
    private final boolean allowUsb;
    private final boolean allowNfc;

    @LayoutRes
    protected final int contentViewLayoutId;
    @IdRes
    protected final int cancelButtonId;
    @IdRes
    protected final int enableNfcButtonId;
    @IdRes
    protected final int helpTextViewId;

    private YubiKitManager yubiKit;
    private boolean hasNfc = true;
    private int usbSessionCounter = 0;
    private boolean isDone = false;
    private Button cancelButton;
    private Button enableNfcButton;
    private TextView helpTextView;

    /**
     * Constructor allowing specification of all options.
     *
     * @param connectionType      the connection type the activity should react to
     * @param allowUsb            true if connecting a YubiKey via USB should be supported
     * @param allowNfc            true if connecting a YubiKey via NFC should be supported
     * @param contentViewLayoutId layout ID for the main content view to be used
     * @param helpTextViewId      resource ID for the help TextView which must exist in the main content view
     * @param cancelButtonId      resource ID for the cancel Button which must exist in the main content view
     * @param enableNfcButtonId   resource ID for the enable NFC Button which must exist in the main content view, if NFC is allowed
     */
    protected YubiKeyPromptActivity(Class<T> connectionType, boolean allowUsb, boolean allowNfc, @LayoutRes int contentViewLayoutId, @IdRes int helpTextViewId, @IdRes int cancelButtonId, @IdRes int enableNfcButtonId) {
        this.connectionType = connectionType;
        this.allowUsb = allowUsb;
        this.allowNfc = allowNfc;
        this.contentViewLayoutId = contentViewLayoutId;
        this.helpTextViewId = helpTextViewId;
        this.cancelButtonId = cancelButtonId;
        this.enableNfcButtonId = enableNfcButtonId;
    }

    /**
     * Constructor allowing specification of basic options.
     *
     * @param connectionType the connection type the activity should react to
     * @param allowUsb       true if connecting a YubiKey via USB should be supported
     * @param allowNfc       true if connecting a YubiKey via NFC should be supported
     */
    protected YubiKeyPromptActivity(Class<T> connectionType, boolean allowUsb, boolean allowNfc) {
        this(connectionType, allowUsb, allowNfc, R.layout.yubikit_yubikey_prompt_content, R.id.yubikit_prompt_help_text_view, R.id.yubikit_prompt_cancel_btn, R.id.yubikit_prompt_enable_nfc_btn);
    }

    /**
     * Constructor using the default settings.
     *
     * @param connectionType the connection type the activity should react to
     */
    protected YubiKeyPromptActivity(Class<T> connectionType) {
        this(connectionType, true, true);
    }

    protected YubiKitManager getYubiKitManager() {
        return yubiKit;
    }

    protected boolean isNfcEnabled() {
        return hasNfc;
    }

    /**
     * Called when a YubiKey is attached.
     * <p>
     * If not overridden, the default implementation will connect to the YubiKey (if the desired connection type is
     * supported) and invoke {@link #onYubiKeyConnection(YubiKeyConnection)}, finally closing the connection once done.
     * If {@link #provideResult(int, Intent)} has been called once this method returns, the Activity will finish.
     *
     * @param device a connected YubiKey
     */
    @WorkerThread
    protected void onYubiKeyDevice(YubiKeyDevice device) {
        if (device.supportsConnection(connectionType)) {
            try (T connection = device.openConnection(connectionType)) {
                onYubiKeyConnection(connection);
            } catch (IOException e) {
                onError(e);
            }
        } else {
            Logger.d("Connected YubiKey does not support desired connection type");
        }
    }

    /**
     * Called when a YubiKey supporting the desired connection type is connected.
     * <p>
     * Subclasses should override this method to react to a connected YubiKey. {@link #provideResult(int, Intent)}
     * should be called by this method to indicate that the activity should finish.
     * <p>
     * NOTE: Subclasses should not close the connection, as it will be closed by {@link #onYubiKeyDevice(YubiKeyDevice)}.
     *
     * @param connection A YubiKey connection
     */
    @WorkerThread
    protected void onYubiKeyConnection(T connection) {
        Logger.d("YubiKey connected with connection: " + connection);
    }

    /**
     * This method can be overriden to react to Exceptions thrown when connecting to a YubiKey.
     *
     * @param e the Exception which was thrown.
     */
    protected void onError(Exception e) {
        Logger.e("Error in YubiKey communication", e);
    }

    /**
     * Provides a result to return to the caller of the Activity.
     * Internally this calls {@link #setResult(int, Intent)} with the given arguments, as well as informing this
     * Activity that it should finish once it is done handling any connected YubiKey.
     *
     * @param resultCode The result code to propagate back to the originating
     *                   activity, often RESULT_CANCELED or RESULT_OK
     * @param data       The data to propagate back to the originating activity.
     */
    protected void provideResult(int resultCode, Intent data) {
        setResult(resultCode, data);
        isDone = true;
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(contentViewLayoutId);

        setFinishOnTouchOutside(false);

        helpTextView = findViewById(helpTextViewId);
        cancelButton = findViewById(cancelButtonId);
        cancelButton.setFocusable(false);
        cancelButton.setOnClickListener(v -> {
            setResult(Activity.RESULT_CANCELED);
            finish();
        });

        yubiKit = new YubiKitManager(this);
        if (allowUsb) {
            yubiKit.startUsbDiscovery(new UsbConfiguration(), new UsbDeviceListener() {
                @Override
                public void onDeviceAttached(@Nonnull UsbYubiKeyDevice device, boolean hasPermission) {
                    usbSessionCounter++;
                    helpTextView.setText(R.string.yubikit_prompt_wait);
                    if (hasPermission) {
                        executor.execute(() -> {
                            onYubiKeyDevice(device);
                            finishIfDone();
                        });
                    }
                }

                @Override
                public void onDeviceRemoved(@Nonnull UsbYubiKeyDevice device) {
                    usbSessionCounter--;
                    if (usbSessionCounter == 0) {
                        helpTextView.setText(hasNfc ? R.string.yubikit_prompt_plug_in_or_tap : R.string.yubikit_prompt_plug_in);
                    }
                }

                @Override
                public void onRequestPermissionsResult(@Nonnull UsbYubiKeyDevice device, boolean isGranted) {
                    if (isGranted) {
                        executor.execute(() -> {
                            onYubiKeyDevice(device);
                            finishIfDone();
                        });
                    } else {
                        Logger.d("Access to YubiKey denied");
                    }
                }
            });
        }

        if (allowNfc) {
            enableNfcButton = findViewById(enableNfcButtonId);
            enableNfcButton.setFocusable(false);
            enableNfcButton.setOnClickListener(v -> {
                startActivity(new Intent(NfcDeviceManager.NFC_SETTINGS_ACTION));
            });
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (allowNfc) {
            enableNfcButton.setVisibility(View.GONE);
            try {
                yubiKit.startNfcDiscovery(new NfcConfiguration(), this, device -> {
                    executor.execute(() -> {
                        onYubiKeyDevice(device);
                        runOnUiThread(() -> {
                            helpTextView.setText(R.string.yubikit_prompt_remove);
                        });
                        device.awaitRemoval();
                        finishIfDone();
                    });
                });
            } catch (NfcNotAvailable e) {
                hasNfc = false;
                helpTextView.setText(R.string.yubikit_prompt_plug_in);
                if (e.isDisabled()) {
                    enableNfcButton.setVisibility(View.VISIBLE);
                }
            }
        }
    }

    @Override
    protected void onPause() {
        if (allowNfc) {
            yubiKit.stopNfcDiscovery(this);
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (allowUsb) {
            yubiKit.stopUsbDiscovery();
        }
        executor.shutdown();
        super.onDestroy();
    }

    private void finishIfDone() {
        if (isDone) {
            finish();
        }
    }
}
