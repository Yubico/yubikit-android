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

package com.yubico.yubikit.transport.nfc;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;

import com.yubico.yubikit.exceptions.NfcDisabledException;
import com.yubico.yubikit.exceptions.NfcNotFoundException;

import androidx.annotation.NonNull;

/**
 * This class allows you to communicate with local NFC adapter
 */
public class NfcDeviceManager {

    /**
     * Action for intent to tweak NFC settings in Android settings view
     * on Q Android supports Settings.Panel.ACTION_NFC, we might update with release on Q
     *
     */
    public static final String NFC_SETTINGS_ACTION = "android.settings.NFC_SETTINGS";

    private final Context context;
    private final NfcAdapter adapter;

    private NfcSessionListener listener;
    /**
     * Creates instance of {@link NfcDeviceManager}
     * @param context the application context
     */
    public NfcDeviceManager(Context context) {
        this.context = context;
        adapter = NfcAdapter.getDefaultAdapter(this.context);
    }

    /**
     * Sets listener to Nfc session discovery
     * @param listener the listener
     */
    public void setListener(final @NonNull NfcSessionListener listener) {
        this.listener = listener;
    }

    /**
     * Enable discovery of nfc tags for foreground activity
     * @param activity activity that is going to dispatch nfc tags
     * @param nfcConfiguration additional configurations for NFC discovery
     * @throws NfcDisabledException in case if NFC turned off
     * @throws NfcNotFoundException in case if NFC not available on android device
     */
    public void enable(final @NonNull Activity activity, final NfcConfiguration nfcConfiguration) throws NfcDisabledException, NfcNotFoundException {
        if (checkAvailability(nfcConfiguration.isHandleUnavailableNfc())) {
            // restart nfc watching services
            disableReaderMode(activity);
            enableReaderMode(activity, nfcConfiguration);
        }
    }

    /**
     * Disable active listening of nfc events
     * @param activity activity that goes to background or want to stop dispatching nfc tags
     */
    public void disable(final @NonNull Activity activity) {
        if (adapter == null) {
            return;
        }
        disableReaderMode(activity);
    }

    /**
     * Checks if user turned on NFC_TRANSPORT and returns result via listener callbacks
     * @param handleUnavailableNfc true if prompt user for turning on settings with UI dialog, otherwise returns error if no settings on or NFC_TRANSPORT is not available
     * @throws NfcDisabledException in case if NFC turned off
     * @throws NfcNotFoundException in case if NFC not available on android device
     */
    private boolean checkAvailability(boolean handleUnavailableNfc) throws NfcDisabledException, NfcNotFoundException {
        if (adapter == null) {
            throw new NfcNotFoundException("NFC transport is not available on this device");
        }
        if (!adapter.isEnabled() && !handleUnavailableNfc) {
            throw new NfcDisabledException("Please activate NFC_TRANSPORT");
        }
        if (!adapter.isEnabled()) {
            context.startActivity(new Intent(NFC_SETTINGS_ACTION));
            return false;
        } else {
            return true;
        }
    }

    /**
     * Start intercepting nfc events
     * @param activity activity that is going to receive nfc events
     * Note: invoke that while activity is in foreground
     */
    private void enableReaderMode(Activity activity, final NfcConfiguration nfcConfiguration) {
        NfcAdapter.ReaderCallback callback = new NfcAdapter.ReaderCallback() {
            public void onTagDiscovered(Tag tag) {
                listener.onSessionReceived(new NfcSession(tag));
            }
        };
        Bundle options = new Bundle();
        options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 50);
        int READER_FLAGS = NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B;
        if (nfcConfiguration.isDisableNfcDiscoverySound()) {
            READER_FLAGS |= NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS;
        }

        if (nfcConfiguration.isSkipNdefCheck()) {
            READER_FLAGS |= NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;
        }
        adapter.enableReaderMode(activity, callback, READER_FLAGS, options);
    }

    /**
     * Stop intercepting nfc events
     * @param activity activity that was receiving nfc events
     * Note: invoke that while activity is still in foreground
     */
    private void disableReaderMode(Activity activity) {
        adapter.disableReaderMode(activity);
    }
}
