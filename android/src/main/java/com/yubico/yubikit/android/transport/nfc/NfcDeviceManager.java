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

package com.yubico.yubikit.android.transport.nfc;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;

import javax.annotation.Nullable;

/**
 * This class allows you to communicate with local NFC adapter
 */
public class NfcDeviceManager {

    /**
     * Action for intent to tweak NFC settings in Android settings view
     * on Q Android supports Settings.Panel.ACTION_NFC, we might update with release on Q
     */
    public static final String NFC_SETTINGS_ACTION = "android.settings.NFC_SETTINGS";

    private final Context context;
    private final NfcAdapter adapter;
    private final NfcDispatcher dispatcher;

    /**
     * Creates instance of {@link NfcDeviceManager}
     *
     * @param context    the application context
     * @param dispatcher optional implementation of NfcDispatcher to use instead of the default.
     * @throws NfcNotFoundException if the Android device does not support NFC
     */
    public NfcDeviceManager(Context context, @Nullable NfcDispatcher dispatcher) throws NfcNotFoundException {
        this.context = context;
        adapter = NfcAdapter.getDefaultAdapter(this.context);
        if (adapter == null) {
            throw new NfcNotFoundException("NFC unavailable on this device");
        }
        if (dispatcher == null) {
            dispatcher = new NfcReaderDispatcher(adapter);
        }
        this.dispatcher = dispatcher;
    }

    public NfcDeviceManager(Context context) throws NfcNotFoundException {
        this(context, null);
    }

    /**
     * Enable discovery of nfc tags for foreground activity
     *
     * @param activity         activity that is going to dispatch nfc tags
     * @param nfcConfiguration additional configurations for NFC discovery
     * @param listener         the listener to invoke on NFC sessions
     * @throws NfcDisabledException in case NFC is turned off (but available)
     */
    public void enable(Activity activity, NfcConfiguration nfcConfiguration, NfcSessionListener listener) throws NfcDisabledException {
        if (checkAvailability(nfcConfiguration.isHandleUnavailableNfc())) {
            dispatcher.enable(activity, nfcConfiguration, tag -> listener.onSessionReceived(new NfcSession(tag, nfcConfiguration.getTimeout())));
        }
    }

    /**
     * Disable active listening of nfc events
     *
     * @param activity activity that goes to background or want to stop dispatching nfc tags
     */
    public void disable(Activity activity) {
        dispatcher.disable(activity);
    }

    /**
     * Checks if user turned on NFC_TRANSPORT and returns result via listener callbacks
     *
     * @param handleUnavailableNfc true if prompt user for turning on settings with UI dialog, otherwise returns error if no settings on or NFC_TRANSPORT is not available
     * @throws NfcDisabledException in case if NFC turned off
     */
    private boolean checkAvailability(boolean handleUnavailableNfc) throws NfcDisabledException {
        if (adapter.isEnabled()) {
            return true;
        }
        if (handleUnavailableNfc) {
            context.startActivity(new Intent(NFC_SETTINGS_ACTION));
            return false;
        } else {
            throw new NfcDisabledException("Please activate NFC_TRANSPORT");
        }
    }
}
