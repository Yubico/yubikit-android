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

package com.yubico.yubikit.transport.nfc;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;

import androidx.annotation.NonNull;

public class NfcReaderDispatcher implements NfcDispatcher {
    private final NfcAdapter adapter;
    private OnTagHandler handler;

    public NfcReaderDispatcher(@NonNull NfcAdapter adapter) {
        this.adapter = adapter;
    }

    @Override
    public void setOnTagHandler(OnTagHandler handler) {
        this.handler = handler;
    }

    @Override
    public void enable(@NonNull Activity activity, NfcConfiguration nfcConfiguration) {
        // restart nfc watching services
        disableReaderMode(activity);
        enableReaderMode(activity, nfcConfiguration);
    }

    @Override
    public void disable(@NonNull Activity activity) {
        disableReaderMode(activity);
    }
    /**
     * Start intercepting nfc events
     * @param activity activity that is going to receive nfc events
     * Note: invoke that while activity is in foreground
     */
    private void enableReaderMode(Activity activity, final NfcConfiguration nfcConfiguration) {
        NfcAdapter.ReaderCallback callback = new NfcAdapter.ReaderCallback() {
            public void onTagDiscovered(Tag tag) {
                handler.onTag(tag);
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
