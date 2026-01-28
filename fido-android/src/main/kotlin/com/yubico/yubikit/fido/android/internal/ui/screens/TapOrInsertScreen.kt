/*
 * Copyright (C) 2025-2026 Yubico.
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

package com.yubico.yubikit.fido.android.internal.ui.screens

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.internal.ui.theme.DefaultPreview

@Composable
internal fun TapOrInsertSecurityKey(
    operation: FidoClientService.Operation,
    isNfcAvailable: Boolean,
    origin: String,
    onCloseButtonClick: () -> Unit,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_baseline_passkey_24),
            contentDescription = stringResource(R.string.yk_fido_passkey_icon),
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.yk_fido_tap_or_insert_key))
        if (!isNfcAvailable) {
            Text(
                text = "NFC not available",
                color = MaterialTheme.colorScheme.primary,
                fontSize = MaterialTheme.typography.bodySmall.fontSize,
                textDecoration = TextDecoration.Underline,
                modifier = Modifier.testTag("nfc_not_available_text"),
            )
        }
    }
}

@DefaultPreview
@Composable
internal fun TapOrInsertSecurityKeyForMakeCredentialPreview() {
    TapOrInsertSecurityKey(
        isNfcAvailable = false,
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "www.example.com",
    ) {}
}

@DefaultPreview
@Composable
internal fun TapOrInsertSecurityKeyForGetAssertionPreview() {
    TapOrInsertSecurityKey(
        isNfcAvailable = true,
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "www.example.com",
    ) {}
}
