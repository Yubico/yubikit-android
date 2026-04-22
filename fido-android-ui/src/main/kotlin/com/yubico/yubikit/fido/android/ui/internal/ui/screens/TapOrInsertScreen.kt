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

package com.yubico.yubikit.fido.android.ui.internal.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.internal.ui.components.OperationTitle
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.DefaultPreview
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme

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
        OperationTitle(
            operation = operation,
            origin = "",
            titleOverride = stringResource(R.string.yk_fido_connect_your_key_title),
        )

        Text(
            text = stringResource(R.string.yk_fido_connect_your_key_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            minLines = 2,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        )

        Spacer(modifier = Modifier.height(24.dp))

        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(100.dp)
                .background(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = CircleShape,
                ),
        ) {
            Icon(
                painter = painterResource(R.drawable.security_key_24px),
                contentDescription = stringResource(R.string.yk_fido_passkey_icon),
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.onSurface,
            )
        }

        if (!isNfcAvailable) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.yk_fido_nfc_not_available),
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
    FidoAndroidTheme {
        TapOrInsertSecurityKey(
            isNfcAvailable = false,
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            origin = "www.example.com",
        ) {}
    }
}

@DefaultPreview
@Composable
internal fun TapOrInsertSecurityKeyForGetAssertionPreview() {
    FidoAndroidTheme {
        TapOrInsertSecurityKey(
            isNfcAvailable = true,
            operation = FidoClientService.Operation.GET_ASSERTION,
            origin = "www.example.com",
        ) {}
    }
}
