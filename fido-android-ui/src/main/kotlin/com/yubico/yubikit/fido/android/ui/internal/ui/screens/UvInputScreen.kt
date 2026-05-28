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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.Error
import com.yubico.yubikit.fido.android.ui.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.DefaultPreview
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
internal fun MatchFingerprint(
    operation: FidoClientService.Operation,
    rpId: String,
    error: Error? = null,
    onCloseButtonClick: () -> Unit,
) {
    val errorText: String? =
        when (error) {
            is Error.IncorrectUvError -> {
                val attempts = error.remainingAttempts
                if (attempts > 0) {
                    pluralStringResource(R.plurals.yk_fido_ctap_err_uv_invalid, count = attempts, attempts)
                } else {
                    stringResource(R.string.yk_fido_ctap_err_uv_invalid_use_pin)
                }
            }
            null -> null
            else -> stringResource(R.string.yk_fido_ctap_err_uv_unknown)
        }

    ContentWrapper(
        operation = operation,
        title = if (operation == FidoClientService.Operation.MAKE_CREDENTIAL) {
            stringResource(R.string.yk_fido_create_passkey)
        } else {
            stringResource(R.string.yk_fido_login_with_passkey)
        },
        onCloseButtonClick = onCloseButtonClick,
    ) {
        if (rpId.isNotEmpty()) {
            Text(
                text = rpId,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Text(
            text = stringResource(R.string.yk_fido_touch_fingerprint),
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
                imageVector = Icons.Filled.Fingerprint,
                contentDescription = stringResource(R.string.yk_fido_fingerprint_icon),
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.onSurface,
            )
        }

        if (errorText != null) {
            Text(
                text = errorText,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp)
                    .testTag("uv_error_text"),
            )
        }
    }
}

@DefaultPreview
@Composable
internal fun MatchFingerprintNewPreview() {
    FidoAndroidTheme {
        MatchFingerprint(
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            rpId = "example.com",
            onCloseButtonClick = {},
        )
    }
}

@DefaultPreview
@Composable
internal fun MatchFingerprintNewWithErrorPreview() {
    FidoAndroidTheme {
        MatchFingerprint(
            operation = FidoClientService.Operation.GET_ASSERTION,
            rpId = "example.com",
            error = Error.IncorrectUvError(3),
            onCloseButtonClick = {},
        )
    }
}
