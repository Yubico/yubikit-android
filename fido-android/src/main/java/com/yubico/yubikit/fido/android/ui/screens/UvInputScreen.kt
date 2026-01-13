/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.android.ui.screens

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.theme.DefaultPreview

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun MatchFingerprint(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    onCloseButtonClick: () -> Unit,
) {
    val errorText =
        when (error) {
            is Error.IncorrectUvError -> {
                val attempts = error.remainingAttempts
                if (attempts > 0) {
                    stringResource(R.string.ctap_err_uv_invalid, attempts)
                } else {
                    stringResource(R.string.ctap_err_uv_invalid_use_pin)
                }
            }

            null -> stringResource(R.string.touch_fingerprint)
            else -> stringResource(R.string.ctap_err_uv_unknown)
        }

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        val focusRequester = remember { FocusRequester() }
        val keyboardController = LocalSoftwareKeyboardController.current

        LaunchedEffect(Unit) {
            focusRequester.requestFocus()
            keyboardController?.show()
        }

        Icon(
            imageVector = Icons.Filled.Fingerprint,
            contentDescription = stringResource(R.string.fingerprint_icon),
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.primary,
        )

        Text(
            modifier =
                Modifier
                    .padding(start = 32.dp, end = 32.dp, top = 16.dp, bottom = 8.dp),
            style = MaterialTheme.typography.bodySmallEmphasized,
            textAlign = TextAlign.Center,
            text = errorText,
        )
    }
}

@DefaultPreview
@Composable
fun MatchFingerprintNewPreview() {
    MatchFingerprint(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onCloseButtonClick = {},
    )
}

@DefaultPreview
@Composable
fun MatchFingerprintNewWithErrorPreview() {
    MatchFingerprint(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "example.com",
        error = Error.IncorrectUvError(3),
        onCloseButtonClick = {},
    )
}
