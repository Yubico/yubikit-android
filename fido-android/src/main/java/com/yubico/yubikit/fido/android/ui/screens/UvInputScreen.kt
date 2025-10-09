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
import androidx.compose.material3.Button
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
    onRetry: () -> Unit
) {

    val (errorText, buttonText) = when (error) {
        is Error.IncorrectUvError -> {
            val attempts = error.remainingAttempts
            if (attempts > 0) {
                Pair(
                    stringResource(R.string.ctap_err_uv_invalid, attempts),
                    stringResource(R.string.retry)
                )
            } else {
                Pair(
                    stringResource(R.string.ctap_err_uv_invalid_use_pin),
                    stringResource(R.string.continue_operation)
                )
            }
        }

        null -> Pair(null, stringResource(R.string.retry))
        else -> Pair(stringResource(R.string.ctap_err_uv_unknown), stringResource(R.string.retry))
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
            tint = MaterialTheme.colorScheme.primary
        )

        errorText?.let {
            Text(
                modifier = Modifier.padding(horizontal = 32.dp),
                style = MaterialTheme.typography.bodySmallEmphasized,
                text = errorText
            )
        }

        Button(onClick = onRetry) {
            Text(buttonText)
        }
    }
}

@DefaultPreview
@Composable
fun MatchFingerprintPreview() {
    MatchFingerprint(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onCloseButtonClick = {},
        onRetry = {})
}

@DefaultPreview
@Composable
fun MatchFingerprintWithErrorPreview() {
    MatchFingerprint(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "example.com",
        error = Error.IncorrectUvError(3),
        onCloseButtonClick = {},
        onRetry = {})
}
