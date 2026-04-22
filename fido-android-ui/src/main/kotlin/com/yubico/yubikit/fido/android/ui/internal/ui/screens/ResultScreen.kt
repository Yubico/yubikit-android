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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.Error
import com.yubico.yubikit.fido.android.ui.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.internal.ui.components.OperationTitle
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.DefaultPreview
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme

@Composable
internal fun SuccessView(
    operation: FidoClientService.Operation,
    origin: String,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = null,
    ) {
        OperationTitle(
            operation = operation,
            origin = "",
            titleOverride = if (operation == FidoClientService.Operation.MAKE_CREDENTIAL) {
                stringResource(R.string.yk_fido_passkey_created)
            } else {
                stringResource(R.string.yk_fido_login_successful)
            },
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Success icon with background circle
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
                imageVector = Icons.Default.Check,
                contentDescription = stringResource(R.string.yk_fido_passkey_created),
                tint = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.size(80.dp),
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = stringResource(R.string.yk_fido_remove_the_key),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.testTag("result_message_text"),
        )
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
internal fun ErrorView(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    onRetry: () -> Unit,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = null,
    ) {
        OperationTitle(operation = operation, origin = origin)

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .testTag("error_message_text"),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            text = resolveErrorText(error, origin),
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Error icon with background circle
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.size(100.dp)
                .background(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = CircleShape,
                ),
        ) {
            Icon(
                imageVector = Icons.Default.Error,
                contentDescription = stringResource(R.string.yk_fido_error),
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(80.dp),
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
        ) {
            Button(
                onClick = onRetry,
                modifier = Modifier.testTag("retry_button"),
            ) {
                Text(stringResource(R.string.yk_fido_retry))
            }
        }
    }
}

@Composable
private fun resolveErrorText(error: Error?, origin: String): String =
    when (error) {
        is Error.OperationError -> {
            error.exception?.let { ex ->
                when (ex) {
                    is CtapException -> when (ex.ctapError) {
                        CtapException.ERR_NO_CREDENTIALS ->
                            stringResource(R.string.yk_fido_ctap_err_no_credentials, origin)
                        CtapException.ERR_USER_ACTION_TIMEOUT ->
                            stringResource(R.string.yk_fido_ctap_err_user_action_timeout)
                        CtapException.ERR_KEY_STORE_FULL ->
                            stringResource(R.string.yk_fido_ctap_err_key_store_full)
                        CtapException.ERR_PUAT_REQUIRED ->
                            stringResource(R.string.yk_fido_ctap_err_puat_required)
                        CtapException.ERR_UV_INVALID ->
                            stringResource(R.string.yk_fido_ctap_err_uv_unknown)
                        CtapException.ERR_CREDENTIAL_EXCLUDED ->
                            stringResource(R.string.yk_fido_ctap_err_credential_excluded)
                        else -> stringResource(R.string.yk_fido_unknown_error)
                    }
                    else -> stringResource(R.string.yk_fido_unknown_error)
                }
            } ?: stringResource(R.string.yk_fido_unknown_error)
        }
        is Error.DeviceNotConfiguredError -> stringResource(R.string.yk_fido_device_not_configured)
        is Error.UnknownError -> stringResource(R.string.yk_fido_unknown_error)
        else -> stringResource(R.string.yk_fido_unknown_error)
    }

@DefaultPreview
@Composable
internal fun SuccessViewPreview() {
    FidoAndroidTheme {
        SuccessView(
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            origin = "example.com",
        )
    }
}

@DefaultPreview
@Composable
internal fun SuccessLoginViewPreview() {
    FidoAndroidTheme {
        SuccessView(
            operation = FidoClientService.Operation.GET_ASSERTION,
            origin = "example.com",
        )
    }
}

@DefaultPreview
@Composable
internal fun OperationErrorViewPreview() {
    FidoAndroidTheme {
        ErrorView(
            operation = FidoClientService.Operation.GET_ASSERTION,
            origin = "example.com",
            error = Error.OperationError(CtapException(CtapException.ERR_KEY_STORE_FULL)),
            onRetry = {},
        )
    }
}

@DefaultPreview
@Composable
internal fun DeviceNotConfiguredErrorViewPreview() {
    FidoAndroidTheme {
        ErrorView(
            operation = FidoClientService.Operation.GET_ASSERTION,
            origin = "example.com",
            error = Error.DeviceNotConfiguredError,
            onRetry = {},
        )
    }
}
