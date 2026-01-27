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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.Error
import com.yubico.yubikit.fido.android.internal.ui.components.ContentWrapper

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
        Text(
            text =
            if (operation == FidoClientService.Operation.MAKE_CREDENTIAL) {
                stringResource(R.string.passkey_created)
            } else {
                stringResource(R.string.login_successful)
            },
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.testTag("result_message_text"),
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.remove_the_key),
            style = MaterialTheme.typography.bodyMedium,
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
        modifier = Modifier.wrapContentSize(),
        operation = operation,
        origin = origin,
        onCloseButtonClick = null,
    ) {
        Icon(
            imageVector = Icons.Default.Error,
            contentDescription = stringResource(R.string.error),
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(48.dp),
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            modifier = Modifier.padding(horizontal = 32.dp).testTag("error_message_text"),
            style = MaterialTheme.typography.bodySmallEmphasized,
            text =
            when (error) {
                is Error.OperationError -> {
                    error.exception?.let { ex ->
                        when (ex) {
                            is CtapException -> {
                                when (ex.ctapError) {
                                    CtapException.ERR_NO_CREDENTIALS ->
                                        stringResource(
                                            R.string.ctap_err_no_credentials,
                                            origin,
                                        )

                                    CtapException.ERR_USER_ACTION_TIMEOUT ->
                                        stringResource(
                                            R.string.ctap_err_user_action_timeout,
                                        )

                                    CtapException.ERR_KEY_STORE_FULL ->
                                        stringResource(
                                            R.string.ctap_err_key_store_full,
                                        )

                                    CtapException.ERR_PUAT_REQUIRED ->
                                        stringResource(
                                            R.string.ctap_err_puat_required,
                                        )

                                    CtapException.ERR_UV_INVALID ->
                                        stringResource(R.string.ctap_err_uv_unknown)

                                    CtapException.ERR_CREDENTIAL_EXCLUDED ->
                                        stringResource(
                                            R.string.ctap_err_credential_excluded,
                                        )

                                    else -> stringResource(R.string.unknown_error)
                                }
                            }

                            else -> stringResource(R.string.unknown_error)
                        }
                    } ?: stringResource(R.string.unknown_error)
                }

                is Error.DeviceNotConfiguredError -> stringResource(R.string.device_not_configured)

                is Error.UnknownError -> error.message ?: stringResource(R.string.unknown_error)

                else -> stringResource(R.string.unknown_error)
            },
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onRetry,
            modifier = Modifier.testTag("retry_button"),
        ) {
            Text(stringResource(R.string.retry))
        }
    }
}
