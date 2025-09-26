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

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.components.ContentWrapper

@Composable
fun SuccessView(operation: FidoClientService.Operation, origin: String) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = null
    ) {
        Text(
            text = if (operation == FidoClientService.Operation.MAKE_CREDENTIAL)
                stringResource(R.string.passkey_created)
            else
                stringResource(R.string.login_successful),
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.remove_the_key),
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

@Composable
fun ErrorView(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    onRetry: () -> Unit
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = null
    ) {
        Icon(
            imageVector = Icons.Default.Error,
            contentDescription = stringResource(R.string.error),
            tint = Color.Red,
            modifier = Modifier.size(48.dp)
        )

        Spacer(modifier = Modifier.height(8.dp))

        if (error is Error.UnknownError) {
            Text(text = error.message ?: stringResource(R.string.unknown_error))
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(onClick = onRetry) {
            Text(stringResource(R.string.retry))
        }
    }
}