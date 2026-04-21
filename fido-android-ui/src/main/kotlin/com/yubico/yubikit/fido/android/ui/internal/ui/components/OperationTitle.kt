/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.android.ui.internal.ui.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService

@Composable
internal fun OperationTitle(
    operation: FidoClientService.Operation,
    origin: String,
    modifier: Modifier = Modifier,
    titleOverride: String? = null,
) {
    Text(
        text = titleOverride ?: if (operation == FidoClientService.Operation.MAKE_CREDENTIAL) {
            stringResource(R.string.yk_fido_create_passkey)
        } else {
            stringResource(R.string.yk_fido_login_with_passkey)
        },
        style = MaterialTheme.typography.headlineSmall,
        textAlign = TextAlign.Center,
        modifier = modifier.fillMaxWidth(),
    )
    if (origin.isNotEmpty()) {
        Text(
            text = origin,
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
