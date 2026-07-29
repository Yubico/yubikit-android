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

package com.yubico.yubikit.fido.android.ui.internal.ui.screens

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle

/**
 * Builds an [AnnotatedString] from a `%1$s`-style string resource template, bolding the
 * substituted rpId/caller label so it visually stands out from the surrounding sentence.
 */
@Composable
internal fun rpIdSentence(
    @StringRes templateRes: Int,
    rpId: String,
): AnnotatedString {
    val template = stringResource(templateRes)
    val parts = template.split("%1\$s", limit = 2)
    val before = parts[0]
    val after = parts.getOrElse(1) { "" }
    return buildAnnotatedString {
        append(before)
        withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) { append(rpId) }
        append(after)
    }
}
