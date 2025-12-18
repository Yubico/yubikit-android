/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.android.app.ui

import android.content.Context
import android.view.LayoutInflater
import android.widget.EditText
import androidx.annotation.StringRes
import androidx.annotation.UiThread
import androidx.appcompat.app.AlertDialog
import com.google.android.material.textfield.TextInputLayout
import com.yubico.yubikit.android.app.R
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@UiThread
suspend fun getSecret(
    context: Context,
    @StringRes title: Int,
    @StringRes hint: Int = R.string.pin,
) = suspendCoroutine { cont ->
    val view =
        LayoutInflater.from(context).inflate(R.layout.dialog_pin, null).apply {
            findViewById<TextInputLayout>(R.id.dialog_pin_textinputlayout).hint = context.getString(hint)
        }
    val dialog =
        AlertDialog.Builder(context)
            .setTitle(title)
            .setView(view)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                cont.resume(view.findViewById<EditText>(R.id.dialog_pin_edittext).text.toString())
            }
            .setNeutralButton(android.R.string.cancel) { dialog, _ ->
                dialog.cancel()
            }
            .setOnCancelListener {
                cont.resume(null)
            }
            .create()
    dialog.show()
}
