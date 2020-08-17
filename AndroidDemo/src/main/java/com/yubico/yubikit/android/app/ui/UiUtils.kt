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
suspend fun getSecret(context: Context, @StringRes title: Int, @StringRes hint: Int = R.string.pin) = suspendCoroutine<String?> { cont ->
    val view = LayoutInflater.from(context).inflate(R.layout.dialog_pin, null).apply {
        findViewById<TextInputLayout>(R.id.dialog_pin_textinputlayout).hint = context.getString(hint)
    }
    val dialog = AlertDialog.Builder(context)
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