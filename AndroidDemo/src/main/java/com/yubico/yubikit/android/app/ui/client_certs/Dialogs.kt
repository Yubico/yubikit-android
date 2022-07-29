package com.yubico.yubikit.android.app.ui.client_certs

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.view.LayoutInflater
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import com.yubico.yubikit.android.app.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * Asks the user for a PIN/password.
 */
suspend fun enterPin(context: Context, title: String): CharArray =
    withContext(Dispatchers.Main) {
        suspendCoroutine { cont ->
            val view = LayoutInflater.from(context).inflate(R.layout.dialog_pin, null)
            AlertDialog.Builder(context)
                .setTitle(title)
                .setView(view)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    val pin =
                        view.findViewById<EditText>(R.id.dialog_pin_edittext).text.toString()
                    cont.resume(pin.toCharArray())
                }
                .setNeutralButton(android.R.string.cancel) { dialog, _ ->
                    dialog.cancel()
                }
                .setOnCancelListener {
                    cont.resumeWithException(CancellationException())
                }
                .create()
                .show()
        }
    }

/**
 * Asks the user to choose an item from a list.
 */
suspend fun <T> selectItem(
    context: Context,
    title: String,
    items: List<T>,
    label: (T) -> String
): Int =
    withContext(Dispatchers.Main) {
        suspendCoroutine { cont ->
            AlertDialog.Builder(context)
                .setTitle(title)
                .setItems(items.map { label(it) }.toTypedArray()) { _, which ->
                    cont.resume(which)
                }
                .setOnCancelListener {
                    cont.resumeWithException(CancellationException())
                }
                .create().apply {
                    listView.apply {
                        divider = ColorDrawable(Color.GRAY)
                        dividerHeight = 2
                    }
                }.show()
        }
    }

/**
 * Asks the user to confirm (or cancel) an action.
 */
suspend fun confirmAction(context: Context, title: String, message: String): Boolean =
    withContext(Dispatchers.Main) {
        suspendCoroutine { cont ->
            AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    cont.resume(true)
                }
                .setNeutralButton(android.R.string.cancel) { dialog, _ ->
                    dialog.cancel()
                }
                .setOnCancelListener {
                    cont.resume(false)
                }
                .create()
                .show()
        }
    }