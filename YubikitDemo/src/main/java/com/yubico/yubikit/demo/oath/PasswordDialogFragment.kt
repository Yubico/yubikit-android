/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.demo.oath

import android.app.AlertDialog
import android.app.Dialog
import android.content.Context
import android.os.Bundle
import android.text.TextUtils
import android.view.View
import androidx.fragment.app.DialogFragment
import com.yubico.yubikit.demo.R
import kotlinx.android.synthetic.main.password_dialog.view.*

class PasswordDialogFragment : DialogFragment() {
    private var isValidation: Boolean = false
    private var hasPassword: Boolean = false
    private var defaultValue: String? = null
    private var passwordType: PasswordType = PasswordType.PASSWORD

    private var listener: DialogListener? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        arguments?.let {
            isValidation = it.getInt(ARG_VALIDATION) == 1
            hasPassword = it.getInt(HAS_OLD_PASSWORD) == 1
            passwordType = it.getSerializable(ARG_TYPE) as PasswordType
            defaultValue = it.getString(ARG_DEFAULT)
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val alert = AlertDialog.Builder(context)

        val title = when {
            (isValidation) -> R.string.auth_required
            passwordType == PasswordType.PASSWORD -> R.string.set_password
            passwordType == PasswordType.PIN -> R.string.piv_change_pin
            passwordType == PasswordType.PUK -> R.string.piv_change_puk
            passwordType == PasswordType.MGMT_KEY -> R.string.piv_change_mgmt_key
            else -> R.string.set_password
        }
        alert.setTitle(title)

        val input = requireActivity().layoutInflater.inflate(R.layout.password_dialog, null)

        if (isValidation) {
            input.new_password.visibility = View.GONE
        } else if (!hasPassword) {
            input.password.setText("")
            input.password.visibility = View.GONE
        }

        if (!TextUtils.isEmpty(defaultValue)) {
            input.use_default.visibility = View.VISIBLE
            input.use_default.setOnClickListener {
                if (input.use_default.isChecked) {
                    input.password.setText(defaultValue)
                } else {
                    input.password.setText("")
                }
            }
        }

        val passwordHint = when(passwordType) {
            PasswordType.PASSWORD -> "Password"
            PasswordType.PIN -> "PIN"
            PasswordType.PUK -> "PUK"
            PasswordType.MGMT_KEY -> "Management Key"
            PasswordType.UNBLOCK -> "PUK"
        }

        input.password.hint = passwordHint
        input.new_password.hint = if(passwordType == PasswordType.UNBLOCK) "New PIN" else "New $passwordHint"

        alert.setView(input)
        alert.setPositiveButton(android.R.string.ok) { _, _ ->
            val password = input.password.editableText.toString()
            val new_password = input.new_password.editableText.toString()
            if (isValidation) {
                listener?.onPasswordProvided(password, passwordType)
            } else {
                listener?.onPasswordChanged(password, new_password, passwordType)
            }
        }

        alert.setNegativeButton(android.R.string.cancel) {
            dialog, _ -> dialog.cancel()
            listener?.onCancel()
        }
        alert.setOnDismissListener {
            listener?.onCancel()
        }
        return alert.create()
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        val parent = parentFragment
        if (parent != null) {
            listener = parent as DialogListener
        } else {
            listener = context as DialogListener
        }
    }

    override fun onDetach() {
        listener = null
        super.onDetach()
    }

    interface DialogListener {
        fun onPasswordProvided(password: String, passwordType: PasswordType)
        fun onPasswordChanged(password: String, newPassword: String, passwordType: PasswordType)
        fun onCancel()
    }

    companion object {
        const val ARG_VALIDATION = "validation"
        const val HAS_OLD_PASSWORD = "old_password"
        const val ARG_TYPE = "password_type"
        const val ARG_DEFAULT = "default_value"

        @JvmStatic
        fun newInstance(validation: Boolean, hasPassword: Boolean = true, passwordType: PasswordType = PasswordType.PASSWORD, defaultValue: String? = null) =
                PasswordDialogFragment().apply {
                    arguments = Bundle().apply {
                        putInt(ARG_VALIDATION, if(validation) 1 else 0)
                        putInt(HAS_OLD_PASSWORD, if(hasPassword) 1 else 0)
                        putSerializable(ARG_TYPE, passwordType)
                        putString(ARG_DEFAULT, defaultValue ?: "")
                    }
                }
    }

    enum class PasswordType {
        PASSWORD,
        PIN,
        PUK,
        MGMT_KEY,
        UNBLOCK
    }
}