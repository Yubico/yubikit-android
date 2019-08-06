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

package com.yubico.yubikit.demo.fido.listview

import android.app.AlertDialog
import android.app.Dialog
import android.os.Bundle
import android.util.Log
import androidx.fragment.app.DialogFragment
import com.yubico.yubikit.demo.fido.communication.User
import com.yubico.yubikit.fido.AuthenticatorAttachment
import android.content.Context
import android.text.TextUtils
import com.yubico.yubikit.demo.fido.R

/**
 * Dialog fragment that asks user to add authenticator (mandatory or optional)
 */
class AddAuthenticatorDialogFragment : DialogFragment() {

    private lateinit var userData: User
    private lateinit var authenticatorAttachment: AuthenticatorAttachment
    private var dialogText: String? = null
    private var listener: DialogListener? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        arguments?.let {
            userData = it.getSerializable(ARG_USER_DATA) as User
            if (it.containsKey(ARG_ATTACHMENT)) {
                authenticatorAttachment = it.getSerializable(ARG_ATTACHMENT) as AuthenticatorAttachment
            } else {
                authenticatorAttachment = AuthenticatorAttachment.PLATFORM
                dialogText = it.getString(ARG_TEXT)
            }
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        return when(authenticatorAttachment) {
            AuthenticatorAttachment.CROSS_PLATFORM ->
                AlertDialog.Builder(context, R.style.AlertDialogTheme).apply {
                    setTitle(R.string.require_authenticators)
                    setPositiveButton(R.string.retry) { _, _ ->
                        listener?.onAddAuthenticator(authenticatorAttachment)
                    }

                    setNegativeButton(R.string.sign_out) { _, _ ->
                        Log.d(AuthenticatorListFragment.TAG, "alert clicked sign out")
                        listener?.onAddCancel(authenticatorAttachment)
                    }

                    setOnCancelListener {
                        Log.d(AuthenticatorListFragment.TAG, "alert canceled")
                        listener?.onAddCancel(authenticatorAttachment)
                    }
                    setOnDismissListener {
                        Log.d(AuthenticatorListFragment.TAG, "alert dismissed")
                        listener?.onAddCancel(authenticatorAttachment)
                    }
                }.create()
            AuthenticatorAttachment.PLATFORM ->
                AlertDialog.Builder(context, R.style.AlertDialogTheme).apply {
                    setTitle(R.string.require_platform_authenticators_title)
                    if (!TextUtils.isEmpty(dialogText)) {
                        setMessage(dialogText)
                        setPositiveButton(android.R.string.ok) { _, _ ->
                            listener?.onAddCancel(authenticatorAttachment)
                        }
                    } else {
                        setMessage(R.string.require_platform_authenticators)
                        setPositiveButton(android.R.string.ok) { _, _ ->
                            listener?.onAddAuthenticator(authenticatorAttachment)
                        }
                        setNegativeButton(android.R.string.cancel) { dialog, _ -> dialog.cancel() }
                    }
                }.create()
        }
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
        fun onAddAuthenticator(authenticatorAttachment: AuthenticatorAttachment)
        fun onAddCancel(authenticatorAttachment: AuthenticatorAttachment)
    }

    companion object {
        const val ARG_USER_DATA = "user-data"
        const val ARG_ATTACHMENT = "attachment"
        const val ARG_TEXT = "text"

        @JvmStatic
        fun newInstance(userData: User, authenticatorAttachment: AuthenticatorAttachment) =
                AddAuthenticatorDialogFragment().apply {
                    arguments = Bundle().apply {
                        putSerializable(ARG_USER_DATA, userData)
                        putSerializable(ARG_ATTACHMENT, authenticatorAttachment)
                    }
                }

        @JvmStatic
        fun newInstance(userData: User, text: String) =
            AddAuthenticatorDialogFragment().apply {
                arguments = Bundle().apply {
                    putSerializable(ARG_USER_DATA, userData)
                    putString(ARG_TEXT, text)
                }
            }
    }
}