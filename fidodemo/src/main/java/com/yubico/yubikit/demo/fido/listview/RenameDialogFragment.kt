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
import android.content.Context
import android.os.Bundle
import androidx.fragment.app.DialogFragment
import com.yubico.yubikit.demo.fido.R
import kotlinx.android.synthetic.main.dialog_rename.view.*

/**
 * Dialog for rename of authenticator
 */
class RenameDialogFragment : DialogFragment() {
    private lateinit var name: String
    private lateinit var itemid: String

    private var listener: DialogListener? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        arguments?.let {
            name = it.getString(ARG_NAME)!!
            itemid = it.getString(ARG_ID)!!
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val alert = AlertDialog.Builder(context, R.style.AlertDialogTheme)
        alert.setTitle("Rename")

        activity?.let {
            val input = it.layoutInflater.inflate(R.layout.dialog_rename, null)
            input.editText.setText(name)
            alert.setView(input)

            alert.setPositiveButton(android.R.string.ok) { _, _ ->
                val newName = input.editText.editableText.toString()
                listener?.onRename(itemid, newName)
            }
        }

        alert.setNegativeButton(android.R.string.cancel) { dialog, _ -> dialog.cancel() }
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
        fun onRename(itemid: String, newName: String)
    }

    companion object {
        const val ARG_NAME = "arg-name"
        const val ARG_ID = "arg-id"

        @JvmStatic
        fun newInstance(itemid: String, name: String) =
                RenameDialogFragment().apply {
                    arguments = Bundle().apply {
                        putString(ARG_NAME, name)
                        putString(ARG_ID, itemid)
                    }
                }
    }
}