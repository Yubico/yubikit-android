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

package com.yubico.yubikit.demo.piv

import android.app.AlertDialog
import android.app.Dialog
import android.content.Context
import android.os.Bundle
import android.text.TextUtils
import android.view.View
import android.widget.Toast
import androidx.fragment.app.DialogFragment
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.settings.Ramps
import kotlinx.android.synthetic.main.pin_retries_dialog.view.*
import java.lang.NumberFormatException

class RetriesDialogFragment : DialogFragment() {
    private lateinit var defaultValue: String
    private var listener: DialogListener? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        defaultValue = arguments?.getString(ARG_DEFAULT) ?: ""
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val alert = AlertDialog.Builder(context)

        alert.setTitle(R.string.piv_pin_set_retries)

        val input = activity!!.layoutInflater.inflate(R.layout.pin_retries_dialog, null)

        if (!TextUtils.isEmpty(defaultValue)) {
            input.use_default.visibility = View.VISIBLE
            input.use_default.setOnClickListener {
                if (input.use_default.isChecked) {
                    input.pin.setText(defaultValue)
                    input.retries_pin.setText(Ramps.PIV_NUM_RETRIES.getValue(context).toString())
                    input.retries_puk.setText(Ramps.PIV_NUM_RETRIES.getValue(context).toString())
                } else {
                    input.pin.setText("")
                    input.retries_pin.setText("")
                    input.retries_puk.setText("")
                }
            }
        }

        alert.setView(input)
        alert.setPositiveButton(android.R.string.ok) { _, _ ->
            val pin = input.pin.editableText.toString()
            try {
                val pinRetries = Integer.parseInt(input.retries_pin.editableText.toString())
                val pukRetries = Integer.parseInt(input.retries_puk.editableText.toString())
                listener?.onPinProvided(pin, pinRetries, pukRetries)
            } catch (e: NumberFormatException) {
                Toast.makeText(input.context, "Invalid number input", Toast.LENGTH_LONG).show()
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
        fun onPinProvided(pin: String, pinRetries: Int, pukRetries: Int)
        fun onCancel()
    }

    companion object {
        const val ARG_DEFAULT = "default_value"

        @JvmStatic
        fun newInstance(defaultValue: String) =
                RetriesDialogFragment().apply {
                    arguments = Bundle().apply {
                        putString(ARG_DEFAULT, defaultValue)
                    }
                }
    }
}
