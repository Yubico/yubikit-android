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

package com.yubico.yubikit.demo.config

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.Toast
import androidx.lifecycle.*
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.configurator.Slot
import com.yubico.yubikit.demo.BaseYubikeyFragment
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.YubikeyViewModel
import kotlinx.android.synthetic.main.fragment_configuration.*

private const val TAG = "ConfigureOtpFragment"
class ConfigureOtpFragment : BaseYubikeyFragment(TAG) {

    // this view model can be per fragment because we're not sharing it's data with any other activity or fragment
    private val viewModel: YubiKeyConfigViewModel by lazy {
        ViewModelProviders.of(this,
                YubiKeyConfigViewModel.Factory(YubiKitManager(requireActivity().applicationContext)))
                .get(YubiKeyConfigViewModel::class.java)
    }

    override fun getViewModel(): YubikeyViewModel {
        return viewModel
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_configuration, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        showProgress(false)


        generate.setOnClickListener {
            val index = config_type.selectedItemPosition
            val size = if(index == 1) 20 else 16
            secret.setText(viewModel.generateRandomHexString(size))
        }

        generate_public.setOnClickListener {
            publicid.setText(viewModel.generateRandomModhexString(6))
        }

        generate_private.setOnClickListener {
            privateid.setText(viewModel.generateRandomHexString(6))
        }

        config_type.onItemSelectedListener = object : AdapterView.OnItemSelectedListener{
            override fun onNothingSelected(parent: AdapterView<*>?) {

            }

            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                require_touch.visibility = if (position == 1) View.VISIBLE else View.GONE
                privateid_wrapper.visibility = if (position == 0) View.VISIBLE else View.GONE
                publicid_wrapper.visibility = if (position == 0) View.VISIBLE else View.GONE
                if (config_type.selectedItemPosition != position) {
                    secret.setText("")
                }
            }
        }

        swap_slots.setOnClickListener {
            viewModel.swapSlots()
        }

        start_demo.setOnClickListener {
            if (hasConnection) {
                showProgress(true)
            }

            val type = when(config_type.selectedItemPosition) {
                0 -> YubiKeyConfigViewModel.SecretType.OTP
                1 -> YubiKeyConfigViewModel.SecretType.CHALRESP
                else -> YubiKeyConfigViewModel.SecretType.HOTP
            }
            val slot = when(config_slot.selectedItemPosition) {
                0 -> Slot.ONE
                else -> Slot.TWO
            }
            viewModel.setSecret(slot, type, secret.text.toString(), privateid.text.toString(), publicid.text.toString(), require_touch.isChecked)
        }

        viewModel.success.observe(viewLifecycleOwner, Observer {
            if (it == true) {
                showProgress(false)
                Toast.makeText(context, R.string.configure_success, Toast.LENGTH_LONG).show()
            }
        })
    }

    override fun onError(throwable: Throwable) {
        showProgress(false)
        when (throwable) {
            is ApduException -> {
                Log.e(TAG, "Status code : ${Integer.toHexString(throwable.statusCode)} ")
                Toast.makeText(activity, throwable.message, Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(activity, throwable.message ?: "No connection" , Toast.LENGTH_LONG).show()
            }
        }
        activity?.invalidateOptionsMenu()
    }

    override fun onUsbSession(hasPermissions: Boolean) {
        // do not run demo unless user pressed button
    }

    override fun onNfcSession() {
        showProgress(true)
    }

    private fun showProgress(visible: Boolean) {
        progressBar.visibility = if (visible) View.VISIBLE else View.GONE
        hideAllSnackBars()
    }
}
