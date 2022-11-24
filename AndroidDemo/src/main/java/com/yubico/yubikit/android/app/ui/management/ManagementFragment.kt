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

package com.yubico.yubikit.android.app.ui.management

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import androidx.fragment.app.activityViewModels
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.databinding.FragmentManagementBinding
import com.yubico.yubikit.android.app.ui.YubiKeyFragment
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.management.DeviceConfig
import com.yubico.yubikit.management.ManagementSession
import com.yubico.yubikit.support.DeviceUtil

class ManagementFragment : YubiKeyFragment<ManagementSession, ManagementViewModel>() {
    override val viewModel: ManagementViewModel by activityViewModels()

    private lateinit var binding: FragmentManagementBinding

    private val checkboxIds = mapOf(
            (Transport.USB to Capability.OTP) to R.id.checkbox_usb_otp,
            (Transport.USB to Capability.U2F) to R.id.checkbox_usb_u2f,
            (Transport.USB to Capability.PIV) to R.id.checkbox_usb_piv,
            (Transport.USB to Capability.OATH) to R.id.checkbox_usb_oath,
            (Transport.USB to Capability.OPENPGP) to R.id.checkbox_usb_pgp,
            (Transport.USB to Capability.FIDO2) to R.id.checkbox_usb_fido2,

            (Transport.NFC to Capability.OTP) to R.id.checkbox_nfc_otp,
            (Transport.NFC to Capability.U2F) to R.id.checkbox_nfc_u2f,
            (Transport.NFC to Capability.PIV) to R.id.checkbox_nfc_piv,
            (Transport.NFC to Capability.OATH) to R.id.checkbox_nfc_oath,
            (Transport.NFC to Capability.OPENPGP) to R.id.checkbox_nfc_pgp,
            (Transport.NFC to Capability.FIDO2) to R.id.checkbox_nfc_fido2
    )

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View {
        binding = FragmentManagementBinding.inflate(inflater, container, false)
        return binding.root
    }

    @SuppressLint("SetTextI18n")
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.applicationTable.visibility = View.GONE
        binding.save.visibility = View.GONE

        viewModel.deviceInfo.observe(viewLifecycleOwner) {
            if (it != null) {
                val info = it.deviceInfo
                val keyType = it.type
                binding.info.text = "Device: ${DeviceUtil.getName(info, keyType)}\n" +
                        "Device form factor: ${info.formFactor.name}\n" +
                        "Firmware: ${info.version}\n" +
                        "Serial: ${info.serialNumber}\n" +
                        "FIPS: ${info.isFips}\n" +
                        "SKY: ${info.isSky}\n" +
                        "Locked: ${info.isLocked}\n" +
                        "Auto eject timeout: ${info.config.autoEjectTimeout}\n" +
                        "Challenge response timeout: ${info.config.challengeResponseTimeout}\n" +
                        "ATR: ${it.atr}"
                checkboxIds.forEach { (transport, capability), id ->
                    view.findViewById<CheckBox>(id).let { checkbox ->
                        if (info.getSupportedCapabilities(transport) and capability.bit != 0) {
                            checkbox.isChecked = (info.config.getEnabledCapabilities(transport)
                                ?: 0) and capability.bit != 0
                            checkbox.visibility = View.VISIBLE
                        } else {
                            checkbox.visibility = View.GONE
                        }
                    }
                }
                binding.applicationTable.visibility = View.VISIBLE
                binding.save.visibility = View.VISIBLE
                binding.emptyView.visibility = View.GONE
            } else {
                binding.emptyView.visibility = View.VISIBLE
                binding.applicationTable.visibility = View.GONE
                binding.save.visibility = View.GONE
            }
        }

        binding.save.setOnClickListener {
            viewModel.pendingAction.value = {
                updateDeviceConfig(DeviceConfig.Builder().apply {
                    Transport.values().forEach { transport ->
                        enabledCapabilities(transport, checkboxIds.filter {
                            it.key.first == transport && view.findViewById<CheckBox>(it.value).isChecked
                        }.map {
                            it.key.second.bit  // Capability bit
                        }.sum())
                    }
                }.build(), true, null, null)

                "Configuration updated"
            }
        }
    }
}