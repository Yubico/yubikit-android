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

package com.yubico.yubikit.demo.mgmt

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.GridLayout
import android.widget.TextView
import android.widget.Toast
import androidx.lifecycle.*
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.apdu.Version
import com.yubico.yubikit.demo.BaseYubikeyFragment
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.management.ApplicationType
import com.yubico.yubikit.management.DeviceConfiguration
import com.yubico.yubikit.management.TransportType
import kotlinx.android.synthetic.main.fragment_management.*

private const val TAG = "ManagementFragment"
class ManagementFragment : BaseYubikeyFragment(TAG) {

    // this view model can be per fragment because we're not sharing it's data with any other activity or fragment
    private val viewModel: ManagementViewModel by lazy {
        ViewModelProviders.of(this,
                ManagementViewModel.Factory(YubiKitManager(activity!!.applicationContext)))
                .get(ManagementViewModel::class.java)
    }

    /**
     * Mapping between app type and user friendly name of that type
     */
    private val appTypeMap = mapOf(
            ApplicationType.OTP to R.string.interface_otp,
            ApplicationType.CTAP2 to R.string.interface_fido,
            ApplicationType.OATH to R.string.interface_oath,
            ApplicationType.OPGP to R.string.interface_pgp,
            ApplicationType.PIV to R.string.interface_piv,
            ApplicationType.U2F to R.string.interface_u2f
    )

    override fun getViewModel(): YubikeyViewModel {
        return viewModel
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_management, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        viewModel.deviceConfiguration.observe(viewLifecycleOwner, Observer { config ->
            showInterfaceTable(config)
            if (config != null) {
                hideAllSnackBars()
            }
        })

        viewModel.version.observe(viewLifecycleOwner) {
            showFirmwareVersion(it)
        }

        viewModel.updated.observe(viewLifecycleOwner, Observer {
            if (it == true) {
                val config = viewModel.deviceConfiguration.value
                if (config != null) {
                    hideAllSnackBars()
                    if (config.firmwareVersion.major < 5) {
                        Toast.makeText(context, "Config is updated on key, but for version below 5 some settings can't be updated, so please reconnect your YubiKey to see it's state", Toast.LENGTH_LONG).show()
                    } else {
                        // update user that button click was successful
                        Toast.makeText(context, "Config is updated", Toast.LENGTH_LONG).show()
                    }
                }
            }
        })
    }

    override fun onError(throwable: Throwable) {
        when (throwable) {
            is ApduException -> {
                Log.e(TAG, "Status code : ${Integer.toHexString(throwable.statusCode)} ")
                Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
            }
        }
        activity?.invalidateOptionsMenu()
    }

    override fun onUsbSession(hasPermissions: Boolean) {
        if (hasPermissions) {
            viewModel.executeDemoCommands()
        } else {
            viewModel.releaseConfig()
        }
    }

    override fun onNfcSession() {
    }

    override fun onStart() {
        super.onStart()
        showInterfaceTable(viewModel.deviceConfiguration.value)
        showFirmwareVersion(viewModel.version.value)
    }

    /**
     * Populate table of properties from configuration
     */
    private fun showInterfaceTable(config: DeviceConfiguration?) {
        empty_view.visibility = if (config == null) View.VISIBLE else View.GONE
        interface_table.visibility = if (config == null) View.GONE else View.VISIBLE
        info.visibility = if (config == null) View.GONE else View.VISIBLE
        save.isEnabled = config != null
        if (config != null) {
            info.text = "Device type: ${config.formFactor.name} \nFirmaware: ${config.firmwareVersion} \nSerial: ${config.serial}"
            interface_table.removeAllViews()
            addTextView(TransportType.USB)
            addTextView(TransportType.NFC)
            for (appType in ApplicationType.values()) {
                for (transport in TransportType.values()) {
                    if (appTypeMap.containsKey(appType)) {
                        addCheckBox(appType, transport, config)
                    }
                }
            }
        }

        if (config != null) {
            save.setOnClickListener {
                updateConfig(config)
                viewModel.saveConfig(config)
            }
        }
    }

    private fun showFirmwareVersion(version: Version?) {
        version?.run {
            info.visibility = View.VISIBLE
            info.text = "Firmaware: ${this}"
        }
    }

    /**
     * Add textview view to GroupView interface table
     */
    private fun addTextView(transport: TransportType) {
        val textView = TextView(context)
        textView.text = transport.name
        textView.layoutParams = GridLayout.LayoutParams(GridLayout.spec(GridLayout.UNDEFINED, 1f), GridLayout.spec(GridLayout.UNDEFINED, 1f))
        interface_table.addView(textView)
    }

    /**
     * Add checkbox view to GroupView interface table
     */
    private fun addCheckBox(appType: ApplicationType, transport: TransportType, config: DeviceConfiguration) {
        val checkBox = CheckBox(context)
        val textId = appTypeMap[appType]
        if (textId == null) {
            checkBox.text = appType.name
        } else {
            checkBox.setText(textId)
        }
        checkBox.tag = createTag(appType, transport)
        checkBox.isEnabled = config.getSupported(transport, appType)
        checkBox.isChecked = config.getEnabled(transport, appType)
        checkBox.layoutParams = GridLayout.LayoutParams(GridLayout.spec(GridLayout.UNDEFINED, 1f), GridLayout.spec(GridLayout.UNDEFINED, 1f))
        interface_table.addView(checkBox)
    }

    /**
     * Update configurations with values from checkboxes
     */
    private fun updateConfig(config: DeviceConfiguration) {
        for (appType in ApplicationType.values()) {
            for (transport in TransportType.values()) {
                if (appTypeMap.containsKey(appType)) {
                    val checkBox = interface_table.findViewWithTag<CheckBox>(createTag(appType, transport))
                    config.setEnabled(transport, appType, checkBox.isChecked)
                }
            }
        }
    }

    /**
     * Creates some tag that identifies each property
     */
    private fun createTag(appType: ApplicationType, transport: TransportType): String {
        return "$appType : $transport"
    }
}
