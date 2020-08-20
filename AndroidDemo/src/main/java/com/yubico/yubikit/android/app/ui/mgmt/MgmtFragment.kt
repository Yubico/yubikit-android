package com.yubico.yubikit.android.app.ui.mgmt

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Observer
import com.yubico.yubikit.utils.Interface
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.ui.YubiKeyFragment
import com.yubico.yubikit.mgmt.Application
import com.yubico.yubikit.mgmt.DeviceConfig
import com.yubico.yubikit.mgmt.ManagementApplication
import kotlinx.android.synthetic.main.fragment_mgmt.*

class MgmtFragment : YubiKeyFragment<ManagementApplication, MgmtViewModel>() {
    override val viewModel: MgmtViewModel by activityViewModels()

    private val checkboxIds = mapOf(
            (Interface.USB to Application.Type.OTP) to R.id.checkbox_usb_otp,
            (Interface.USB to Application.Type.U2F) to R.id.checkbox_usb_u2f,
            (Interface.USB to Application.Type.PIV) to R.id.checkbox_usb_piv,
            (Interface.USB to Application.Type.OATH) to R.id.checkbox_usb_oath,
            (Interface.USB to Application.Type.OPGP) to R.id.checkbox_usb_pgp,
            (Interface.USB to Application.Type.FIDO2) to R.id.checkbox_usb_fido2,

            (Interface.NFC to Application.Type.OTP) to R.id.checkbox_nfc_otp,
            (Interface.NFC to Application.Type.U2F) to R.id.checkbox_nfc_u2f,
            (Interface.NFC to Application.Type.PIV) to R.id.checkbox_nfc_piv,
            (Interface.NFC to Application.Type.OATH) to R.id.checkbox_nfc_oath,
            (Interface.NFC to Application.Type.OPGP) to R.id.checkbox_nfc_pgp,
            (Interface.NFC to Application.Type.FIDO2) to R.id.checkbox_nfc_fido2
    )

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_mgmt, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        application_table.visibility = View.GONE
        save.visibility = View.GONE

        viewModel.deviceInfo.observe(viewLifecycleOwner, Observer {
            if (it != null) {
                val config = it.config
                info.text = "Device type: ${it.formFactor.name} \nFirmware: ${it.version} \nSerial: ${it.serial}"
                checkboxIds.forEach { (iface, app), id ->
                    view.findViewById<CheckBox>(id).let { checkbox ->
                        if (it.getSupportedApplications(iface).and(app.value) != 0) {
                            checkbox.isChecked = config.getEnabledApplications(iface).and(app.value) != 0
                            checkbox.visibility = View.VISIBLE
                        } else {
                            checkbox.visibility = View.GONE
                        }
                    }
                }
                application_table.visibility = View.VISIBLE
                save.visibility = View.VISIBLE
                empty_view.visibility = View.GONE
            } else {
                empty_view.visibility = View.VISIBLE
                application_table.visibility = View.GONE
                save.visibility = View.GONE
            }
        })

        save.setOnClickListener {
            viewModel.pendingAction.value = {
                writeDeviceConfig(DeviceConfig.Builder().apply {
                    Interface.values().forEach { iface ->
                        enabledApplications(iface, checkboxIds.filter {
                            it.key.first == iface && view.findViewById<CheckBox>(it.value).isChecked
                        }.map {
                            it.key.second.value  // Application bit
                        }.sum())
                    }
                }.build(), true, null, null)

                "Configuration updated"
            }
        }
    }
}