package com.yubico.yubikit.android.app.ui.management

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.otp.OtpConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.management.ManagementSession
import com.yubico.yubikit.support.DeviceUtil
import com.yubico.yubikit.support.YubiKeyType
import com.yubico.yubikit.support.YubiKeyUsbProductId
import java.io.IOException

data class ConnectedDeviceInfo(
    val deviceInfo: DeviceInfo,
    val type: YubiKeyType?
)

class ManagementViewModel : YubiKeyViewModel<ManagementSession>() {
    private val _deviceInfo = MutableLiveData<ConnectedDeviceInfo?>()
    val deviceInfo: LiveData<ConnectedDeviceInfo?> = _deviceInfo


    private fun readDeviceInfo(device: YubiKeyDevice) {

        val productId = if (device is UsbYubiKeyDevice) {
            YubiKeyUsbProductId.fromPid(device.usbDevice.productId)
        } else
            null

        val readInfo: (YubiKeyConnection) -> Unit = {
            _deviceInfo.postValue(
                ConnectedDeviceInfo(DeviceUtil.readInfo(it, productId), productId?.type)
            )
        }

        when {
            device.supportsConnection(SmartCardConnection::class.java) -> {
                device.requestConnection(SmartCardConnection::class.java) {
                    readInfo(it.value)
                }
            }
            device.supportsConnection(OtpConnection::class.java) -> {
                device.requestConnection(OtpConnection::class.java) {
                    readInfo(it.value)
                }
            }
            device.supportsConnection(FidoConnection::class.java) -> {
                device.requestConnection(FidoConnection::class.java) {
                    readInfo(it.value)
                }
            }
            else -> throw ApplicationNotAvailableException("Cannot read device info")
        }
    }

    override fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (ManagementSession) -> Unit) {

        try {
            readDeviceInfo(device)
        } catch (ignored: ApplicationNotAvailableException) {
            // cannot read the device info
        }

        ManagementSession.create(device) {
            try {
                callback(it.value)
            } catch (e: ApplicationNotAvailableException) {
                onError(e)
            } catch (e: IOException) {
                onError(e)
            }
        }
    }

    override fun ManagementSession.updateState() {

    }
}