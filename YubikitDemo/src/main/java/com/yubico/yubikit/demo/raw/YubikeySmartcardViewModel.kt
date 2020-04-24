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

package com.yubico.yubikit.demo.raw

import android.util.Base64
import androidx.lifecycle.LiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.apdu.ApduException

import com.yubico.yubikit.apdu.Apdu
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.exceptions.InvalidCertDataException
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.transport.Iso7816Connection
import com.yubico.yubikit.transport.YubiKeySession
import com.yubico.yubikit.utils.StringUtils
import java.io.IOException
import java.util.concurrent.Executors

private const val TAG = "YubikeyViewModel"
open class YubikeySmartcardViewModel(yubikitManager: YubiKitManager, private val settings: ISettings? = null) : YubikeyViewModel(yubikitManager) {

    private val executorService = Executors.newCachedThreadPool()

    private val _log = SingleLiveEvent<String>()
    val log: LiveData<String> = _log

    /**
     * Execute sequence for APDU commands for specific connection
     */
    override fun YubiKeySession.executeDemoCommands() {
        executorService.execute {
            try {
                openIso7816Connection().use {
                    if (settings != null) {
                        it.setTimeout(settings.connectionTimeout)
                    }
                    // ATR
                    _log.postValue("ATR: " + StringUtils.bytesToHex(it.atr))
                    // read certificate and verify
                    it.checkCertificate()
                }
            } catch (e: IOException) {
                postError(e)
            } catch (e: ApduException) {
                postError(e)
            }
        }
    }

    /**
     * Read certificate and verify
     */
    @Throws(IOException::class, ApduException::class)
    private fun Iso7816Connection.checkCertificate() {
        val selectPIVCommandData = byteArrayOfInts(0xA0, 0x00, 0x00, 0x03, 0x08)

        // 1. Select the PIV application.
        _log.postValue("select the PIV application ")
        transceive(Apdu(0x00, 0xA4, 0x04, 0x00, selectPIVCommandData))

        // 2 Read the certificate stored on the PIV application in slot 9C.
        _log.postValue("reading certificate...")
        val readCommandData = byteArrayOfInts(0x5C, 0x03, 0x5F, 0xC1, 0x0A)
        val readBuffer = transceive(Apdu(0x00, 0xCB, 0x3F, 0xFF, readCommandData))
        if (readBuffer.isEmpty()) {
            throw ApduException("Could not read the certificate from the slot. The slot seems to be empty.")
        }
        _log.postValue("reading certificate successful")

        try {
            // 3 Parse the certificate object.
            val certificate = SecCertificate(readBuffer)

            // 4 Use the certificate to verify a signature.
            // The data which was signed with the private key of the stored certificate.
            val signedString = "yk certificate test"
            val signedStringB64Signature = """
                               XKDV/7sBSYEOEYcTL+C3PErOQ46Ql8y0MJDzh6OT7g3hvI/zi/UfHNls+CRrm8rjE0\
                               UtwqpniBU5lhMQxoICcUemg3c3BZeFl4QaKsuNfcPQ4Q0cPFT35vr5aMwj9EHcLlzS\
                               iYT20lVNpk8m48LBMGu0r8KGTz1GD1lzxxLJe/ZHbkTJTSCrbRBORpq8kGgB33Eukr\
                               7T6eCeobYKQYS7f5Ky8AYtTUbR11vdLAPCsngJaBHnVMabKsBlZ782fqBxaaAPzECR\
                               F5SUpeBpLeqrJ3FYC6m+oyuXG/fpVJQzCHDTIWpXKSvYiebvFQ9OYiBDrN+KCF6n/j\
                               07IDatH/5WnQ==
                               """
            val signatureData = Base64.decode(signedStringB64Signature, Base64.DEFAULT)
            val signedData = signedString.toByteArray(Charsets.UTF_8)
            val signatureIsValid = certificate.verify(signedData, signatureData)
            _log.postValue(if (signatureIsValid) "Signature is valid." else "Signature is not valid.")
        } catch (e: InvalidCertDataException) {
            postError(e)
            return
        }
    }

    /**
     * Convert int array to byte array
     */
    private fun byteArrayOfInts(vararg ints: Int) = ByteArray(ints.size) {
        pos -> ints[pos].toByte()
    }

    /**
     * Class factory to create instance of {@link YubikeySmartcardViewModel}
     */
    class Factory(private val yubikitManager: YubiKitManager, private val setting: ISettings) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return YubikeySmartcardViewModel(yubikitManager, setting) as T
        }
    }
}