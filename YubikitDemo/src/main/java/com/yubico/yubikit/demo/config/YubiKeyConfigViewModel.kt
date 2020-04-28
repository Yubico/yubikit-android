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

import android.os.Build
import android.os.Bundle
import androidx.lifecycle.LiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.utils.Modhex
import com.yubico.yubikit.configurator.Slot
import com.yubico.yubikit.configurator.UnexpectedSymbolException
import com.yubico.yubikit.configurator.YubiKeyConfigurationApplication
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.exceptions.YubiKeyCommunicationException
import com.yubico.yubikit.transport.YubiKeySession
import com.yubico.yubikit.utils.Logger
import org.apache.commons.codec.DecoderException
import org.apache.commons.codec.binary.Hex
import java.io.IOException
import java.lang.IllegalArgumentException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors

class YubiKeyConfigViewModel(yubiKitManager: YubiKitManager) : YubikeyViewModel(yubiKitManager) {
    /**
     * For execution of communication with yubikey on background
     * Using single thread to avoid thread racing for different commands
     */
    private val executorService = Executors.newSingleThreadExecutor()

    private val _success = SingleLiveEvent<Boolean>()
    val success : LiveData<Boolean> = _success

    private val programmingQueue = ConcurrentLinkedQueue<Bundle>()

    @Throws(IOException::class, ApduException::class, UnexpectedSymbolException::class)
    override fun YubiKeySession.executeDemoCommands() {
        executeOnBackgroundThread { application ->
            _success.postValue(false)
            while (programmingQueue.isNotEmpty()) {
                val operation = programmingQueue.remove()
                val type = operation.getSerializable(OPERATION_TYPE) as SecretType
                val slot = operation.getSerializable(SLOT) as Slot?
                when(type) {
                    SecretType.OTP -> application.setOtpKey(operation.getByteArray(PUBLIC_ID),
                            operation.getByteArray(PRIVATE_ID), operation.getByteArray(SECRET), slot)
                    SecretType.STATIC_PASSWORD -> application.setStaticPassword(operation.getString(SECRET), slot)
                    SecretType.CHALRESP -> application.setHmacSha1ChallengeResponseSecret(operation.getByteArray(SECRET),
                            slot, operation.getBoolean(REQUIRE_TOUCH, false))
                    SecretType.HOTP -> application.setHotpKey(operation.getByteArray(SECRET),
                            slot, false)
                    SecretType.SWAP -> application.swapSlots()
                }
                _success.postValue(true)
            }
        }
    }

    private fun YubiKeySession.executeOnBackgroundThread(runCommand: (configApplication: YubiKeyConfigurationApplication) -> Unit) {
        executorService.execute {
            try {
                Logger.d("Select YubiKey application")
                YubiKeyConfigurationApplication(this).use {
                    // run provided command/operation
                    runCommand(it)
                }
            } catch (e: IOException) {
                postError(e)
            } catch (e: YubiKeyCommunicationException) {
                postError(e)
            }
        }
    }

    fun setSecret(slot: Slot, type: SecretType, secret: String, privateId: String = "", publicId: String = "", requireTouch: Boolean = false) {
        val operation = Bundle()
        val formattedSecret = secret.replace(" ", "")
        if (formattedSecret.isEmpty()) {
            postError(IllegalArgumentException("secret is empty"))
            return
        }

        try {
            when(type) {
                SecretType.STATIC_PASSWORD -> {
                    operation.putString(SECRET, secret)
                }
                else -> {
                    val encodedSecret = Hex.decodeHex(formattedSecret)
                    operation.putByteArray(SECRET, encodedSecret)
                }
            }

            operation.putSerializable(OPERATION_TYPE, type)
            operation.putByteArray(PRIVATE_ID, Hex.decodeHex(privateId))
            operation.putByteArray(PUBLIC_ID, Modhex.decode(publicId))
            operation.putSerializable(SLOT, slot)
            operation.putBoolean(REQUIRE_TOUCH, requireTouch)


            programmingQueue.add(operation)
            executeDemoCommands()
        } catch (e: DecoderException) {
            postError(e)
        }
    }


    fun swapSlots() {
        programmingQueue.add(Bundle().apply { putSerializable(OPERATION_TYPE, SecretType.SWAP) })
        executeDemoCommands()
    }

    fun generateRandomHexString(sizeInBytes: Int): String = Hex.encodeHexString(generateRandomBytes(sizeInBytes))

    fun generateRandomModhexString(sizeInBytes: Int) : String = Modhex.encode(generateRandomBytes(sizeInBytes))

    private fun generateRandomBytes(size: Int): ByteArray {
        val randomByteArray = ByteArray(size)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                SecureRandom.getInstanceStrong().nextBytes(randomByteArray)
            } catch (e: NoSuchAlgorithmException) {
                SecureRandom().nextBytes(randomByteArray)
            }

        } else {
            SecureRandom().nextBytes(randomByteArray)
        }

        return randomByteArray;
    }

    /**
     * Class factory to create instance of {@link OathViewModel}
     */
    class Factory(private val yubikitManager: YubiKitManager) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return YubiKeyConfigViewModel(yubikitManager) as T
        }
    }

    enum class SecretType {
        OTP,
        STATIC_PASSWORD,
        CHALRESP,
        HOTP,
        SWAP
    }

    companion object {
        private const val OPERATION_TYPE = "operationType"
        private const val SECRET = "secret"
        private const val PRIVATE_ID = "uid"
        private const val PUBLIC_ID = "fixed"
        private const val SLOT = "slot"
        private const val REQUIRE_TOUCH = "requireTouch"
    }

}
