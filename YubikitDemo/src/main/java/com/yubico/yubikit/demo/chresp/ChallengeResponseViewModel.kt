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

package com.yubico.yubikit.demo.chresp

import android.os.Build
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.apdu.ApduException
import com.yubico.yubikit.configurator.Slot
import com.yubico.yubikit.configurator.YubiKeyConfigurationApplication
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.transport.YubiKeySession
import com.yubico.yubikit.utils.Logger
import org.apache.commons.codec.DecoderException
import org.apache.commons.codec.binary.Hex
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.lang.IllegalArgumentException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors

class ChallengeResponseViewModel(yubiKitManager: YubiKitManager) : YubikeyViewModel(yubiKitManager) {
    /**
     * Regex for hex string
     */
    private val HEX_PATTERN = "^[0-9a-fA-F]+$"

    /**
     * For execution of communication with yubikey on background
     * Using single thread to avoid thread racing for different commands
     */
    private val executorService = Executors.newSingleThreadExecutor()

    private val _response = MutableLiveData<ByteArray>()
    val response : LiveData<ByteArray> = _response

    private val challengeQueue = ConcurrentLinkedQueue<ByteArray>()


    private val _requireTouch = SingleLiveEvent<Boolean>()
    val requireTouch : LiveData<Boolean> = _requireTouch

    override fun YubiKeySession.executeDemoCommands() {
        executeOnBackgroundThread { application ->
            if (challengeQueue.isEmpty()) {
                _response.postValue(null)
                return@executeOnBackgroundThread
            }
            while (challengeQueue.isNotEmpty()) {
                val challenge = challengeQueue.remove()
                Logger.d("Send challenge")

                // demo tries to get response on challenge using 1st slot, then 2nd slot
                var slot = Slot.ONE
                var response = application.calculateHmacSha1(challenge, slot)
                if (challenge.isNotEmpty() && response.isEmpty()) {
                    slot = Slot.TWO
                    response = application.calculateHmacSha1(challenge, slot)
                }
                _response.postValue(response)
            }
        }
    }

    private fun YubiKeySession.executeOnBackgroundThread(runCommand: (configApplication: YubiKeyConfigurationApplication) -> Unit) {
        executorService.execute {
            val timer = Timer()

            // in case if we don't get response withing 3 second
            // (each calculateHmacSha1 supposed to timeout within 1 sec)
            // we consider YubiKey waits for the touch
            // notify user using UI that touch is required
            timer.schedule(object : TimerTask() {
                override fun run() {
                    _requireTouch.postValue(true)
                }
            }, 3000)


            try {
                Logger.d("Select YubiKey application")
                YubiKeyConfigurationApplication(this).use {
                    // run provided command/operation
                    runCommand(it)
                }
            } catch (e: IOException) {
                postError(e)
            } catch (e: ApduException) {
                postError(e)
            }

            timer.cancel()
        }
    }

    /**
     * Example, of such test for secret f6 d6 47 5b 48 b9 4f 0d 84 9a 6c 19 bf 8c c7 f0 d6 22 55 a0
     * challenge: 313233343637
     * response: 96 af b9 b2 95 6f 76 0f 46 98 57 c0 28 51 52 33 24 08 a0 d5
     */
    fun readResponse(challenge: String) {
        val formattedChallenge = challenge.replace(" ", "");
        when {
            formattedChallenge.isEmpty() -> postError(IllegalArgumentException("Challenge should not be empty"))
            formattedChallenge.matches(HEX_PATTERN.toRegex()) -> try {
                challengeQueue.clear()
                challengeQueue.add(Hex.decodeHex(formattedChallenge))
                executeDemoCommands()
            } catch (e: DecoderException) {
                postError(e)
            }
            else -> postError(UnsupportedEncodingException("Challenge should be HEX-formatted string (byte array)"))
        }
    }


    fun generateChallenge(size: Int): ByteArray {
        val secret = ByteArray(size)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                SecureRandom.getInstanceStrong().nextBytes(secret)
            } catch (e: NoSuchAlgorithmException) {
                SecureRandom().nextBytes(secret)
            }

        } else {
            SecureRandom().nextBytes(secret)
        }
        return secret
    }

    fun resetResponse() {
        _response.value = null
    }


    /**
     * Class factory to create instance of {@link ChallengeResponseViewModel}
     */
    class Factory(private val yubikitManager: YubiKitManager) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return ChallengeResponseViewModel(yubikitManager) as T
        }
    }
}