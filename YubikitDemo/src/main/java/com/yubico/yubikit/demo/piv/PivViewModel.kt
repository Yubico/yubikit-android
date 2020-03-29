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

import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.SparseArray
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.apdu.ApduCodeException
import com.yubico.yubikit.apdu.ApduException
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.exceptions.InvalidCertDataException
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.demo.oath.AuthRequiredException
import com.yubico.yubikit.demo.oath.PasswordDialogFragment
import com.yubico.yubikit.demo.oath.WrongPasswordException
import com.yubico.yubikit.demo.raw.ISettings
import com.yubico.yubikit.exceptions.NotSupportedOperation
import com.yubico.yubikit.piv.*
import com.yubico.yubikit.transport.YubiKeySession
import com.yubico.yubikit.utils.Logger
import com.yubico.yubikit.utils.StringUtils
import org.apache.commons.codec.binary.Hex
import java.io.*
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.cert.CertificateEncodingException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors

private const val OPERATION_ID = "operationId"
private const val PASSWORD = "password"
private const val NEW_PASSWORD = "new_password"

private const val SLOT_ID = "slot"
private const val ALGO = "algorithm"
private const val DATA = "data"
const val DEFAULT_AUTH_KEY = "010203040506070801020304050607080102030405060708"
const val DEFAULT_PIN = "123456"
const val DEFAULT_PUK = "12345678"

class PivViewModel(yubiKitManager: YubiKitManager, private val settings: ISettings? = null) : YubikeyViewModel(yubiKitManager) {

    /**
     * List of slots that we will show on demo UI
     */
    private val slots = listOf(Slot.AUTHENTICATION, Slot.SIGNATURE, Slot.KEY_MANAGEMENT, Slot.CARD_AUTH)

    /**
     * For execution of communication with yubikey on background
     * Using single thread to avoid thread racing for different commands
     */
    private val executorService = Executors.newSingleThreadExecutor()

    /**
     * This is queue of requests that need to be executed on key
     * Helps to execute operations if they require authentication or yubikey to be plugged in or tapped over NFC
     */
    private val requestQueue = ConcurrentLinkedQueue<Bundle>()

    /**
     * Map of credentials and codes received from keys (can be populated from multiple keys)
     */
    private val _certificates = MutableLiveData<SparseArray<X509Certificate>>()
    val certificates: LiveData<SparseArray<X509Certificate>> = _certificates

    private val _operationStarted = SingleLiveEvent<String>()
    val operationStarted: LiveData<String> = _operationStarted

    private val _operationCompleted = SingleLiveEvent<String>()
    val operationCompleted: LiveData<String> = _operationCompleted

    private val _requireAuth = SingleLiveEvent<PasswordDialogFragment.PasswordType>()
    val requireAuth: LiveData<PasswordDialogFragment.PasswordType> = _requireAuth

    override fun YubiKeySession.executeDemoCommands() {
        // executes operations on background thread after connect() and atr and select() commands been sent
        executeOnBackgroundThread { pivApplication ->
            while (requestQueue.isNotEmpty()) {
                val request = getRequestFromQueue()
                // empty bundle means no pending requests - nothing to execute
                request ?: return@executeOnBackgroundThread

                // execute operation from queue
                val pendingOperation = request.getSerializable(OPERATION_ID) as Operations
                try {
                    when (pendingOperation) {
                        Operations.AUTHENTICATE -> {
                            Logger.d("Authenticate with management key")
                            val password = request.getString(PASSWORD)
                            try {
                                pivApplication.authenticate(Hex.decodeHex(password))
                            } catch (e: ApduException) {
                                Logger.e("Authentication failed", e)
                                // if we couldn't validate password we remove all requests
                                // user will have to request new operation (import, generate, etc)
                                requestQueue.clear()
                                postError(WrongPasswordException("Authentication failed"))
                            }
                        }
                        Operations.VERIFY -> {
                            Logger.d("Verify pin")
                            try {
                                pivApplication.verify(request.getString(PASSWORD))
                            } catch (e: InvalidPinException) {
                                Logger.e("Authentication failed", e)
                                // if we couldn't validate pin we remove all requests
                                // user will have to request new sign operation
                                requestQueue.clear()
                                postError(e)
                            }
                        }
                        Operations.READ_ALL_CERTIFICATES -> {
                            _operationStarted.postValue("Reading certificates")
                            var counter = 0
                            val certificateList = SparseArray<X509Certificate>()
                            for (slot in slots) {
                                try {
                                    val certificate = pivApplication.getCertificate(slot)
                                    if (certificate != null) {
                                        counter++
                                    }
                                    certificateList.put(slot.value, certificate)
                                } catch (e: ApduCodeException) {
                                    // file not found error means that certificate is not found
                                    if (PivApplication.FILE_NOT_FOUND_ERROR.toInt() != e.statusCode) {
                                        throw e
                                    }
                                }
                            }
                            _operationCompleted.postValue("Found $counter certificates")
                            _certificates.postValue(certificateList)
                        }
                        Operations.ATTEST -> {
                            _operationStarted.postValue("Getting certificate signed by the key in slot f9")
                            val certificate = pivApplication.attest(request.getSerializable(SLOT_ID) as Slot)
                            _operationCompleted.postValue("Received certificate ${certificate.subjectDN} issued by ${certificate.issuerDN}")
                        }
                        Operations.SIGN -> {
                            _operationStarted.postValue("Signing message")
                            val data = request.getString(DATA)!!.toByteArray(StandardCharsets.UTF_8)
                            val slot = request.getSerializable(SLOT_ID) as Slot
                            val algorithm = request.getSerializable(ALGO) as Algorithm
                            val signature = pivApplication.sign(slot, algorithm, data)
                            val certificate = _certificates.value?.get(slot.value)
                            if(certificate != null) {
                                val signatureIsValid = verifySignature(data, signature, certificate)
                                Logger.d(if (signatureIsValid) "Signature is valid. " else "Signature is not valid. ")
                            }
                            _operationCompleted.postValue("Signature: " + Base64.encodeToString(signature, Base64.DEFAULT))
                        }
                        Operations.CHANGE_PIN -> {
                            _operationStarted.postValue("Changing pin")
                            pivApplication.changePin(request.getString(PASSWORD), request.getString(NEW_PASSWORD))
                            _operationCompleted.postValue("Pin has been changed")
                        }
                        Operations.CHANGE_PUK -> {
                            _operationStarted.postValue("Changing puk")
                            pivApplication.changePuk(request.getString(PASSWORD), request.getString(NEW_PASSWORD))
                            _operationCompleted.postValue("Puk has been changed")
                        }
                        Operations.CHANGE_MANAGEMENT_KEY -> {
                            _operationStarted.postValue("Setting management key")
                            pivApplication.authenticate(Hex.decodeHex(request.getString(PASSWORD)))
                            pivApplication.setManagementKey(Hex.decodeHex(request.getString(NEW_PASSWORD)))
                            _operationCompleted.postValue("Management key is set")
                        }
                        Operations.CHANGE_RETRIES -> {
                            _operationStarted.postValue("Changing retries")
                            pivApplication.setPinRetries(request.getInt(PASSWORD), request.getInt(NEW_PASSWORD))
                            _operationCompleted.postValue("Retries set to ${request.getInt(PASSWORD)}")
                        }
                        Operations.UNBLOCK_PIN -> {
                            _operationStarted.postValue("Unblocking pin")
                            pivApplication.unblockPin(request.getString(PASSWORD), request.getString(NEW_PASSWORD))
                            _operationCompleted.postValue("Pin has been set")
                        }
                        Operations.GENERATE_KEY -> {
                            _operationStarted.postValue("Generating key pair")
                            val algorithm = request.getSerializable(ALGO) as Algorithm
                            val key = pivApplication.generateKey(request.getSerializable(SLOT_ID) as Slot,
                                    algorithm,
                                    PinPolicy.DEFAULT, TouchPolicy.DEFAULT)
                            _operationCompleted.postValue("Generated on YubiKey ${algorithm.name} public key: " + StringUtils.convertBytesToString(key.encoded))
                        }
                        Operations.IMPORT_KEY -> {
                            _operationStarted.postValue("Importing key")
                            val algorithm = pivApplication.importKey(request.getSerializable(SLOT_ID) as Slot,
                                    request.getSerializable(DATA) as PrivateKey,
                                    PinPolicy.DEFAULT, TouchPolicy.DEFAULT)
                            _operationCompleted.postValue("Imported key for algorithm ${algorithm.name}")
                        }
                        Operations.IMPORT_CERT -> {
                            _operationStarted.postValue("Importing certificate")
                            val slot = request.getSerializable(SLOT_ID) as Slot
                            val cert = readCertificateFromFile(request.getString(DATA)!!)
                            pivApplication.putCertificate(slot, cert)

                            // update UI with new cert
                            val certificateList = _certificates.value ?: SparseArray()
                            certificateList.put(slot.value, pivApplication.getCertificate(slot))
                            _certificates.postValue(certificateList)
                            _operationCompleted.postValue("Certificate is imported")
                        }
                        Operations.DELETE_CERT -> {
                            _operationStarted.postValue("Deleting certificate")
                            val slot = request.getSerializable(SLOT_ID) as Slot
                            pivApplication.deleteCertificate(slot)
                            // notify UI about change
                            val certificateList = _certificates.value ?: SparseArray()
                            certificateList.delete(slot.value)
                            _certificates.postValue(certificateList)
                            _operationCompleted.postValue("Certificate is deleted")
                        }
                        Operations.RESET -> {
                            _operationStarted.postValue("Resetting piv application")
                            pivApplication.reset()
                            val certificateList = _certificates.value ?: SparseArray()
                            certificateList.clear()
                            _certificates.postValue(certificateList)
                            _operationCompleted.postValue("PIV application has been reset")
                        }
                    }
                } catch (e : ApduCodeException) {
                    // if user required to input password notify user about error and stop executing requests
                    // and do not remove from queue as they will be executed after validation
                    if (e.statusCode == PivApplication.AUTHENTICATION_REQUIRED_ERROR.toInt()) {
                        // note: for sign/general authenticate operation pin would be required
                        // currently sign is not implemented
                        postError(AuthRequiredException("Authentication is required for operations on that device",
                                if (pendingOperation == Operations.SIGN) PasswordDialogFragment.PasswordType.PIN else PasswordDialogFragment.PasswordType.MGMT_KEY))
                        break
                    }

                    postError(e)
                } catch (e : ApduException) {
                    postError(e)
                } catch (e : IOException) {
                    postError(e)
                }
                // removing successfully completed or failed request from queue
                requestQueue.remove(request)
            }
        }
    }

    private fun YubiKeySession.executeOnBackgroundThread(runCommand: (pivApplication: PivApplication) -> Unit) {
        executorService.execute {
            if (requestQueue.isEmpty()) {
                // if we've got no pending requests, refresh codes by default
                requestQueue.add(Bundle().apply { putSerializable(OPERATION_ID, Operations.READ_ALL_CERTIFICATES) })
            }

            try {
                Logger.d("Select PIV application")
                PivApplication(this).use {
                    if (settings != null) {
                        it.connection.setTimeout(settings.connectionTimeout)
                    }
                    // run provided command/operation (put/calculate/delete/etc)
                    runCommand(it)
                }
            } catch (e: IOException) {
                postError(e)
            } catch (e: ApduException) {
                postError(e)
            }
        }
    }

    fun generateKey(slot: Slot, algo: Algorithm) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.GENERATE_KEY)
            putSerializable(SLOT_ID, slot)
            putSerializable(ALGO, algo)
        })
        _requireAuth.value = PasswordDialogFragment.PasswordType.MGMT_KEY
    }

    fun importKey(slot: Slot, key: PrivateKey) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.IMPORT_KEY)
            putSerializable(SLOT_ID, slot)
            putSerializable(DATA, key)
        })
        _requireAuth.value = PasswordDialogFragment.PasswordType.MGMT_KEY
    }

    fun importCertificate(slot: Slot, filename: String) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            postError(NotSupportedOperation("Method supported on Android 8+"))
        }
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.IMPORT_CERT)
            putSerializable(SLOT_ID, slot)
            putString(DATA, filename)
        })
        _requireAuth.value = PasswordDialogFragment.PasswordType.MGMT_KEY
    }

    fun exportCertificate(slot: Slot, fileName: String) {
        val certificate = certificates.value?.get(slot.value)
        if (certificate == null) {
            postError(NotSupportedOperation("No certificates loaded on that slot"))
        } else {
            try {
                File(fileName).writeBytes(certificate.encoded)
                _operationCompleted.value = "Certificate exported to $fileName"
            } catch (e: IOException) {
                postError(e)
            } catch (e: CertificateEncodingException) {
                postError(e)
            }
        }
    }

    fun authenticate(mgmtKey: String) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.AUTHENTICATE)
            putString(PASSWORD, mgmtKey)
        })
        executeDemoCommands()
    }

    fun verify(pin: String) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.VERIFY)
            putString(PASSWORD, pin)
        })
        executeDemoCommands()

    }

    fun attest(slot: Slot) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.ATTEST)
            putSerializable(SLOT_ID, slot)
        })
        executeDemoCommands()
    }

    fun sign(slot: Slot, algo: Algorithm, message: String) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.SIGN)
            putSerializable(ALGO, algo)
            putSerializable(SLOT_ID, slot)
            putString(DATA, message)
        })
        _requireAuth.value = PasswordDialogFragment.PasswordType.PIN
    }

    fun deleteCertificate(slot: Slot) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.DELETE_CERT)
            putSerializable(SLOT_ID, slot)
        })
        _requireAuth.value = PasswordDialogFragment.PasswordType.MGMT_KEY
    }

    /**
     * Changes pin, puk or management key
     */
    fun changePassword(oldPassword: String, newPassword: String, passwordType: PasswordDialogFragment.PasswordType) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, when(passwordType) {
                PasswordDialogFragment.PasswordType.PIN -> Operations.CHANGE_PIN
                PasswordDialogFragment.PasswordType.PUK -> Operations.CHANGE_PUK
                else -> Operations.CHANGE_MANAGEMENT_KEY
            })
            putString(PASSWORD, oldPassword)
            putString(NEW_PASSWORD, newPassword)
        })
        executeDemoCommands()
    }

    fun changeRetries(pin: String, retries_pin: Int, retries_puk: Int) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.VERIFY)
            putString(PASSWORD, pin)
        })
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.CHANGE_RETRIES)
            putInt(PASSWORD, retries_pin)
            putInt(NEW_PASSWORD, retries_puk)
        })
        _requireAuth.value = PasswordDialogFragment.PasswordType.MGMT_KEY
    }

    fun unblockPin(puk: String, pin: String) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.UNBLOCK_PIN)
            putString(PASSWORD, puk)
            putString(NEW_PASSWORD, pin)
        })
        executeDemoCommands()
    }

    /**
     * Resets oath application (resets password and removes all credentials)
     */
    fun reset() {
        // if user is doing factory reset all previous requests can be dismissed
        requestQueue.clear()
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.RESET)
        })
        executeDemoCommands()
    }

    /**
     * Helper method to verify that signature is authentic (provided using key pair within Certificate)
     */
    private fun verifySignature(data: ByteArray, signature: ByteArray, certificate: X509Certificate) : Boolean {
        try {
            val privateSignature = Signature.getInstance(certificate.sigAlgName)
            privateSignature.initVerify(certificate)
            privateSignature.update(data)
            return privateSignature.verify(signature)
        } catch (e: NoSuchAlgorithmException) {
            throw InvalidCertDataException("Cert algorithm " + certificate.sigAlgName + " is not valid", e)
        } catch (e: InvalidKeyException) {
            throw InvalidCertDataException("Cert key " + StringUtils.convertBytesToString(certificate.publicKey.encoded) + " is not valid", e)
        } catch (e: SignatureException) {
            throw InvalidCertDataException("Signature " + StringUtils.convertBytesToString(signature) + " is not valid", e)
        }
    }

    /**
     * Reads certificate from file
     */
    private fun readCertificateFromFile(fileName: String): X509Certificate {
        try {
            FileInputStream(fileName).use { inStream ->
                val cf = CertificateFactory.getInstance("X.509")
                return cf.generateCertificate(inStream) as X509Certificate
            }
        } catch (e: CertificateException) {
            throw IOException("Failed to read cert from file $fileName", e)
        }
    }

    /**
     * Returns request from queue
     * If it contains validation/authentication request - gets that one as it has higher priority
     */
    private fun getRequestFromQueue() : Bundle? {
        val validationRequest = requestQueue.filter {
            val operation = it.getSerializable(OPERATION_ID) as Operations
            Operations.AUTHENTICATE == operation ||
            Operations.VERIFY == operation
        }
        var request: Bundle?
        request = if (!validationRequest.isEmpty()) {
            // if we need to authenticate we start with that operation
            validationRequest.first()
        } else {
            requestQueue.peek()
        }
        return request
    }

    fun clearTasks() {
        requestQueue.clear()
    }

    enum class Operations {
        AUTHENTICATE,
        VERIFY,
        READ_ALL_CERTIFICATES,
        IMPORT_KEY,
        GENERATE_KEY,
        DELETE_CERT,
        IMPORT_CERT,
        ATTEST,
        SIGN,
        CHANGE_PIN,
        CHANGE_PUK,
        CHANGE_MANAGEMENT_KEY,
        CHANGE_RETRIES,
        UNBLOCK_PIN,
        RESET
    }

    /**
     * Class factory to create instance of {@link PivViewModel}
     */
    class Factory(private val yubikitManager: YubiKitManager, private val settings: ISettings? = null) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return PivViewModel(yubikitManager, settings) as T
        }
    }

}