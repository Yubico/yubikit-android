/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.android

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.core.view.WindowCompat
import androidx.lifecycle.coroutineScope
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.fido.android.YubiKitFidoActivity.Companion.toMap
import com.yubico.yubikit.fido.android.ui.components.NfcUsageGuide
import com.yubico.yubikit.fido.android.ui.screens.FidoClientUi
import com.yubico.yubikit.fido.android.ui.theme.FidoAndroidTheme
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import com.yubico.yubikit.fido.webauthn.SerializationType
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

class FidoClientService(private val viewModel: MainViewModel = MainViewModel()) {

    enum class Operation {
        MAKE_CREDENTIAL,
        GET_ASSERTION
    }

    suspend fun performOperation(
        pin: String?,
        operation: Operation,
        rpId: String,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit
    ): Result<PublicKeyCredential> {
        return when (operation) {
            Operation.MAKE_CREDENTIAL -> makeCredential(
                pin,
                rpId,
                clientDataHash,
                request,
                onConnection
            )

            Operation.GET_ASSERTION -> getAssertion(
                pin,
                rpId,
                clientDataHash,
                request,
                onConnection
            )
        }
    }

    suspend fun waitForKeyRemoval() {
        viewModel.waitForKeyRemoval()
    }

    private fun buildClientData(
        type: String, origin: String, challenge: String
    ): ByteArray {
        return """
            {
                "type": "$type",
                "challenge": "$challenge",
                "origin": "$origin"
            }
        """.trimIndent().toByteArray()
    }

    private suspend fun makeCredential(
        pin: String?,
        rpId: String,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit
    ): Result<PublicKeyCredential> =
        viewModel.useWebAuthn { client ->
            onConnection()
            if (pin == null && client.isPinSupported && client.isPinConfigured) {
                /* TODO get remaining attempts or information about PIN blocked state and return
                   the most appropriate error
                 */
                throw PinRequiredClientError()
            }

            val requestJson = JSONObject(request).toMap()

            val publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions.fromMap(
                JSONObject(request).toMap()
            )

            if (clientDataHash != null) {
                client.makeCredentialWithHash(
                    clientDataHash,
                    publicKeyCredentialCreationOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    null,
                    null
                )
            } else {
                client.makeCredential(
                    buildClientData(
                        "webauthn.create",
                        rpId,
                        requestJson["challenge"] as String
                    ),
                    publicKeyCredentialCreationOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    null,
                    null
                )
            }
        }

    private suspend fun getAssertion(
        pin: String?,
        rpId: String,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit
    ): Result<PublicKeyCredential> =
        viewModel.useWebAuthn { client ->
            onConnection()
            if (pin == null && client.isPinSupported && client.isPinConfigured) {
                /* TODO get remaining attempts or information about PIN blocked state and return
                   the most appropriate error
                 */
                throw PinRequiredClientError()
            }

            val requestJson = JSONObject(request).toMap()

            val clientData = buildClientData(
                "webauthn.get",
                rpId,
                requestJson["challenge"] as String
            )

            val publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions.fromMap(
                JSONObject(request).toMap()
            )

            if (clientDataHash != null) {
                client.getAssertionWithHash(
                    clientDataHash,
                    publicKeyCredentialRequestOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    null,
                )
            } else {
                client.getAssertion(
                    clientData,
                    publicKeyCredentialRequestOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    null,
                )
            }
        }
}

class YubiKitFidoActivity : ComponentActivity() {

    object ThemeManager {
        private var theme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null

        fun setTheme(theme: (@Composable (content: @Composable () -> Unit) -> Unit)?) {
            this.theme = theme
        }

        @Composable
        fun ApplyTheme(content: @Composable () -> Unit) {
            val themeToUse = theme ?: { FidoAndroidTheme(content = it) }
            themeToUse(content)
        }
    }

    companion object {
        var theme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null

        fun JSONObject.toMap(): Map<String, *> = keys().asSequence().associateWith {
            when (val value = this[it]) {
                is JSONArray -> {
                    val map = (0 until value.length()).associate { mapValue ->
                        Pair(
                            mapValue.toString(), value[mapValue]
                        )
                    }
                    JSONObject(map).toMap().values.toList()
                }

                is JSONObject -> value.toMap()
                JSONObject.NULL -> null
                else -> value
            }
        }
    }

    private lateinit var yubikit: YubiKitManager
    private val viewModel: MainViewModel by viewModels()
    private val fidoClientService: FidoClientService by lazy { FidoClientService(viewModel) }

    @OptIn(ExperimentalMaterial3Api::class)
    @SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val rpId = intent.extras?.getString("rpId")
        val request = intent.extras?.getString("request")
        val clientDataHash = intent.extras?.getString("clientDataHash")?.hexToByteArray()
        val operation = intent.extras?.getInt("type")?.let { type ->
            mapOf(
                0 to FidoClientService.Operation.MAKE_CREDENTIAL,
                1 to FidoClientService.Operation.GET_ASSERTION
            )[type]
        }

        if (rpId == null || request == null || operation == null) {
            throw IllegalArgumentException("Invalid parameters")
        }

        WindowCompat.setDecorFitsSystemWindows(window, false)

        yubikit = YubiKitManager(this)

        enableEdgeToEdge()

        setContent {
            ThemeManager.ApplyTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color.Transparent
                ) {
                    val sheetState = rememberModalBottomSheetState()
                    val scope = rememberCoroutineScope()
                    var bottomSheetVisible by remember { mutableStateOf(true) }
                    var nfcGuideVisible by remember { mutableStateOf(false) }

                    val finishActivity: () -> Unit = {
                        scope.launch {
                            sheetState.hide()
                        }.invokeOnCompletion {
                            if (!sheetState.isVisible) {
                                bottomSheetVisible = false
                                finish()
                            }
                        }
                    }

                    val finishActivityWithCancel: () -> Unit = {
                        setResult(
                            RESULT_CANCELED
                        )
                        finishActivity()
                    }

                    val finishActivityWithResult: (PublicKeyCredential) -> Unit = { result ->
                        setResult(
                            RESULT_OK, intent.putExtra(
                                "credential",
                                JSONObject(result.toMap(SerializationType.JSON)).toString()
                            )
                        )
                        finishActivity()
                    }

                    BackHandler(enabled = nfcGuideVisible) {
                        nfcGuideVisible = !nfcGuideVisible
                        bottomSheetVisible = true
                    }

                    AnimatedVisibility(
                        visible = nfcGuideVisible,
                        enter = fadeIn(),
                        exit = fadeOut()
                    ) {
                        NfcUsageGuide(
                            onDisposed = { startDiscovery() }
                        ) {
                            nfcGuideVisible = !nfcGuideVisible
                            bottomSheetVisible = true
                        }
                    }

                    AnimatedVisibility(
                        visible = !nfcGuideVisible,
                        enter = fadeIn(),
                        exit = fadeOut()
                    ) {
                        if (bottomSheetVisible) {
                            ModalBottomSheet(
                                dragHandle = {},
                                sheetState = sheetState,
                                onDismissRequest = finishActivityWithCancel,
                            ) {
                                FidoClientUi(
                                    operation,
                                    isUsb = viewModel.isUsb,
                                    isNfcAvailable =
                                        viewModel.isNfcAvailable.observeAsState(false).value,
                                    rpId,
                                    request,
                                    clientDataHash,
                                    fidoClientService = fidoClientService,
                                    onResult = { finishActivityWithResult(it) },
                                    onShowNfcGuideClick = {
                                        nfcGuideVisible = true
                                        bottomSheetVisible = false
                                    },
                                    onCloseButtonClick = finishActivityWithCancel
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun startDiscovery() {
        yubikit.startUsbDiscovery(UsbConfiguration()) {
            lifecycle.coroutineScope.launch {
                viewModel.provideYubiKey(it)
            }
        }
        try {
            yubikit.startNfcDiscovery(NfcConfiguration().timeout(5000), this) {
                lifecycle.coroutineScope.launch {
                    viewModel.provideYubiKey(it)
                }
            }
            viewModel.setNfcAvailable(true)
        } catch (_: NfcNotAvailable) {
            viewModel.setNfcAvailable(false)
        }
    }

    private fun stopDiscovery() {
        yubikit.stopNfcDiscovery(this)
        yubikit.stopUsbDiscovery()
    }

    override fun onStart() {
        super.onStart()
        startDiscovery()
    }

    override fun onStop() {
        super.onStop()
        stopDiscovery()
    }
}
