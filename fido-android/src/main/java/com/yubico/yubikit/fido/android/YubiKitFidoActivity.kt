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
import android.content.Intent
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
import com.yubico.yubikit.fido.android.ui.components.NfcUsageGuide
import com.yubico.yubikit.fido.android.ui.screens.FidoClientUi
import com.yubico.yubikit.fido.android.ui.theme.FidoAndroidTheme
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.SerializationType
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class YubiKitFidoActivity : ComponentActivity() {
    companion object {
        private val logger: Logger = LoggerFactory.getLogger(YubiKitFidoActivity::class.java)
        private var customTheme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null

        fun setTheme(theme: (@Composable (content: @Composable () -> Unit) -> Unit)?) {
            customTheme = theme
        }
    }

    private lateinit var yubikit: YubiKitManager
    private lateinit var params: FidoActivityParameters
    private val viewModel: MainViewModel by viewModels()
    private val fidoClientService: FidoClientService by lazy { FidoClientService(viewModel) }

    @OptIn(ExperimentalMaterial3Api::class)
    @SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            params = FidoActivityParameters.fromIntent(intent)
        } catch (e: Exception) {
            logger.error("Invalid parameters: ", e)
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        WindowCompat.setDecorFitsSystemWindows(window, false)

        yubikit = YubiKitManager(this)

        enableEdgeToEdge()

        setContent {
            val theme = customTheme ?: { FidoAndroidTheme(content = it) }
            theme {
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
                                    viewModel,
                                    params.operation,
                                    isUsb = viewModel.isUsb,
                                    isNfcAvailable =
                                        viewModel.isNfcAvailable.observeAsState(false).value,
                                    params.rpId,
                                    params.request,
                                    params.clientDataHash?.toByteArray(),
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

    data class FidoActivityParameters(
        val rpId: String,
        val request: String,
        val clientDataHash: List<Byte>?,
        val operation: FidoClientService.Operation
    ) {
        companion object {
            fun fromIntent(intent: Intent): FidoActivityParameters {
                val extras = intent.extras ?: throw IllegalArgumentException("Missing extras")

                // This single line gets the int, maps it, and throws an exception if the mapping fails.
                val operation = extras.getInt("type").let { type ->
                    when (type) {
                        0 -> FidoClientService.Operation.MAKE_CREDENTIAL
                        1 -> FidoClientService.Operation.GET_ASSERTION
                        else -> null
                    }
                } ?: throw IllegalArgumentException("Invalid operation type")

                return FidoActivityParameters(
                    rpId = extras.getString("rpId")!!,
                    request = extras.getString("request")!!,
                    clientDataHash = extras.getString("clientDataHash")?.hexToByteArray()?.toList(),
                    operation = operation
                )
            }
        }
    }
}
