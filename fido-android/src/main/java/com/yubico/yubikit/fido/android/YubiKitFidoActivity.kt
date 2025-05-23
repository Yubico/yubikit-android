package com.yubico.yubikit.fido.android

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Flare
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.lifecycle.coroutineScope
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.YubiKitFidoActivity.Companion.toMap
import com.yubico.yubikit.fido.android.ui.theme.FidoAndroidTheme
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.PinInvalidClientError
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import com.yubico.yubikit.fido.webauthn.SerializationType
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

sealed class UiState {
    data object WaitingForKey : UiState()
    data object WaitingForKeyAgain : UiState()
    data object Processing : UiState()
    data object TouchKey : UiState()
    data object Success : UiState()
    data class Error(val error: com.yubico.yubikit.fido.android.Error) : UiState()
    data class WaitingForPinEntry(val error: com.yubico.yubikit.fido.android.Error?) : UiState()
}

sealed class Error {
    data object PinRequiredError : Error()
    data object PinBlockedError : Error()
    data object PinAuthBlockedError : Error()
    data class IncorrectPinError(val remainingAttempts: Int?) : Error()
    data object OperationFailed : Error()
    data class UnknownError(val message: String?) : Error()
}

class FidoClientService(private val viewModel: MainViewModel = MainViewModel()) {

    enum class Operation {
        MAKE_CREDENTIAL,
        GET_ASSERTION
    }

    suspend fun performOperation(
        pin: String?, operation: Operation, rpId: String, request: String, onConnection: () -> Unit
    ): Result<PublicKeyCredential> {
        return when (operation) {
            Operation.MAKE_CREDENTIAL -> makeCredential(pin, rpId, request, onConnection)
            Operation.GET_ASSERTION -> getAssertion(pin, rpId, request, onConnection)
        }
    }

    suspend fun waitForKeyRemoval(): Unit {
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
        pin: String?, rpId: String, request: String, onConnection: () -> Unit
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
                "webauthn.create",
                rpId,
                requestJson["challenge"] as String
            )

            val publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions.fromMap(
                JSONObject(request).toMap()
            )
            client.makeCredential(
                clientData,
                publicKeyCredentialCreationOptions,
                rpId.removePrefix("https://"), // TODO reason about this
                pin?.toCharArray(),
                null,
                null
            )
        }

    private suspend fun getAssertion(
        pin: String?, rpId: String, request: String, onConnection: () -> Unit
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
            client.getAssertion(
                clientData,
                publicKeyCredentialRequestOptions,
                rpId.removePrefix("https://"), // TODO reason about this
                pin?.toCharArray(),
                null,
            )
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
                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    containerColor = Color.Transparent
                ) { _ ->

                    val sheetState = rememberModalBottomSheetState()
                    val scope = rememberCoroutineScope()
                    var bottomSheetVisible by remember { mutableStateOf(true) }

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

                    val finishActivityWithResult: (PublicKeyCredential) -> Unit = { result ->
                        setResult(
                            RESULT_OK, intent.putExtra(
                                "credential", result.toMap(SerializationType.JSON).toString()
                            )
                        )
                        finishActivity()
                    }

                    if (bottomSheetVisible) {
                        ModalBottomSheet(
                            dragHandle = {},
                            sheetState = sheetState,
                            onDismissRequest = finishActivity,
                        ) {
                            FidoClientUi(
                                operation,
                                isUsb = viewModel.isUsb,
                                rpId,
                                request,
                                fidoClientService = fidoClientService,
                                onResult = { finishActivityWithResult(it) },
                                onCloseButtonClick = finishActivity
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        yubikit.startUsbDiscovery(UsbConfiguration()) {
            lifecycle.coroutineScope.launch {
                viewModel.provideYubiKey(it)
            }
        }
        yubikit.startNfcDiscovery(NfcConfiguration().timeout(5000), this) {
            lifecycle.coroutineScope.launch {
                viewModel.provideYubiKey(it)
            }
        }
    }

    override fun onStop() {
        super.onStop()
        yubikit.stopUsbDiscovery()
    }
}

@Composable
fun ContentWrapper(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: (() -> Unit)? = null,
    content: @Composable (() -> Unit)
) {
    Column(
        modifier = Modifier
            .height(225.dp)
            .fillMaxWidth()
            .padding(top = 0.dp, start = 0.dp, end = 0.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()
        ) {
            if (onCloseButtonClick != null) {
                IconButton(onClick = onCloseButtonClick) {
                    Icon(
                        imageVector = Icons.Default.Close, contentDescription = "Close"
                    )
                }
            } else {
                Box(
                    modifier = Modifier
                        .width(16.dp)
                        .height(48.dp)
                )
            }
            Text(
                text = if (operation == FidoClientService.Operation.MAKE_CREDENTIAL) {
                    stringResource(R.string.create_passkey_for, origin)
                } else {
                    stringResource(R.string.login_with_passkey, origin)
                }, style = MaterialTheme.typography.titleSmall
            )

        }
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            content()
        }
    }
}

@Composable
fun TapOrInsertSecurityKey(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_baseline_passkey_24),
            contentDescription = stringResource(R.string.passkey_icon),
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.tap_or_insert_key))
    }
}

@Composable
fun TapAgainSecurityKey(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        PulsingIcon(
            painter = painterResource(R.drawable.ic_baseline_passkey_24),
            contentDescription = stringResource(R.string.passkey_icon),
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.tap_key_again))
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun Processing(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        LoadingIndicator(modifier = Modifier.size(64.dp, 64.dp))
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.dont_remove_the_key))
    }
}

@Composable
fun TouchTheSecurityKey(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        Icon(
            modifier = Modifier.size(64.dp, 64.dp),
            imageVector = Icons.Default.Flare,
            contentDescription = "Touch the key",
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.touch_the_key))
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun EnterPin(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    onCloseButtonClick: () -> Unit,
    pin: String? = "",
    onPinEntered: (pin: String) -> Unit
) {

    val errorText: String? = when (error) {
        is Error.IncorrectPinError -> {
            if (error.remainingAttempts != null) {
                stringResource(
                    R.string.incorrect_pin_with_attempts,
                    error.remainingAttempts
                )
            } else {
                stringResource(R.string.incorrect_pin)
            }
        }

        is Error.PinBlockedError -> {
            stringResource(R.string.pin_blocked)
        }

        is Error.PinAuthBlockedError -> {
            stringResource(R.string.pin_auth_blocked)
        }

        else -> null
    }

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        var text by remember { mutableStateOf(TextFieldValue(pin ?: "")) }
        var showPassword by remember { mutableStateOf(false) }
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = text,
            supportingText = { Text(text = errorText ?: "") },
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        imageVector = if (showPassword) {
                            Icons.Default.VisibilityOff
                        } else {
                            Icons.Default.Visibility
                        },
                        contentDescription = "Show"
                    )
                }
            },
            singleLine = true,
            isError = errorText != null,
            label = { Text(text = stringResource(R.string.provide_pin)) },
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Password,
                    contentDescription = stringResource(
                        R.string.icon_content_description_password
                    ),
                    tint = MaterialTheme.colorScheme.onBackground
                )
            },
            visualTransformation = if (!showPassword) {
                PasswordVisualTransformation()
            } else {
                VisualTransformation.None
            },
            onValueChange = {
                text = it
            })

        Row(
            modifier = Modifier
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.End
        ) {
            Button(
                modifier = Modifier.width(IntrinsicSize.Min),
                onClick = {
                    onPinEntered.invoke(text.text)
                }, shapes = ButtonDefaults.shapes()
            ) {
                Text(text = stringResource(R.string.continue_operation), maxLines = 1)
            }
        }

    }
}

@Composable
fun SuccessView(operation: FidoClientService.Operation, origin: String) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = null
    ) {
        Text(
            text = if (operation == FidoClientService.Operation.MAKE_CREDENTIAL)
                stringResource(R.string.passkey_created)
            else
                stringResource(R.string.login_successful),
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.remove_the_key),
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

@Composable
fun ErrorView(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    onRetry: () -> Unit
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = null
    ) {
        Icon(
            imageVector = Icons.Default.Error,
            contentDescription = stringResource(R.string.error),
            tint = Color.Red,
            modifier = Modifier.size(48.dp)
        )

        Spacer(modifier = Modifier.height(8.dp))

        if (error is Error.UnknownError) {
            Text(text = error.message ?: stringResource(R.string.unknown_error))
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(onClick = onRetry) {
            Text(stringResource(R.string.retry))
        }
    }
}

@Composable
fun FidoClientUi(
    operation: FidoClientService.Operation,
    isUsb: Boolean,
    rpId: String,
    request: String,
    fidoClientService: FidoClientService = remember { FidoClientService() },
    onResult: (PublicKeyCredential) -> Unit = {},
    onCloseButtonClick: () -> Unit
) {
    var result: PublicKeyCredential? by remember { mutableStateOf(null) }
    var pinValue: String? by remember { mutableStateOf(null) }
    var retryOperation by remember { mutableStateOf(false) }
    var tapAgain by remember { mutableStateOf(false) }

    val uiState = produceState<UiState>(
        initialValue = UiState.WaitingForKey,
        key1 = retryOperation
    ) {
        try {
            if (result != null) {
                fidoClientService.waitForKeyRemoval()
                onResult(result!!)
                return@produceState // End the flow after completion
            }

            if (tapAgain) {
                value = UiState.WaitingForKeyAgain
                tapAgain = false
            } else {
                value = UiState.WaitingForKey
            }

            fidoClientService.performOperation(pinValue, operation, rpId, request) {
                value = if (isUsb) UiState.TouchKey else UiState.Processing
            }
                .fold(onSuccess = {
                    result = it
                    value = UiState.Success
                    retryOperation = !retryOperation
                    return@produceState // End the flow after completion
                }, onFailure = { error ->
                    val errorState = when (error) {
                        is PinRequiredClientError -> Error.PinRequiredError
                        is PinInvalidClientError -> Error.IncorrectPinError(
                            error.pinRetries
                        )

                        is ClientError -> {
                            if (error.cause is CtapException) {
                                when ((error.cause as CtapException).ctapError) {
                                    CtapException.ERR_PIN_BLOCKED -> Error.PinBlockedError
                                    CtapException.ERR_PIN_AUTH_BLOCKED -> Error.PinAuthBlockedError
                                    else -> Error.OperationFailed
                                }
                            } else {
                                Error.OperationFailed
                            }
                        }

                        else -> Error.UnknownError(
                            error.message
                        )
                    }

                    value = when (errorState) {
                        is Error.PinRequiredError,
                        is Error.PinBlockedError,
                        is Error.PinAuthBlockedError,
                        is Error.IncorrectPinError -> {
                            // Show PIN entry screen with error
                            UiState.WaitingForPinEntry(errorState)
                        }

                        else -> {
                            UiState.Error(errorState)
                        }
                    }
                    return@produceState

                })
        } catch (e: Exception) {
            value = UiState.Error(
                Error.UnknownError(
                    e.message
                )
            )
        }
    }

    Column(
        modifier = Modifier
            .padding(
                top = 16.dp,
                start = 16.dp,
                end = 16.dp,
                bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {

        AnimatedContent(
            targetState = uiState.value,
            label = "FidoClientUi",
            transitionSpec = {
                fadeIn() togetherWith fadeOut()
            }
        ) { state ->
            when (state) {

                is UiState.WaitingForKey -> {
                    TapOrInsertSecurityKey(
                        operation = operation,
                        origin = rpId,
                        onCloseButtonClick = onCloseButtonClick
                    )
                }

                is UiState.WaitingForKeyAgain -> {
                    TapAgainSecurityKey(
                        operation = operation,
                        origin = rpId,
                        onCloseButtonClick = onCloseButtonClick
                    )
                }

                is UiState.WaitingForPinEntry -> {
                    EnterPin(
                        operation = operation,
                        origin = rpId,
                        error = state.error,
                        pin = pinValue ?: "",
                        onCloseButtonClick = onCloseButtonClick
                    ) {
                        pinValue = it.ifEmpty {
                            null
                        }
                        retryOperation = !retryOperation
                        tapAgain = true
                    }
                }

                is UiState.Processing -> {
                    Processing(operation = operation, origin = rpId) {}
                }

                is UiState.TouchKey -> {
                    TouchTheSecurityKey(operation = operation, origin = rpId) {}
                }

                is UiState.Success -> {
                    SuccessView(operation = operation, origin = rpId)
                }

                is UiState.Error -> {
                    ErrorView(
                        operation = operation,
                        origin = rpId,
                        error = state.error
                    ) {
                        pinValue = null
                        retryOperation = !retryOperation
                    }
                }
            }
        }

    }
}

// helpers

@Composable
fun PulsingIcon(
    painter: Painter,
    contentDescription: String?,
    modifier: Modifier = Modifier,
    tint: Color = LocalContentColor.current
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")

    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1000,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scale"
    )

    val alpha by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 0.7f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1000,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "alpha"
    )

    Icon(
        painter = painter,
        contentDescription = contentDescription,
        modifier = modifier
            .scale(scale)
            .alpha(alpha),
        tint = tint
    )
}

@Preview(
    name = "default preview", showBackground = true
)
annotation class DefaultPreview

@DefaultPreview
@Composable
fun EnterPinPreview() {
    EnterPin(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onCloseButtonClick = {}) {}
}

@DefaultPreview
@Composable
fun EnterPinWithErrorPreview() {
    EnterPin(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "example.com",
        error = Error.IncorrectPinError(3),
        onCloseButtonClick = {}) {}
}

@DefaultPreview
@Composable
fun TapOrInsertSecurityKeyForMakeCredentialPreview() {
    TapOrInsertSecurityKey(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "www.example.com"
    ) {}
}

@DefaultPreview
@Composable
fun TapOrInsertSecurityKeyForGetAssertionPreview() {
    TapOrInsertSecurityKey(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "www.example.com"
    ) {}
}

@DefaultPreview
@Composable
fun TapSecurityKeyAgainForGetAssertionPreview() {
    TapAgainSecurityKey(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "www.example.com"
    ) {}
}

@DefaultPreview
@Composable
fun ProcessingPreview() {
    Processing(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onCloseButtonClick = {})
}
