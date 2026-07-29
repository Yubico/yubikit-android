/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.android.ui

import app.cash.turbine.test
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.ui.Origin
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.MainViewModel
import com.yubico.yubikit.fido.android.ui.internal.ui.Error
import com.yubico.yubikit.fido.android.ui.internal.ui.State
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.extensions.ExtensionConfigurationException
import com.yubico.yubikit.fido.client.extensions.ExtensionNotSupportedException
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verifyBlocking

/**
 * Unit tests for MainViewModel.
 * Tests verify ViewModel behavior for initial state and PIN storage.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MainViewModelTest {
    private val testDispatcher = StandardTestDispatcher()
    private lateinit var viewModel: MainViewModel

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
        FidoConfigManager.replace(FidoConfig())
        viewModel = MainViewModel(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `initial state is WaitingForKey when prioritizePin is false`() = runTest {
        FidoConfigManager.setIsPinPrioritized(false)
        val viewModel = MainViewModel()

        viewModel.state.test {
            val state = awaitItem()
            assertTrue(state is State.WaitingForKey)
        }
    }

    @Test
    fun `initial state is WaitingForPinEntry when prioritizePin is true`() = runTest {
        FidoConfigManager.setIsPinPrioritized(true)
        val viewModel = MainViewModel()

        viewModel.state.test {
            val state = awaitItem()
            assertTrue(state is State.WaitingForPinEntry)
        }
    }

    @Test
    fun `setLastEnteredPin stores PIN`() {
        viewModel.setLastEnteredPin("123456".toCharArray())

        assertEquals("123456", String(viewModel.lastEnteredPin!!))
    }

    @Test
    fun `clearLastEnteredPin clears stored PIN`() {
        viewModel.setLastEnteredPin("123456".toCharArray())

        viewModel.clearLastEnteredPin()

        assertNull(viewModel.lastEnteredPin)
    }

    @Test
    fun `setLastEnteredPin clones the input to prevent external modification`() {
        val originalPin = "123456".toCharArray()
        viewModel.setLastEnteredPin(originalPin)

        originalPin[0] = 'X'

        assertEquals('1', viewModel.lastEnteredPin!![0])
    }

    @Test
    fun `cancelUiStateTimer does not throw when no timer active`() {
        viewModel.cancelUiStateTimer()
    }

    /**
     * Drives [MainViewModel.runFidoOperation] with a [FidoClientService] whose operation fails with
     * [failure], and returns the resulting terminal [State].
     */
    private suspend fun TestScope.stateAfterOperationFailure(failure: Throwable): State {
        val service =
            mock<FidoClientService> {
                onBlocking {
                    performOperation(anyOrNull(), any(), any(), anyOrNull(), any(), any())
                } doReturn Result.failure(failure)
            }
        viewModel.lastFidoClientService = service
        viewModel.lastOperation = FidoClientService.Operation.GET_ASSERTION
        viewModel.lastOrigin = Origin("https://example.com")
        viewModel.lastRequest = "{}"
        viewModel.lastClientDataHash = null
        viewModel.lastOnResult = {}

        viewModel.runFidoOperation()
        advanceUntilIdle()
        return viewModel.state.value
    }

    @Test
    fun `extension configuration error surfaces ExtensionUnsupportedError not device-not-configured`() = runTest {
        // Regression: a ClientError whose (base) ExtensionConfigurationException cause must not
        // fall through to DeviceNotConfiguredError ("Set a PIN"); it is an unsupported request.
        val cause =
            ExtensionConfigurationException(
                ClientError.Code.CONFIGURATION_UNSUPPORTED,
                "largeBlob write requires exactly one allowed credential",
            )
        val error =
            ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "message", cause)

        val state = stateAfterOperationFailure(error)

        assertTrue(state is State.OperationError)
        assertTrue((state as State.OperationError).error is Error.ExtensionUnsupportedError)
    }

    @Test
    fun `credProtect-unsupported extension error surfaces DeviceIneligibleError`() = runTest {
        // Regression guard for the merge interaction: a missing required capability
        // (ExtensionNotSupportedException) must map back to DeviceIneligibleError, not
        // DeviceNotConfiguredError.
        val cause = ExtensionNotSupportedException("No Credential Protection support")
        val error = ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "message", cause)

        val state = stateAfterOperationFailure(error)

        assertTrue(state is State.OperationError)
        assertEquals(Error.DeviceIneligibleError, (state as State.OperationError).error)
    }

    @Test
    fun `prevalidation failure short-circuits to OperationError without connecting`() = runTest {
        // A doomed extension request must fail before the key is ever contacted: no WaitingForKey,
        // and performOperation is never invoked.
        val cause =
            ExtensionConfigurationException(
                ClientError.Code.CONFIGURATION_UNSUPPORTED,
                "largeBlob write requires exactly one allowed credential",
            )
        val clientError = ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "message", cause)
        val service =
            mock<FidoClientService> {
                on { validateRequest(any(), any()) } doAnswer { throw clientError }
            }
        viewModel.lastFidoClientService = service
        viewModel.lastOperation = FidoClientService.Operation.GET_ASSERTION
        viewModel.lastOrigin = Origin("https://example.com")
        viewModel.lastRequest = "{}"
        viewModel.lastClientDataHash = null
        viewModel.lastOnResult = {}

        viewModel.runFidoOperation()
        advanceUntilIdle()

        val state = viewModel.state.value
        assertTrue(state is State.OperationError)
        assertTrue((state as State.OperationError).error is Error.ExtensionUnsupportedError)
        verifyBlocking(service, never()) {
            performOperation(anyOrNull(), any(), any(), anyOrNull(), any(), any())
        }
    }

    @Test
    fun `configuration-unsupported without extension cause still maps to DeviceNotConfiguredError`() = runTest {
        // The genuine "UV not configured" case (no cause) must keep its "Set a PIN" mapping.
        val error =
            ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "User verification not configured")

        val state = stateAfterOperationFailure(error)

        assertTrue(state is State.OperationError)
        assertEquals(Error.DeviceNotConfiguredError, (state as State.OperationError).error)
    }
}
