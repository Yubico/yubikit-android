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

package com.yubico.yubikit.fido.android

import app.cash.turbine.test
import com.yubico.yubikit.fido.android.config.YubiKitFidoConfig
import com.yubico.yubikit.fido.android.config.YubiKitFidoConfigManager
import com.yubico.yubikit.fido.android.ui.State
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

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
        YubiKitFidoConfigManager.replace(YubiKitFidoConfig())
        viewModel = MainViewModel(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `initial state is WaitingForKey when prioritizePin is false`() = runTest {
        YubiKitFidoConfigManager.setPrioritizePin(false)
        val viewModel = MainViewModel()

        viewModel.state.test {
            val state = awaitItem()
            assertTrue(state is State.WaitingForKey)
        }
    }

    @Test
    fun `initial state is WaitingForPinEntry when prioritizePin is true`() = runTest {
        YubiKitFidoConfigManager.setPrioritizePin(true)
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
}
