/*
 * Copyright (C) 2025-2026 Yubico.
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

package com.yubico.yubikit.fido.android.internal.ui

import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity

internal sealed class State {
    data object WaitingForKey : State()

    data object WaitingForKeyAgain : State()

    data object Processing : State()

    data object TouchKey : State()

    data object Success : State()

    data object PinCreated : State()

    data object PinChanged : State()

    data class PinNotSetError(val error: Error? = null) : State()

    data class ForcePinChangeError(val error: Error? = null) : State()

    data class OperationError(val error: Error) : State()

    data class WaitingForPinEntry(val error: Error?) : State()

    data class WaitingForUvEntry(val error: Error?) : State()

    data class MultipleAssertions(
        val users: List<PublicKeyCredentialUserEntity>,
        val onSelect: (Int) -> Unit,
    ) : State()
}
