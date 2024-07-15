/*
 * Copyright (C) 2022-2024 Yubico.
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

package com.yubico.yubikit.testing.framework;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.testing.fido.FidoTestUtils;

import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;

import javax.annotation.Nullable;

public class FidoInstrumentedTests extends YKInstrumentedTests {
    public interface Callback {
        void invoke(Ctap2Session session) throws Throwable;
    }

    protected void withCtap2Session(Callback callback) throws Throwable {
        withCtap2Session(callback, true);
    }

    protected void withCtap2Session(Callback callback, boolean setPin) throws Throwable {

        FidoTestUtils.verifyAndSetup(device, getPinUvAuthProtocol(), setPin);

        LinkedBlockingQueue<Optional<Throwable>> result = new LinkedBlockingQueue<>();
        Ctap2Session.create(device, value -> {
            try {
                Ctap2Session session = value.getValue();
                callback.invoke(session);
                result.offer(Optional.empty());
            } catch (Throwable e) {
                result.offer(Optional.of(e));
            }
        });

        Optional<Throwable> exception = result.take();
        if (exception.isPresent()) {
            throw exception.get();
        }
    }

    protected PinUvAuthProtocol getPinUvAuthProtocol() {
        // default is protocol V2
        return new PinUvAuthProtocolV2();
    }
}