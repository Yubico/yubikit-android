/*
 * Copyright (C) 2022-2023 Yubico.
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

import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;

public class FidoInstrumentedTests extends YKInstrumentedTests {

    public interface Callback {
        void invoke(Ctap2Session value) throws Throwable;
    }

    protected void withCtap2Session(Callback callback) throws Throwable {
        LinkedBlockingQueue<Optional<Throwable>> result = new LinkedBlockingQueue<>();
        Ctap2Session.create(device, value -> {
            try {
                callback.invoke(value.getValue());
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
}