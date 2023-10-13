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

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.fido.ctap.Ctap2Session;

import org.junit.Assume;

import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;

import javax.annotation.Nullable;

/**
 * @noinspection unused
 */
public class FidoInstrumentedTests extends YKInstrumentedTests {

    public interface TestCondition {
        boolean invoke(YubiKeyDevice device, Ctap2Session value) throws Throwable;
    }

    public interface Callback {
        void invoke(Ctap2Session session, Object... args) throws Throwable;
    }

    protected void withCtap2Session(
            Callback callback,
            Object... args) throws Throwable {
        withCtap2Session(null, null, callback, args);
    }

    protected void withCtap2Session(
            @Nullable TestCondition testCondition,
            Callback callback,
            Object... args) throws Throwable {
        withCtap2Session(null, testCondition, callback, args);
    }

    protected void withCtap2Session(
            @Nullable TestCondition testCondition,
            Callback callback) throws Throwable {
        withCtap2Session((String) null, testCondition, callback);
    }

    protected void withCtap2Session(
            @Nullable String message,
            @Nullable TestCondition testCondition,
            Callback callback,
            Object... args) throws Throwable {
        LinkedBlockingQueue<Optional<Throwable>> result = new LinkedBlockingQueue<>();
        Ctap2Session.create(device, value -> {
            try {
                Ctap2Session session = value.getValue();
                if (testCondition != null) {
                    if (message != null) {
                        Assume.assumeTrue(
                                message,
                                testCondition.invoke(device, session));
                    } else {
                        Assume.assumeTrue(
                                testCondition.invoke(device, session));
                    }
                }
                callback.invoke(session, args);
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