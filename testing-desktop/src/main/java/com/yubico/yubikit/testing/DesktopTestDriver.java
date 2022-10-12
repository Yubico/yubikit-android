/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.testing;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.desktop.*;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class DesktopTestDriver {

    private final BlockingQueue<PcscDevice> sessionQueue = new ArrayBlockingQueue<>(1);

    private final YubiKitManager yubikit;

    private Thread observerThread = null;

    public DesktopTestDriver() {
        if (OperatingSystem.isMac()) {
            System.setProperty("sun.security.smartcardio.library", "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
        }
        yubikit = new YubiKitManager();
        startObserving();
    }

    private void startObserving() {

        observerThread = new Thread(() -> yubikit.run(new PcscConfiguration(), new PcscSessionListener() {
            @Override
            public void onSessionReceived(@NotNull PcscDevice session) {
                sessionQueue.add(session);
                System.out.println("Session added");
            }

            @Override
            public void onSessionRemoved(@NotNull PcscDevice session) {
                System.out.println("Session removed");
            }
        }));

        observerThread.start();
    }

    private void stopObserving() {
        yubikit.stop();
    }

    public YubiKeyDevice awaitSession() throws InterruptedException {
        YubiKeyDevice connectedDevice = sessionQueue.take();
        System.out.println("Device connected");
        return connectedDevice;
    }

    public void returnSession(YubiKeyDevice device) {
        System.out.println("Device returned");
    }
}
