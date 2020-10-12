/*
 * Copyright (C) 2019 Yubico.
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
package com.yubico.yubikit.android;

import android.app.Activity;
import android.os.Handler;
import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.yubico.yubikit.android.transport.nfc.*;
import com.yubico.yubikit.android.transport.usb.*;
import com.yubico.yubikit.core.YubiKeyDevice;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.annotation.Config;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

@RunWith(AndroidJUnit4.class)
@Config(manifest = Config.NONE)
public class YubikitManagerTest {
    private UsbYubiKeyManager mockUsb = Mockito.mock(UsbYubiKeyManager.class);
    private NfcYubiKeyManager mockNfc = Mockito.mock(NfcYubiKeyManager.class);
    private Activity mockActivity = Mockito.mock(Activity.class);

    private UsbYubiKeyDevice usbSession = Mockito.mock(UsbYubiKeyDevice.class);
    private NfcYubiKeyDevice nfcSession = Mockito.mock(NfcYubiKeyDevice.class);

    private final CountDownLatch signal = new CountDownLatch(2);
    private YubiKitManager yubiKitManager = new YubiKitManager(mockUsb, mockNfc);

    @Before
    public void setUp() throws NfcNotAvailable {
        Mockito.doAnswer(new ListenerInvocation(usbSession)).when(mockUsb).enable(Mockito.any(), Mockito.any(UsbYubiKeyListener.class));
        Mockito.doAnswer(new ListenerInvocation(nfcSession)).when(mockNfc).enable(Mockito.any(), Mockito.any(), Mockito.any(NfcYubiKeyListener.class));
    }

    @Test
    public void discoverSession() throws NfcNotAvailable {
        yubiKitManager.startNfcDiscovery(new NfcConfiguration(), mockActivity, new NfcListener());
        yubiKitManager.startUsbDiscovery(new UsbConfiguration(), new UsbListener());

        // wait until listener will be invoked
        try {
            signal.await(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Assert.fail();
        }

        yubiKitManager.stopUsbDiscovery();
        yubiKitManager.stopNfcDiscovery(mockActivity);
        Mockito.verify(mockUsb).disable();
        Mockito.verify(mockNfc).disable(mockActivity);

        // expected to discover 2 sessions
        Assert.assertEquals(0, signal.getCount());
    }

    @Test
    public void discoverUsbSession() throws NfcNotAvailable {
        UsbConfiguration configuration = new UsbConfiguration();
        yubiKitManager.startUsbDiscovery(configuration, new UsbListener());

        Mockito.verify(mockUsb).enable(Mockito.eq(configuration), Mockito.any(UsbYubiKeyListener.class));
        Mockito.verify(mockNfc, Mockito.never()).enable(Mockito.any(), Mockito.any(), Mockito.any());

        // wait until listener will be invoked
        try {
            signal.await(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Assert.fail();
        }

        yubiKitManager.stopUsbDiscovery();
        Mockito.verify(mockUsb).disable();
        Mockito.verify(mockNfc, Mockito.never()).disable(mockActivity);

        // expected to discover 1 session
        Assert.assertEquals(1, signal.getCount());
    }

    @Test
    public void discoverNfcSession() throws NfcNotAvailable {
        NfcConfiguration configuration = new NfcConfiguration();
        yubiKitManager.startNfcDiscovery(configuration, mockActivity, new NfcListener());

        Mockito.verify(mockUsb, Mockito.never()).enable(Mockito.any(), Mockito.any(UsbYubiKeyListener.class));
        Mockito.verify(mockNfc).enable(Mockito.eq(mockActivity), Mockito.eq(configuration), Mockito.any());

        // wait until listener will be invoked
        try {
            signal.await(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Assert.fail();
        }

        yubiKitManager.stopNfcDiscovery(mockActivity);
        Mockito.verify(mockUsb, Mockito.never()).disable();
        Mockito.verify(mockNfc).disable(mockActivity);

        // expected to discover 1 session
        Assert.assertEquals(1, signal.getCount());
    }

    private class UsbListener implements UsbYubiKeyListener {
        @Override
        public void onDeviceAttached(@NonNull UsbYubiKeyDevice device, boolean hasPermission) {
            if (!hasPermission) {
                Assert.fail();
            }
            signal.countDown();
        }

        @Override
        public void onDeviceRemoved(@NonNull UsbYubiKeyDevice device) {
            Assert.fail();
        }

        @Override
        public void onRequestPermissionsResult(@NonNull UsbYubiKeyDevice device, boolean isGranted) {
        }
    }

    private class NfcListener implements NfcYubiKeyListener {
        @Override
        public void onDeviceAttached(@NonNull NfcYubiKeyDevice device) {
            signal.countDown();
        }
    }

    private class ListenerInvocation implements Answer {
        private YubiKeyDevice session;

        private ListenerInvocation(YubiKeyDevice session) {
            this.session = session;
        }

        @Override
        public Object answer(InvocationOnMock invocation) throws Throwable {
            if (invocation.getArgument(1) instanceof UsbYubiKeyListener) {
                final UsbYubiKeyListener internalListener = invocation.getArgument(1);

                new Timer().schedule(new TimerTask() {
                    @Override
                    public void run() {
                        internalListener.onDeviceAttached((UsbYubiKeyDevice) session, true);
                    }
                }, 100); // emulating that discovery of session took some time
            } else if (invocation.getArgument(2) instanceof NfcYubiKeyListener) {
                final NfcYubiKeyListener internalListener = invocation.getArgument(2);
                internalListener.onDeviceAttached((NfcYubiKeyDevice) session);

            }
            return null;
        }
    }

    ;
}
