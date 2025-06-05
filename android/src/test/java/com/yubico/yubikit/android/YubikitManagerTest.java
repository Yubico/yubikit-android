/*
 * Copyright (C) 2019-2022 Yubico.
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
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable;
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice;
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyManager;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyManager;
import com.yubico.yubikit.core.util.Callback;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.annotation.Config;

@RunWith(AndroidJUnit4.class)
@Config(manifest = Config.NONE)
public class YubikitManagerTest {
  private final UsbYubiKeyManager mockUsb = Mockito.mock(UsbYubiKeyManager.class);
  private final NfcYubiKeyManager mockNfc = Mockito.mock(NfcYubiKeyManager.class);
  private final Activity mockActivity = Mockito.mock(Activity.class);

  private final UsbYubiKeyDevice usbSession = Mockito.mock(UsbYubiKeyDevice.class);
  private final NfcYubiKeyDevice nfcSession = Mockito.mock(NfcYubiKeyDevice.class);

  private final CountDownLatch signal = new CountDownLatch(2);
  private final YubiKitManager yubiKitManager = new YubiKitManager(mockUsb, mockNfc);

  @Before
  public void setUp() throws NfcNotAvailable {
    Mockito.doAnswer(new UsbListenerInvocationTest(usbSession))
        .when(mockUsb)
        .enable(Mockito.any(), ArgumentMatchers.<Callback<UsbYubiKeyDevice>>any());
    Mockito.doAnswer(new NfcListenerInvocationTest(nfcSession))
        .when(mockNfc)
        .enable(Mockito.any(), Mockito.any(), ArgumentMatchers.<Callback<NfcYubiKeyDevice>>any());
  }

  @Test
  public void discoverSession() throws NfcNotAvailable {
    yubiKitManager.startNfcDiscovery(new NfcConfiguration(), mockActivity, new NfcListener());
    yubiKitManager.startUsbDiscovery(new UsbConfiguration(), new UsbListener());

    // wait until listener will be invoked
    try {
      final boolean ignoredResult = signal.await(1, TimeUnit.SECONDS);
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

    Mockito.verify(mockUsb)
        .enable(Mockito.eq(configuration), ArgumentMatchers.<Callback<UsbYubiKeyDevice>>any());
    Mockito.verify(mockNfc, Mockito.never()).enable(Mockito.any(), Mockito.any(), Mockito.any());

    // wait until listener will be invoked
    try {
      final boolean ignoredResult = signal.await(1, TimeUnit.SECONDS);
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

    Mockito.verify(mockUsb, Mockito.never())
        .enable(Mockito.any(), ArgumentMatchers.<Callback<UsbYubiKeyDevice>>any());
    Mockito.verify(mockNfc)
        .enable(Mockito.eq(mockActivity), Mockito.eq(configuration), Mockito.any());

    // wait until listener will be invoked
    try {
      final boolean ignoredResult = signal.await(1, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      Assert.fail();
    }

    yubiKitManager.stopNfcDiscovery(mockActivity);
    Mockito.verify(mockUsb, Mockito.never()).disable();
    Mockito.verify(mockNfc).disable(mockActivity);

    // expected to discover 1 session
    Assert.assertEquals(1, signal.getCount());
  }

  private class UsbListener implements Callback<UsbYubiKeyDevice> {
    @Override
    public void invoke(UsbYubiKeyDevice value) {
      signal.countDown();
    }
  }

  private class NfcListener implements Callback<NfcYubiKeyDevice> {
    @Override
    public void invoke(NfcYubiKeyDevice value) {
      signal.countDown();
    }
  }

  private static class UsbListenerInvocationTest implements Answer<Object> {
    private final UsbYubiKeyDevice session;

    private UsbListenerInvocationTest(UsbYubiKeyDevice session) {
      this.session = session;
    }

    @Nullable
    @Override
    public Object answer(InvocationOnMock invocation) throws Throwable {
      Callback<? super UsbYubiKeyDevice> internalListener = invocation.getArgument(1);
      new Timer()
          .schedule(
              new TimerTask() {
                @Override
                public void run() {
                  internalListener.invoke(session);
                }
              },
              100); // emulating that discovery of session took some time
      return null;
    }
  }

  private static class NfcListenerInvocationTest implements Answer<Object> {
    private final NfcYubiKeyDevice session;

    private NfcListenerInvocationTest(NfcYubiKeyDevice session) {
      this.session = session;
    }

    @Nullable
    @Override
    public Object answer(InvocationOnMock invocation) {
      Callback<? super NfcYubiKeyDevice> internalListener = invocation.getArgument(2);
      internalListener.invoke(session);
      return null;
    }
  }
}
