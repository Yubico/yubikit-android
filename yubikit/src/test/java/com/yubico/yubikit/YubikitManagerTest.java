package com.yubico.yubikit;

import android.app.Activity;
import android.os.Handler;

import com.yubico.yubikit.exceptions.NfcDisabledException;
import com.yubico.yubikit.exceptions.NfcNotFoundException;
import com.yubico.yubikit.transport.YubiKeySession;
import com.yubico.yubikit.transport.nfc.NfcDeviceManager;
import com.yubico.yubikit.transport.nfc.NfcSession;
import com.yubico.yubikit.transport.nfc.NfcSessionListener;
import com.yubico.yubikit.transport.usb.UsbDeviceManager;
import com.yubico.yubikit.transport.usb.UsbSession;
import com.yubico.yubikit.transport.usb.UsbSessionListener;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;

@RunWith(AndroidJUnit4.class)
//@RunWith(RobolectricTestRunner.class)
public class YubikitManagerTest {
    private UsbDeviceManager mockUsb = Mockito.mock(UsbDeviceManager.class);
    private NfcDeviceManager mockNfc = Mockito.mock(NfcDeviceManager.class);
    private Activity mockActivity = Mockito.mock(Activity.class);

    private UsbSession usbSession = Mockito.mock(UsbSession.class);
    private NfcSession nfcSession = Mockito.mock(NfcSession.class);

    private final Handler handler = Mockito.mock(Handler.class);

    private final CountDownLatch signal = new CountDownLatch(2);
    private YubiKitManager yubiKitManager = new YubiKitManager(handler,mockUsb, mockNfc);

    @Before
    public void setUp() {
        Mockito.doAnswer(new ListenerInvocation(usbSession)).when(mockUsb).setListener(Mockito.any(UsbSessionListener.class));
        Mockito.doAnswer(new ListenerInvocation(nfcSession)).when(mockNfc).setListener(Mockito.any(NfcSessionListener.class));

        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                Runnable runnable = invocation.getArgument(0);
                runnable.run();
                return null;
            }
        }).when(handler).post(Mockito.any(Runnable.class));
    }

    @Test
    public void discoverSession() throws NfcDisabledException, NfcNotFoundException {
        yubiKitManager.startNfcDiscovery(true, mockActivity, new NfcListener());
        yubiKitManager.startUsbDiscovery(true, new UsbListener());

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
    public void discoverUsbSession() throws NfcNotFoundException, NfcDisabledException {
        yubiKitManager.startUsbDiscovery(true, new UsbListener());

        Mockito.verify(mockUsb).enable(true);
        Mockito.verify(mockNfc, Mockito.never()).enable(mockActivity, true);

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
    public void discoverNfcSession() throws NfcNotFoundException, NfcDisabledException {
        yubiKitManager.startNfcDiscovery(true, mockActivity, new NfcListener());
        Mockito.verify(mockUsb, Mockito.never()).enable(true);
        Mockito.verify(mockNfc).enable(mockActivity, true);

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

    private class UsbListener implements UsbSessionListener {
        @Override
        public void onSessionReceived(@NonNull UsbSession session, boolean hasPermission) {
            if (!hasPermission) {
                Assert.fail();
            }
            signal.countDown();
        }

        @Override
        public void onSessionRemoved(@NonNull UsbSession session) {
            Assert.fail();
        }
    }

    private class NfcListener implements NfcSessionListener {
        @Override
        public void onSessionReceived(@NonNull NfcSession session) {
            signal.countDown();
        }
    }

    private class ListenerInvocation implements Answer {
        private YubiKeySession session;
        private ListenerInvocation(YubiKeySession session) {
            this.session = session;
        }

        @Override
        public Object answer(InvocationOnMock invocation) throws Throwable {
            if (invocation.getArgument(0) instanceof UsbSessionListener) {
                final UsbSessionListener internalListener = invocation.getArgument(0);

                new Timer().schedule(new TimerTask() {
                    @Override
                    public void run() {
                        internalListener.onSessionReceived((UsbSession)session, true);
                    }
                }, 100); // emulating that discovery of session took some time
            } else if (invocation.getArgument(0) instanceof NfcSessionListener) {
                final NfcSessionListener internalListener = invocation.getArgument(0);
                internalListener.onSessionReceived((NfcSession)session);

            }
            return null;
        }
    };
}
