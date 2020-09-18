package com.yubico.yubikit.android;

import android.app.Activity;
import android.os.Handler;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.yubico.yubikit.core.YubiKeySession;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcDeviceManager;
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable;
import com.yubico.yubikit.android.transport.nfc.NfcSession;
import com.yubico.yubikit.android.transport.nfc.NfcSessionListener;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbDeviceManager;
import com.yubico.yubikit.android.transport.usb.UsbSession;
import com.yubico.yubikit.android.transport.usb.UsbSessionListener;

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
    private UsbDeviceManager mockUsb = Mockito.mock(UsbDeviceManager.class);
    private NfcDeviceManager mockNfc = Mockito.mock(NfcDeviceManager.class);
    private Activity mockActivity = Mockito.mock(Activity.class);

    private UsbSession usbSession = Mockito.mock(UsbSession.class);
    private NfcSession nfcSession = Mockito.mock(NfcSession.class);

    private final Handler handler = Mockito.mock(Handler.class);

    private final CountDownLatch signal = new CountDownLatch(2);
    private YubiKitManager yubiKitManager = new YubiKitManager(handler, mockUsb, mockNfc);

    @Before
    public void setUp() throws NfcNotAvailable {
        Mockito.doAnswer(new ListenerInvocation(usbSession)).when(mockUsb).enable(Mockito.any(), Mockito.any(UsbSessionListener.class));
        Mockito.doAnswer(new ListenerInvocation(nfcSession)).when(mockNfc).enable(Mockito.any(), Mockito.any(), Mockito.any(NfcSessionListener.class));

        Mockito.doAnswer(invocation -> {
            Runnable runnable = invocation.getArgument(0);
            runnable.run();
            return null;
        }).when(handler).post(Mockito.any(Runnable.class));
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

        Mockito.verify(mockUsb).enable(Mockito.eq(configuration), Mockito.any(UsbSessionListener.class));
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

        Mockito.verify(mockUsb, Mockito.never()).enable(Mockito.any(), Mockito.any(UsbSessionListener.class));
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

        @Override
        public void onRequestPermissionsResult(@NonNull UsbSession session, boolean isGranted) {
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
            if (invocation.getArgument(1) instanceof UsbSessionListener) {
                final UsbSessionListener internalListener = invocation.getArgument(1);

                new Timer().schedule(new TimerTask() {
                    @Override
                    public void run() {
                        internalListener.onSessionReceived((UsbSession) session, true);
                    }
                }, 100); // emulating that discovery of session took some time
            } else if (invocation.getArgument(2) instanceof NfcSessionListener) {
                final NfcSessionListener internalListener = invocation.getArgument(2);
                internalListener.onSessionReceived((NfcSession) session);

            }
            return null;
        }
    }

    ;
}
