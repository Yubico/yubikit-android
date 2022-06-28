package com.yubico.yubikit.testing.framework;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;

import org.junit.runner.RunWith;

import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;

@RunWith(AndroidJUnit4.class)
public class PivInstrumentedTests extends YKInstrumentedTests {

    public interface Callback {
        void invoke(PivSession value) throws Throwable;
    }

    protected void withPivSession(Callback callback) throws Throwable {
        LinkedBlockingQueue<Optional<Throwable>> result = new LinkedBlockingQueue<>();
        device.requestConnection(SmartCardConnection.class, callbackResult -> {
            try {
                if (callbackResult.isSuccess()) {
                    PivSession pivSession = new PivSession(callbackResult.getValue());
                    callback.invoke(pivSession);
                    result.offer(Optional.empty());
                }
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