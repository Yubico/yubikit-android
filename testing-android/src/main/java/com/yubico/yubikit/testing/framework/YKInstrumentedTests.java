package com.yubico.yubikit.testing.framework;

import androidx.test.rule.ActivityTestRule;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.testing.TestActivity;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;

public class YKInstrumentedTests {

    protected YubiKeyDevice device = null;

    @Rule
    public final TestName name = new TestName();

    @Rule
    public final ActivityTestRule<TestActivity> rule = new ActivityTestRule<>(TestActivity.class);

    @Before
    public void getYubiKey() throws InterruptedException {
        device = rule.getActivity().awaitSession(
                getClass().getSimpleName() + " / " + name.getMethodName()
        );
    }

    @After
    public void releaseYubiKey() throws InterruptedException {
        rule.getActivity().returnSession(device);
        device = null;
    }
}
