package com.yubico.yubikit.testing;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.yubico.yubikit.testing.framework.PivInstrumentedTests;
import com.yubico.yubikit.testing.piv.PivJcaDeviceTests;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class PivJcaProviderTests extends PivInstrumentedTests {

    @Test
    public void testGenerateKeys() throws Throwable {
        withPivSession(PivJcaDeviceTests::testGenerateKeys);
    }

    @Test
    public void testImportKeys() throws Throwable {
        withPivSession(PivJcaDeviceTests::testImportKeys);
    }

}