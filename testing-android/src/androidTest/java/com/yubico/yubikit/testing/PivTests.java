package com.yubico.yubikit.testing;

import com.yubico.yubikit.testing.framework.PivInstrumentedTests;
import com.yubico.yubikit.testing.piv.PivDeviceTests;
import com.yubico.yubikit.testing.piv.PivJcaDeviceTests;

import org.junit.Test;

public class PivTests extends PivInstrumentedTests {

    @Test
    public void testPin() throws Throwable {
        withPivSession(PivDeviceTests::testPin);
    }

    @Test
    public void testPuk() throws Throwable {
        withPivSession(PivDeviceTests::testPuk);
    }

    @Test
    public void testManagementKey() throws Throwable {
        withPivSession(PivDeviceTests::testManagementKey);
    }

    @Test
    public void testGenerateKeys() throws Throwable {
        withPivSession(PivDeviceTests::testGenerateKeys);
    }

    @Test
    public void testImportKeys() throws Throwable {
        withPivSession(PivJcaDeviceTests::testImportKeys);
    }

}
