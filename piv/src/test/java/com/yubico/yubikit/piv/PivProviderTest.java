package com.yubico.yubikit.piv;

import com.yubico.yubikit.piv.jca.PivProvider;
import com.yubico.yubikit.testing.piv.PivTestUtils;

import org.junit.Test;

import java.security.Security;

public class PivProviderTest {
    @Test
    public void testStandardAlgorithms() throws Exception {
        PivTestUtils.rsaTests();
        PivTestUtils.ecTests();
    }

    @Test
    public void testAlgorithmsWithProvider() throws Exception {
        Security.insertProviderAt(new PivProvider(), 1);

        PivTestUtils.rsaTests();
        PivTestUtils.ecTests();
    }
}
