package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.util.Result;
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
        // This doesn't actually use the provider, it makes sure the provider doesn't interfere.
        Security.insertProviderAt(new PivProvider(callback -> callback.invoke(Result.failure(new UnsupportedOperationException()))), 1);

        PivTestUtils.rsaTests();
        PivTestUtils.ecTests();
    }
}
