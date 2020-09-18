package com.yubico.yubikit.piv;

import com.yubico.yubikit.testing.Codec;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class PaddingTest {
    @Test
    public void testPkcs1v1_5() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

        Assert.assertArrayEquals(
                Codec.fromHex("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"),
                Padding.pad(KeyType.RSA1024, message, "SHA256WithRSA")
        );

        Assert.assertArrayEquals(
                Codec.fromHex("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414d3486ae9136e7856bc42212385ea797094475802"),
                Padding.pad(KeyType.RSA1024, message, "SHA1WithRSA")
        );
    }
}
