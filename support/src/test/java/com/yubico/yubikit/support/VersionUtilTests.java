package com.yubico.yubikit.support;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.Version;

import org.junit.Test;

public class VersionUtilTests {

    @Test
    public void isPreview() {
        assertTrue(VersionUtil.isPreview(new Version(5,0, 0)));
        assertFalse(VersionUtil.isPreview(new Version(5,1, 0)));
        assertTrue(VersionUtil.isPreview(new Version(5,2, 0)));
        assertFalse(VersionUtil.isPreview(new Version(5,2, 3)));
        assertTrue(VersionUtil.isPreview(new Version(5,5, 0)));
        assertFalse(VersionUtil.isPreview(new Version(5,5, 2)));
    }
}
