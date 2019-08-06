package com.yubico.yubikit.utils;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowPackageManager;

import java.util.List;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.robolectric.Shadows.shadowOf;

//@RunWith(RobolectricTestRunner.class)
@RunWith(AndroidJUnit4.class)
public class PackageUtilsTest {

    private static final String TEST_PACKAGE_NAME = "com.some.other.package";

    protected ShadowPackageManager shadowPackageManager;
    private PackageManager packageManager;
    @Before
    public void setUp() {
        packageManager = ApplicationProvider.getApplicationContext().getPackageManager();
        shadowPackageManager = shadowOf(packageManager);

    }
    @Test
    public void getCertSHA256() {
        shadowPackageManager.installPackage(
                newPackageInfo(TEST_PACKAGE_NAME, new Signature("00000000"), new Signature("FFFFFFFF")));
        List<String> signatures = PackageUtils.getCertSha256(packageManager, TEST_PACKAGE_NAME);
        assertNotNull(signatures);
        assertEquals(2, signatures.size());
        assertEquals("DF:3F:61:98:04:A9:2F:DB:40:57:19:2D:C4:3D:D7:48:EA:77:8A:DC:52:BC:49:8C:E8:05:24:C0:14:B8:11:19", signatures.get(0));
        assertEquals("AD:95:13:1B:C0:B7:99:C0:B1:AF:47:7F:B1:4F:CF:26:A6:A9:F7:60:79:E4:8B:F0:90:AC:B7:E8:36:7B:FD:0E", signatures.get(1));
    }

    private static PackageInfo newPackageInfo(String packageName, Signature... signatures) {
        PackageInfo firstPackageInfo = new PackageInfo();
        firstPackageInfo.packageName = packageName;
        firstPackageInfo.signatures = signatures;
        return firstPackageInfo;
    }
}
