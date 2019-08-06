/*
 * Copyright (C) 2019 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.utils;

import android.annotation.SuppressLint;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.text.TextUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class PackageUtils {

    /**
     * Allows to get SHA256 of package signature
     * @param pm package manager
     * @param packageName name of the package
     * @return SHA265 signature
     */
    @SuppressLint("PackageManagerGetSignatures")
    public static List<String> getCertSha256(PackageManager pm, String packageName) {
        try {
            PackageInfo info;
            List<byte[]> certList = new ArrayList<>();
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                Signature[] signatures = info.signingInfo.getApkContentsSigners();
                for (Signature s : signatures) {
                    certList.add(s.toByteArray());
                }
            } else {
                info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                Signature[] signatures = info.signatures;
                for (Signature s : signatures) {
                    certList.add(s.toByteArray());
                }
            }

            List<String> hexCertList = new ArrayList<>();
            for (byte[] cert : certList) {
                byte[] digest = MessageDigest.getInstance("sha256").digest(cert);
                String[] digestHex = new String[digest.length];
                for (int i = 0; i < digest.length; i++) {
                    digestHex[i] = String.format("%02X", digest[i]);
                }
                hexCertList.add(TextUtils.join(":", digestHex));
            }
            return hexCertList;
        } catch (PackageManager.NameNotFoundException e) {
            throw new IllegalStateException("Unable to get APK signing certificate!");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
