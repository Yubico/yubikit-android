package com.yubico.yubikit.oath;

import com.yubico.yubikit.core.application.Application;

public class Oath extends Application {
    public static final Feature<Oath> FEATURE_TOUCH = new VersionedFeature<>("Touch", 4, 2, 0);
    public static final Feature<Oath> FEATURE_SHA512 = new VersionedFeature<>("SHA-512", 4, 3, 1);
    public static final Feature<Oath> FEATURE_RENAME = new VersionedFeature<>("Rename Credential", 5, 3, 0);
}
