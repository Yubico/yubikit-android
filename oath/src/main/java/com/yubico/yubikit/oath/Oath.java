package com.yubico.yubikit.oath;

import com.yubico.yubikit.core.application.Application;

public class Oath extends Application {
    public static final Feature<Oath> FEATURE_TOUCH = new VersionedFeature<Oath, OathSession>("Touch", 4, 2, 0, session -> session.getApplicationInfo().getVersion());
    public static final Feature<Oath> FEATURE_SHA512 = new VersionedFeature<Oath, OathSession>("SHA-512", 4, 3, 1, session -> session.getApplicationInfo().getVersion());
    public static final Feature<Oath> FEATURE_RENAME = new VersionedFeature<Oath, OathSession>("Rename Credential", 5, 3, 0, session -> session.getApplicationInfo().getVersion());
}
