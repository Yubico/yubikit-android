package com.yubico.yubikit.management;

import com.yubico.yubikit.core.application.Application;

public class Management extends Application {
    public static final Feature<Management> FEATURE_MODE = new VersionedFeature<>("Mode", 3, 0, 0, ManagementSession::getVersion);
    public static final Feature<Management> FEATURE_DEVICE_INFO = new VersionedFeature<>("Device Info", 4, 1, 0, ManagementSession::getVersion);
    public static final Feature<Management> FEATURE_DEVICE_CONFIG = new VersionedFeature<>("Device Config", 5, 0, 0, ManagementSession::getVersion);
}
