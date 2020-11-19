package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.Application;

public class YubiOtp extends Application {
    /**
     * Support for checking if a slot is configured via the ConfigState.
     */
    public static final Feature<YubiOtp> FEATURE_CHECK_CONFIGURED = new VersionedFeature<>("Check if a slot is configured", 2, 1, 0);
    /**
     * Support for checking if a configured slot requires touch via the ConfigState.
     */
    public static final Feature<YubiOtp> FEATURE_CHECK_TOUCH = new VersionedFeature<>("Check if a slot requires touch", 3, 0, 0);
    /**
     * Support for HMAC-SHA1 challenge response functionality.
     */
    public static final Feature<YubiOtp> FEATURE_CHALLENGE_RESPONSE = new VersionedFeature<>("Challenge-Response", 2, 2, 0);

    /**
     * Support for inverted LED behavior.
     */
    public static final Feature<YubiOtp> FEATURE_INVERT_LED = new Feature<YubiOtp>("Invert LED") {
        @Override
        public boolean isSupportedBy(Version version) {
            if (version.major == 0) {
                return true;
            }
            if (version.isAtLeast(2, 4, 0)) {
                // YubiKey NEO < 3.1 does not support invert LED behavior
                if (version.major == 3 && version.minor == 0) {
                    return false;
                }
                return true;
            }
            return false;
        }
    };
    /**
     * Support for swapping slot configurations.
     */
    public static final Feature<YubiOtp> FEATURE_SWAP = new VersionedFeature<>("Swap Slots", 2, 3, 0);
    /**
     * Support for updating an already configured slot.
     */
    public static final Feature<YubiOtp> FEATURE_UPDATE = new VersionedFeature<>("Update Slot", 2, 3, 0);
    /**
     * Support for NDEF configuration.
     */
    public static final Feature<YubiOtp> FEATURE_NDEF = new VersionedFeature<>("NDEF", 3, 0, 0);
}
