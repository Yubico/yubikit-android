package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.Application;

public class YubiOtp extends Application {
    /**
     * Support for checking if a slot is configured via the ConfigState.
     */
    public static final VersionedFeature<YubiOtp, YubiOtpSession> FEATURE_CHECK_CONFIGURED = otpFeature("Check if a slot is configured", 2, 1, 0);
    /**
     * Support for checking if a configured slot requires touch via the ConfigState.
     */
    public static final VersionedFeature<YubiOtp, YubiOtpSession> FEATURE_CHECK_TOUCH = otpFeature("Check if a slot requires touch", 3, 0, 0);
    /**
     * Support for HMAC-SHA1 challenge response functionality.
     */
    public static final VersionedFeature<YubiOtp, YubiOtpSession> FEATURE_CHALLENGE_RESPONSE = otpFeature("Challenge-Response", 2, 2, 0);

    /**
     * Support for inverted LED behavior.
     */
    public static final VersionedFeature<YubiOtp, YubiOtpSession> FEATURE_INVERT_LED = new VersionedFeature<YubiOtp, YubiOtpSession>("Invert LED", 2, 4, 0, YubiOtpSession::getVersion) {
        @Override
        public boolean supports(Version version) {
            // YubiKey NEO < 3.1 does not support invert LED behavior
            if (version.isAtLeast(3, 0, 0) && version.isLessThan(3, 1, 0)) {
                return false;
            }
            return super.supports(version);
        }
    };
    /**
     * Support for swapping slot configurations.
     */
    public static final VersionedFeature<YubiOtp, YubiOtpSession> FEATURE_SWAP = otpFeature("Swap Slots", 2, 3, 0);
    /**
     * Support for updating an already configured slot.
     */
    public static final VersionedFeature<YubiOtp, YubiOtpSession> FEATURE_UPDATE = otpFeature("Update Slot", 2, 3, 0);
    /**
     * Support for NDEF configuration.
     */
    public static final VersionedFeature<YubiOtp, YubiOtpSession> FEATURE_NDEF = otpFeature("NDEF", 3, 0, 0);

    private static VersionedFeature<YubiOtp, YubiOtpSession> otpFeature(String name, int major, int minor, int build) {
        return new VersionedFeature<>(name, major, minor, build, YubiOtpSession::getVersion);
    }
}
