package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.Application;

public class Piv extends Application {
    /**
     * Support for the NIST P-348 elliptic curve.
     */
    public static final Feature<Piv> FEATURE_P384 = new VersionedFeature<>("Curve P384", 4, 0, 0);
    /**
     * Support for custom PIN or Touch policy.
     */
    public static final Feature<Piv> FEATURE_KEY_POLICY = new VersionedFeature<>("PIN/Touch Policy", 4, 0, 0);
    /**
     * Support for the CACHED Touch policy.
     */
    public static final Feature<Piv> FEATURE_TOUCH_CACHED = new VersionedFeature<>("Cached Touch Policy", 4, 3, 0);
    /**
     * Support for Attestation of generated keys.
     */
    public static final Feature<Piv> FEATURE_ATTESTATION = new VersionedFeature<>("Attestation", 4, 3, 0);
    /**
     * Support for getting PIN/PUK/Management key and private key metadata.
     */
    public static final Feature<Piv> FEATURE_METADATA = new VersionedFeature<>("Metadata", 5, 3, 0);

    /**
     * Support for generating RSA keys.
     */
    public static final Feature<Piv> FEATURE_RSA_GENERATION = new Feature<Piv>("RSA key generation") {
        @Override
        public boolean isSupportedBy(Version version) {
            return version.isLessThan(4, 2, 6) || version.isAtLeast(4, 3, 5);
        }
    };
}
