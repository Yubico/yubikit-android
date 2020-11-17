package com.yubico.yubikit.core;

import java.util.function.Function;

/**
 * A feature for an Application, which may not be supported by all YubiKeys.
 *
 * @param <T> The type of Session for which the Feature is relevant.
 */
public abstract class Feature<T extends ApplicationSession<T>> {
    protected final String featureName;

    protected Feature(String featureName) {
        this.featureName = featureName;
    }

    /**
     * Get a human readable name of the feature.
     *
     * @return the name of the feature
     */
    public String getFeatureName() {
        return featureName;
    }

    /**
     * Checks if the Feature is supported by the given Session.
     *
     * @param session the session to check support for.
     * @return true if the Feature is supported, false if not
     */
    public abstract boolean isSupported(T session);

    protected String getRequiredMessage() {
        return String.format("%s is not supported by this YubiKey", featureName);
    }

    /**
     * A Feature which has a minimum version which it checks against.
     *
     * @param <T> The type of Session for which the Feature is relevant.
     */
    public static class MinVersion<T extends ApplicationSession<T>> extends Feature<T> {
        protected final Version requiredVersion;
        protected final Function<T, Version> getVersion;

        public MinVersion(String featureName, int major, int minor, int build, Function<T, Version> getVersion) {
            super(featureName);
            requiredVersion = new Version(major, minor, build);
            this.getVersion = getVersion;
        }

        @Override
        protected String getRequiredMessage() {
            return String.format("%s requires YubiKey %s or later", featureName, requiredVersion);
        }

        @Override
        public boolean isSupported(T session) {
            Version version = getVersion.apply(session);
            return version.major == 0 || version.compareTo(requiredVersion) >= 0;
        }
    }
}
