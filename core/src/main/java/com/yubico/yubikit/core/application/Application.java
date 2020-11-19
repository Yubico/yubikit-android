package com.yubico.yubikit.core.application;

import com.yubico.yubikit.core.Version;

import java.util.function.Function;

/**
 * Marker interface for YubiKey Application types.
 */
public abstract class Application {
    protected Application() {
        throw new IllegalStateException("Application cannot be instantiated");
    }

    /**
     * A feature for an Application, which may not be supported by all YubiKeys.
     *
     * @param <T> The type of Session for which the Feature is relevant.
     */
    public static abstract class Feature<T extends Application> {
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
        public abstract boolean isSupported(ApplicationSession<T> session);

        protected String getRequiredMessage() {
            return String.format("%s is not supported by this YubiKey", featureName);
        }
    }

    /**
     * A Feature which has a minimum version which it checks against.
     *
     * @param <T> The type of Session for which the Feature is relevant.
     */
    public static class VersionedFeature<T extends Application, S extends ApplicationSession<T>> extends Feature<T> {
        public final Version requiredVersion;
        protected final Function<S, Version> getVersion;

        public VersionedFeature(String featureName, int major, int minor, int build, Function<S, Version> getVersion) {
            super(featureName);
            requiredVersion = new Version(major, minor, build);
            this.getVersion = getVersion;
        }

        @Override
        protected String getRequiredMessage() {
            return String.format("%s requires YubiKey %s or later", featureName, requiredVersion);
        }

        public boolean supports(Version version) {
            return version.major == 0 || requiredVersion.compareTo(version) >= 0;
        }

        @Override
        public boolean isSupported(ApplicationSession<T> session) {
            try {
                return supports(getVersion.apply((S) session));
            } catch (ClassCastException ignored) {
                return false;
            }
        }
    }
}
