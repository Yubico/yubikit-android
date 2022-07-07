/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.core.application;

import com.yubico.yubikit.core.Version;

/**
 * A feature for a YubiKey application, which may not be supported by all YubiKeys.
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
     * Checks if the Feature is supported by the given Application version.
     *
     * @param version the version of the Application to check support for.
     * @return true if the Feature is supported, false if not
     */
    public abstract boolean isSupportedBy(Version version);

    protected String getRequiredMessage() {
        return String.format("%s is not supported by this YubiKey", featureName);
    }

    /**
     * A Feature which has a minimum version which it checks against.
     *
     * @param <T> The type of Session for which the Feature is relevant.
     */
    public static class Versioned<T extends ApplicationSession<T>> extends Feature<T> {
        private final Version requiredVersion;

        public Versioned(String featureName, int major, int minor, int micro) {
            super(featureName);
            requiredVersion = new Version(major, minor, micro);
        }

        @Override
        protected String getRequiredMessage() {
            return String.format("%s requires YubiKey %s or later", featureName, requiredVersion);
        }

        @Override
        public boolean isSupportedBy(Version version) {
            return version.major == 0 || version.compareTo(requiredVersion) >= 0;
        }
    }
}
