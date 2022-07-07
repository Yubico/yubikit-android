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

import java.io.Closeable;

/**
 * A base class for Sessions with a YubiKey.
 * <p>
 * Subclasses should use their own type as the parameter T:
 * <pre>{@code class FooSession extends ApplicationSession<FooSession>}</pre>
 *
 * @param <T> the type of the subclass
 */
public abstract class ApplicationSession<T extends ApplicationSession<T>> implements Closeable {
    /**
     * Get the version of the Application from the YubiKey. This is typically the same as the YubiKey firmware, but can be versioned separately as well.
     *
     * @return the Application version
     */
    public abstract Version getVersion();

    /**
     * Check if a Feature is supported by the YubiKey.
     *
     * @param feature the Feature to check support for.
     * @return true if the Feature is supported, false if not.
     */
    public boolean supports(Feature<T> feature) {
        return feature.isSupportedBy(getVersion());
    }

    protected void require(Feature<T> feature) {
        if (!supports(feature)) {
            throw new UnsupportedOperationException(feature.getRequiredMessage());
        }
    }
}
