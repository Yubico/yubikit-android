package com.yubico.yubikit.core;

import java.io.Closeable;

/**
 * A base class for Sessions with a YubiKey. Subclasses should use their own type as the parameter T:
 * <pre>{@code class FooSession extends ApplicationSession<FooSession>}</pre>
 *
 * @param <T> the type of the subclass
 */
public abstract class ApplicationSession<T extends ApplicationSession<T>> implements Closeable {
    /**
     * Check if a Feature is supported by the YubiKey.
     *
     * @param feature the Feature to check support for.
     * @return true if the Feature is supported, false if not.
     */
    public boolean supports(Feature<T> feature) {
        return feature.isSupported((T) this);
    }

    protected void require(Feature<T> feature) {
        if (!supports(feature)) {
            throw new NotSupportedException(feature.getRequiredMessage());
        }
    }
}
