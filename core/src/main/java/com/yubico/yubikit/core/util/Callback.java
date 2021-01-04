package com.yubico.yubikit.core.util;

/**
 * Generic callback interface.
 *
 * @param <T> the type of the value expected as input to the callback.
 */
public interface Callback<T> {
    void invoke(T value);
}
