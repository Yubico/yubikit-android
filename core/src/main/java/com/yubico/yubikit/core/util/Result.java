package com.yubico.yubikit.core.util;

import java.util.concurrent.Callable;

import javax.annotation.Nullable;

/**
 * Result value, wrapping a T (if successful) or an Exception (if failed).
 *
 * @param <T> the type of the wrapped value
 * @param <E> the type of the exception thrown
 */
public class Result<T, E extends Throwable> {
    @Nullable
    private final T value;
    @Nullable
    private final E error;

    private Result(@Nullable T value, @Nullable E error) {
        this.value = value;
        this.error = error;
    }

    /**
     * Gets the held value, if the Result is successful, or throws the error on failure.
     *
     * @return the held value on success
     * @throws E the held exception on failure
     */
    public T getValue() throws E {
        if (value != null) {
            return value;
        }
        assert error != null;
        throw error;
    }

    /**
     * Checks if the Result is successful.
     */
    public boolean isSuccess() {
        return value != null;
    }

    /**
     * Checks if the Result is a failure.
     */
    public boolean isError() {
        return error != null;
    }

    /**
     * Constructs a Result for a value (success).
     *
     * @param value the value to hold
     */
    public static <T, E extends Throwable> Result<T, E> success(T value) {
        return new Result<>(value, null);
    }

    /**
     * Constructs a Result for an Exception (failure).
     *
     * @param error the error to hold
     */
    public static <T, E extends Throwable> Result<T, E> failure(E error) {
        return new Result<>(null, error);
    }

    /**
     * Runs the given callable, creating a Result of its value, if run successfully, or its Exception.
     *
     * @param call callable to invoke, resulting in a value
     */
    public static <T> Result<T, Exception> of(Callable<T> call) {
        try {
            return Result.success(call.call());
        } catch (Exception e) {
            return Result.failure(e);
        }
    }
}
