package com.yubico.yubikit.android.ui;

import android.content.Intent;
import android.os.Bundle;

import androidx.annotation.WorkerThread;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.util.Pair;

import javax.annotation.Nullable;

/**
 * Action to be performed by a {@link YubiKeyPromptActivity} when a YubiKey is attached.
 * Extend this class to handle an attached YubiKey from a YubiKeyPromptActivity, capable of providing a specific type of connection.
 *
 * @param <T> The connection type to handle
 */
public abstract class YubiKeyPromptConnectionAction<T extends YubiKeyConnection> extends YubiKeyPromptAction {
    final Class<T> connectionType;

    /**
     * Subclasses need to provide a default (no-arg) constructor which calls this parent constructor.
     *
     * @param connectionType the type of connection used
     */
    protected YubiKeyPromptConnectionAction(Class<T> connectionType) {
        this.connectionType = connectionType;
    }

    @Nullable
    @Override
    final Pair<Integer, Intent> onYubiKey(YubiKeyDevice device, Bundle extras, CommandState commandState) {
        if (device.supportsConnection(connectionType)) {
            try (T connection = device.openConnection(connectionType)) {
                return onYubiKeyConnection(connection, extras, commandState);
            } catch (Exception e) {
                onError(e);
            }
        } else {
            Logger.d("Connected YubiKey does not support desired connection type");
        }
        return null;
    }

    /**
     * Called when a YubiKey supporting the desired connection type is connected.
     * <p>
     * Subclasses should override this method to react to a connected YubiKey.
     * Return a value to cause the dialog to finish, returning the Intent to the caller, using
     * the given result code. Return null to keep the dialog open to process additional YubiKey
     * connections. The CommandState can be used to update the dialog UI based on status of the
     * operation, and is cancelled if the user presses the cancel button.
     * NOTE: Subclasses should not close the connection, as it will be closed automatically.
     *
     * @param connection   A YubiKey connection
     * @param extras       the extras the Activity was called with
     * @param commandState a CommandState that is hooked up to the activity.
     * @return the result of the operation, as a Pair of result code and Intent with extras, or null
     */
    @Nullable
    @WorkerThread
    protected abstract Pair<Integer, Intent> onYubiKeyConnection(T connection, Bundle extras, CommandState commandState);

    /**
     * Overridable method called if opening a connection to a YubiKey throws an error.
     *
     * @param exception the Exception raised
     */
    @WorkerThread
    protected void onError(Exception exception) {
        Logger.e("Error connecting to YubiKey", exception);
    }
}