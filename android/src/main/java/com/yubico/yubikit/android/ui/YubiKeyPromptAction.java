package com.yubico.yubikit.android.ui;

import android.content.Intent;
import android.os.Bundle;

import androidx.annotation.WorkerThread;

import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.util.Pair;

import javax.annotation.Nullable;

/**
 * Action to be performed by a {@link YubiKeyPromptActivity} when a YubiKey is attached.
 * Extend this class to handle an attached YubiKey from a YubiKeyPromptActivity.
 *
 * See also {@link YubiKeyPromptConnectionAction} for an alternative which handles YubiKeys for a
 * specific connection type.
 */
public abstract class YubiKeyPromptAction {
    /**
     * Called when a YubiKey is connected.
     * <p>
     * Subclasses should override this method to react to a connected YubiKey.
     * Return a value to cause the dialog to finish, returning the Intent to the caller, using
     * the given result code. Return null to keep the dialog open to process additional YubiKeys.
     * The CommandState can be used to update the dialog UI based on status of the
     * operation, and is cancelled if the user presses the cancel button.
     * NOTE: Subclasses should not close the connection, as it will be closed automatically.
     *
     * @param device       A YubiKeyDevice
     * @param extras       the extras the Activity was called with
     * @param commandState a CommandState that is hooked up to the activity.
     * @return the result of the operation, as a Pair of result code and Intent with extras, or null
     */
    @Nullable
    @WorkerThread
    abstract Pair<Integer, Intent> onYubiKey(YubiKeyDevice device, Bundle extras, CommandState commandState);
}
