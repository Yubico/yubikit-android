/*
 * Copyright (C) 2022-2023 Yubico.
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

package com.yubico.yubikit.android.ui;

import android.content.Intent;
import android.os.Bundle;
import androidx.annotation.WorkerThread;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Pair;
import java.io.IOException;
import org.slf4j.LoggerFactory;

/**
 * Action to be performed by a {@link YubiKeyPromptActivity} when a YubiKey is attached.
 *
 * <p>Extend this class to handle an attached YubiKey from a YubiKeyPromptActivity, capable of
 * providing a specific type of connection.
 *
 * @param <T> The connection type to handle
 */
public abstract class YubiKeyPromptConnectionAction<T extends YubiKeyConnection>
    extends YubiKeyPromptAction {

  final Class<T> connectionType;

  private static final org.slf4j.Logger logger =
      LoggerFactory.getLogger(YubiKeyPromptConnectionAction.class);

  /**
   * Subclasses need to provide a default (no-arg) constructor which calls this parent constructor.
   *
   * @param connectionType the type of connection used
   */
  protected YubiKeyPromptConnectionAction(Class<T> connectionType) {
    this.connectionType = connectionType;
  }

  @Override
  final void onYubiKey(
      YubiKeyDevice device,
      Bundle extras,
      CommandState commandState,
      Callback<Pair<Integer, Intent>> callback) {
    if (device.supportsConnection(connectionType)) {
      device.requestConnection(
          connectionType,
          value -> {
            try {
              callback.invoke(onYubiKeyConnection(value.getValue(), extras, commandState));
            } catch (IOException exception) {
              onError(exception);
            }
          });
    } else {
      Logger.debug(logger, "Connected YubiKey does not support desired connection type");
      callback.invoke(CONTINUE);
    }
  }

  /**
   * Called when a YubiKey supporting the desired connection type is connected.
   *
   * <p>Subclasses should override this method to react to a connected YubiKey. Return a value to
   * cause the dialog to finish, returning the Intent to the caller, using the given result code.
   * Return {@link #CONTINUE} to keep the dialog open to process additional connections. The
   * CommandState can be used to update the dialog UI based on status of the operation, and is
   * cancelled if the user presses the cancel button. NOTE: Subclasses should not close the
   * connection, as it will be closed automatically.
   *
   * @param connection A YubiKey connection
   * @param extras the extras the Activity was called with
   * @param commandState a CommandState that is hooked up to the activity.
   * @return the result of the operation, as a Pair of result code and Intent with extras, or null
   */
  @WorkerThread
  protected abstract Pair<Integer, Intent> onYubiKeyConnection(
      T connection, Bundle extras, CommandState commandState);

  /**
   * Overridable method called if opening a connection to a YubiKey throws an error.
   *
   * @param exception the Exception raised
   */
  @WorkerThread
  protected void onError(Exception exception) {
    Logger.error(logger, "Error connecting to YubiKey", exception);
  }
}
