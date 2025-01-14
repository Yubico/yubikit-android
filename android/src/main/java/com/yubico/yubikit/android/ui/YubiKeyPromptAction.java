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

package com.yubico.yubikit.android.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Pair;

/**
 * Action to be performed by a {@link YubiKeyPromptActivity} when a YubiKey is attached. Extend this
 * class to handle an attached YubiKey from a YubiKeyPromptActivity.
 *
 * <p>See also {@link YubiKeyPromptConnectionAction} for an alternative which handles YubiKeys for a
 * specific connection type.
 */
public abstract class YubiKeyPromptAction {
  /**
   * A special result code which will reset the dialog state to continue processing additional
   * YubiKeys.
   */
  public static final int RESULT_CONTINUE = Activity.RESULT_FIRST_USER + 100;

  /** A result Pair used to keep the dialog open to continue processing YubiKeys. */
  public static final Pair<Integer, Intent> CONTINUE = new Pair<>(RESULT_CONTINUE, new Intent());

  /**
   * Called when a YubiKey is connected.
   *
   * <p>Subclasses should override this method to react to a connected YubiKey. Use the callback to
   * signal when the method is done handling the YubiKey, with a result (a pair of resultCode,
   * Intent) to return to the caller, closing the dialog. Use the special {@link #CONTINUE} result
   * to leave the dialog open, without returning to the caller, and continue to process additional
   * YubiKeys. The CommandState can be used to update the dialog UI based on status of the
   * operation, and is cancelled if the user presses the cancel button.
   *
   * @param device A YubiKeyDevice
   * @param extras the extras the Activity was called with
   * @param commandState a CommandState that is hooked up to the activity.
   * @param callback a callback to invoke to provide the result of the operation, as a Pair of
   *     result code and Intent with extras
   */
  abstract void onYubiKey(
      YubiKeyDevice device,
      Bundle extras,
      CommandState commandState,
      Callback<Pair<Integer, Intent>> callback);
}
