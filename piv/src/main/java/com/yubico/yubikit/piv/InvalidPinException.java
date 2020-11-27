/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.application.CommandException;

/**
 * Thrown when the wrong PIN or PUK is used (or when the PIN or PUK is in a blocked state).
 */
public class InvalidPinException extends CommandException {
    private final int attemptsRemaining;

    public InvalidPinException(int attemptsRemaining) {
        super("Invalid PIN/PUK. Remaining attempts: " + attemptsRemaining);
        this.attemptsRemaining = attemptsRemaining;
    }

    public int getAttemptsRemaining() {
        return attemptsRemaining;
    }
}
