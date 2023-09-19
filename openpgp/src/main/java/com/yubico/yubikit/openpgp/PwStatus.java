/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.openpgp;

import java.nio.ByteBuffer;

public class PwStatus {
    private final PinPolicy pinPolicyUser;
    private final int maxLenUser;
    private final int maxLenReset;
    private final int maxLenAdmin;
    private final int attemptsUser;
    private final int attemptsReset;
    private final int attemptsAdmin;

    PwStatus(PinPolicy pinPolicyUser,
             int maxLenUser,
             int maxLenReset,
             int maxLenAdmin,
             int attemptsUser,
             int attemptsReset,
             int attemptsAdmin
    ) {
        this.pinPolicyUser = pinPolicyUser;
        this.maxLenUser = maxLenUser;
        this.maxLenReset = maxLenReset;
        this.maxLenAdmin = maxLenAdmin;
        this.attemptsUser = attemptsUser;
        this.attemptsReset = attemptsReset;
        this.attemptsAdmin = attemptsAdmin;
    }

    public PinPolicy getPinPolicyUser() {
        return pinPolicyUser;
    }

    public int getMaxLenUser() {
        return maxLenUser;
    }

    public int getMaxLenReset() {
        return maxLenReset;
    }

    public int getMaxLenAdmin() {
        return maxLenAdmin;
    }

    public int getAttemptsUser() {
        return attemptsUser;
    }

    public int getAttemptsReset() {
        return attemptsReset;
    }

    public int getAttemptsAdmin() {
        return attemptsAdmin;
    }

    int getAttempts(Pw pw) {
        switch (pw) {
            case USER:
                return attemptsUser;
            case RESET:
                return attemptsReset;
            case ADMIN:
                return attemptsAdmin;
            default:
                throw new IllegalArgumentException();
        }
    }

    static PwStatus parse(byte[] encoded) {
        ByteBuffer buf = ByteBuffer.wrap(encoded);
        return new PwStatus(
                buf.get() == 0 ? PinPolicy.ALWAYS : PinPolicy.ONCE,
                0xff & buf.get(),
                0xff & buf.get(),
                0xff & buf.get(),
                0xff & buf.get(),
                0xff & buf.get(),
                0xff & buf.get()
        );
    }
}
