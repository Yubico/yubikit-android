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

package com.yubico.yubikit.apdu;

/**
 * Thrown when received response has no valid/expected data or requested operation with arguments that don't meet requirements
 */
public class ApduException extends Exception {
    static final long serialVersionUID = 1L;

    public ApduException(String message) {
        super(message);
    }

    public ApduException(String message, Throwable cause) {
        super(message, cause);
    }
}
