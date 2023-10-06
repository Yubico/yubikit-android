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

package com.yubico.yubikit.fido.ctap;

import java.util.List;

public enum FidoVersion {
    INVALID,
    U2F_V2,
    FIDO_2_0,
    FIDO_2_1_PRE,
    FIDO_2_1;

    public static FidoVersion get(List<String> versions) {
        final FidoVersion[] values = FidoVersion.values();
        for(int i = values.length -1 ; i > 0; i --) {
            if (versions.contains(values[i].name())) {
                return values[i];
            }
        }

        return INVALID;
    }
}
