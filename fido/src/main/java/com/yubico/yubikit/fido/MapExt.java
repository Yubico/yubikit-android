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

package com.yubico.yubikit.fido;

import java.util.Arrays;
import java.util.Map;

import javax.annotation.Nullable;

public class MapExt {
    /**
     * Compares two maps and their contents
     *
     * @param l left hand side of equality comparison
     * @param r right hand side of equality comparison
     * @return true if the maps have the same content
     */
    public static boolean equals(@Nullable Map<?, ?> l, @Nullable Map<?, ?> r) {
        if ((l == null && r != null) ||
                (l != null && r == null)) {
            return false;
        }

        if (l == null) {
            return true;
        }

        if (l.getClass() != r.getClass()) {
            return false;
        }

        if (l.size() != r.size()) {
            return false;
        }

        for (Object key : l.keySet()) {
            if (!r.containsKey(key)) {
                return false;
            }

            @Nullable Object value1 = l.get(key);
            @Nullable Object value2 = r.get(key);

            if (value1 == null && value2 == null) {
                continue;
            }

            if (value1 == null || value2 == null) {
                return false;
            }

            if (value1.getClass() != value2.getClass()) {
                return false;
            }

            if (value1 instanceof byte[]) {
                if (!Arrays.equals((byte[]) value1, (byte[]) value2)) {
                    return false;
                }
            } else if (!value1.equals(value2)) {
                return false;
            }
        }

        return true;
    }
}
