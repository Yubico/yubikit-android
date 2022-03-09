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

package com.yubico.yubikit.support;

import com.yubico.yubikit.core.Version;

public class VersionUtil {
    static boolean isFips(Version version) {
        return version.isAtLeast(4, 4, 0) && version.isLessThan(4, 5, 0);
    }

    static boolean isPreview(Version version) {
        return (version.isAtLeast(5, 0, 0) && version.isLessThan(5, 1, 0))
                || (version.isAtLeast(5, 2, 0) && version.isLessThan(5, 2, 3))
                || (version.isAtLeast(5, 5, 0) && version.isLessThan(5, 5, 2));
    }
}
