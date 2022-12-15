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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.management.DeviceConfig;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.FormFactor;

import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

public class Util {
    static class InfoBuilder {

        private final FormFactor formFactor;
        private boolean isNfc = false;
        private boolean isSky = false;
        private @Nullable Integer serialNumber = null;

        public InfoBuilder(FormFactor formFactor) {
            this.formFactor = formFactor;
        }

        InfoBuilder withNfc() {
            this.isNfc = true;
            return this;
        }

        InfoBuilder isSky() {
            this.isSky = true;
            return this;
        }

        InfoBuilder withSerialNumber() {
            this.serialNumber = 123;
            return this;
        }

        public DeviceInfo build() {
            Map<Transport, Integer> supportedCapabilities = new HashMap<Transport, Integer>() {
                {
                    put(Transport.USB, 0xFF);
                    if (isNfc) {
                        put(Transport.NFC, 0xFF);
                    }
                }
            };
            return new DeviceInfo(new DeviceConfig.Builder().build(),
                    serialNumber,
                    new Version(5, 3, 0),
                    formFactor,
                    supportedCapabilities,
                    false, false, isSky);
        }
    }

    static DeviceInfo info(FormFactor formFactor) {
        return new InfoBuilder(formFactor).build();
    }

    static DeviceInfo infoNfc(FormFactor formFactor) {
        return new InfoBuilder(formFactor).withNfc().build();
    }

    static DeviceInfo infoSky(FormFactor formFactor) {
        return new InfoBuilder(formFactor).isSky().withNfc().build();
    }

    static DeviceInfo infoSkyEnterprise(FormFactor formFactor) {
        return new InfoBuilder(formFactor).isSky().withNfc().withSerialNumber().build();
    }
}
