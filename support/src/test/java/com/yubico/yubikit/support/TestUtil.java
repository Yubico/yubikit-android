/*
 * Copyright (C) 2024 Yubico.
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

import com.yubico.yubikit.management.DeviceConfig;
import com.yubico.yubikit.management.DeviceInfo;

class TestUtil {
  interface DeviceConfigBuilder {
    void createWith(DeviceConfig.Builder builder);
  }

  static DeviceConfig config(DeviceConfigBuilder configBuilder) {
    DeviceConfig.Builder builder = new DeviceConfig.Builder();
    configBuilder.createWith(builder);
    return builder.build();
  }

  interface DeviceInfoBuilder {
    void createWith(DeviceInfo.Builder builder);
  }

  static DeviceInfo info(DeviceInfoBuilder infoBuilder) {
    DeviceInfo.Builder builder = new DeviceInfo.Builder();
    infoBuilder.createWith(builder);
    return builder.build();
  }
}
