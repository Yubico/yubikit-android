/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.testing;

import android.content.Context;
import android.content.res.AssetManager;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AndroidAllowListProvider implements AllowList.AllowListProvider {
  private static final Logger logger = LoggerFactory.getLogger(AndroidAllowListProvider.class);
  private static final String ALLOW_LIST_FILENAME = "allowed_serials.csv";

  @Override
  public List<Integer> getList() {
    Context context = InstrumentationRegistry.getInstrumentation().getContext();
    AssetManager assetManager = context.getAssets();
    List<Integer> allowedSerials = new ArrayList<>();

    try (InputStream inputStream = assetManager.open(ALLOW_LIST_FILENAME);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
      String line;
      while ((line = reader.readLine()) != null) {
        Arrays.stream(line.split(","))
            .map(String::trim)
            .forEach(
                s -> {
                  try {
                    allowedSerials.add(Integer.parseInt(s));
                  } catch (NumberFormatException e) {
                    logger.warn("Invalid serial number format: {}", s);
                  }
                });
      }
    } catch (IOException ignored) {
    }

    return allowedSerials;
  }

  @Override
  public String onEmptyListErrorMessage() {
    return "For running the integrations tests, add serial numbers of test devices to "
        + ALLOW_LIST_FILENAME;
  }

  @Override
  public String onNotAllowedErrorMessage(Integer serialNumber) {
    return "Device with serial number "
        + serialNumber
        + " is not allowed for integration tests. "
        + "Add the serial number to assets/"
        + ALLOW_LIST_FILENAME;
  }
}
