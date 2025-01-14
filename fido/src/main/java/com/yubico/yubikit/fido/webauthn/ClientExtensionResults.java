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

package com.yubico.yubikit.fido.webauthn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ClientExtensionResults {

  private final List<ClientExtensionResultProvider> resultProviders = new ArrayList<>();

  public void add(ClientExtensionResultProvider resultProvider) {
    resultProviders.add(resultProvider);
  }

  public Map<String, Object> toMap(SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    for (ClientExtensionResultProvider resultProvider : resultProviders) {
      map.putAll(resultProvider.getClientExtensionResult(serializationType));
    }
    return map;
  }
}
