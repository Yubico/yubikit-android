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

package com.yubico.yubikit.core.smartcard.scp;

import javax.annotation.Nullable;
import javax.crypto.SecretKey;

/**
 * Session keys for SCP. DEK only needs to be provided if you need to call {@link
 * SecurityDomainSession#putKey}.
 */
public class SessionKeys {
  final SecretKey senc;
  final SecretKey smac;
  final SecretKey srmac;
  @Nullable final SecretKey dek;

  public SessionKeys(SecretKey senc, SecretKey smac, SecretKey srmac, @Nullable SecretKey dek) {
    this.senc = senc;
    this.smac = smac;
    this.srmac = srmac;
    this.dek = dek;
  }
}
