/*
 * Copyright (C) 2020-2023 Yubico.
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

package com.yubico.yubikit.fido.client;

/**
 * A ClientError indicating that UserEntity information isn't available for assertions returned by
 * the Authenticator. This happens when {@link BasicWebAuthnClient#getAssertion} is called without
 * providing PIV or UV, when returning discoverable credentials.
 */
public class UserInformationNotAvailableError extends ClientError {
  public UserInformationNotAvailableError() {
    super(Code.OTHER_ERROR, "User information is not available unless PIN/UV is provided");
  }
}
