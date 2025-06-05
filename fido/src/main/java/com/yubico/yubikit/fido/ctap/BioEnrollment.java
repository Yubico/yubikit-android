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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.application.CommandException;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

/**
 * Implements Bio enrollment commands.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorBioEnrollment">authenticatorBioEnrollment</a>
 */
public class BioEnrollment {
  protected static final int RESULT_MODALITY = 0x01;
  protected static final int MODALITY_FINGERPRINT = 0x01;

  protected final Ctap2Session ctap;
  protected final int modality;

  public BioEnrollment(Ctap2Session ctap, int modality) throws IOException, CommandException {
    if (!isSupported(ctap.getCachedInfo())) {
      throw new IllegalStateException("Bio enrollment not supported");
    }

    this.ctap = ctap;
    this.modality = getModality(ctap);

    if (this.modality != modality) {
      throw new IllegalStateException("Device does not support modality " + modality);
    }
  }

  public static boolean isSupported(Ctap2Session.InfoData info) {
    final Map<String, ?> options = info.getOptions();
    if (options.containsKey("bioEnroll")) {
      return true;
    } else
      return info.getVersions().contains("FIDO_2_1_PRE")
          && options.containsKey("userVerificationMgmtPreview");
  }

  /**
   * Get the type of modality the authenticator supports.
   *
   * @param ctap CTAP2 session
   * @return The type of modality authenticator supports. For fingerprint, its value is 1.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getUserVerificationModality">Get
   *     bio modality</a>
   */
  public static int getModality(Ctap2Session ctap) throws IOException, CommandException {
    final Map<Integer, ?> result =
        ctap.bioEnrollment(null, null, null, null, null, Boolean.TRUE, null);
    return Objects.requireNonNull((Integer) result.get(RESULT_MODALITY));
  }
}
