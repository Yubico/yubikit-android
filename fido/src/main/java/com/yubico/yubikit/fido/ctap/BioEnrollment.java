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

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

@SuppressWarnings("unused")
public class BioEnrollment {
    private static final int RESULT_MODALITY = 0x01;
    private static final int RESULT_FINGERPRINT_KIND = 0x02;
    private static final int RESULT_MAX_SAMPLES_REQUIRED = 0x03;
    public static final int RESULT_TEMPLATE_ID = 0x04;
    public static final int RESULT_LAST_SAMPLE_STATUS = 0x05;
    public static final int RESULT_REMAINING_SAMPLES = 0x06;
    public static final int RESULT_TEMPLATE_INFOS = 0x07;
    public static final int RESULT_MAX_TEMPLATE_FRIENDLY_NAME = 0x08;

    protected static final int TEMPLATE_INFO_ID = 0x01;
    protected static final int TEMPLATE_INFO_NAME = 0x02;

    static final int MODALITY_FINGERPRINT = 0x01;

    protected final Ctap2Session ctap;
    protected final int modality;

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BioEnrollment.class);

    public BioEnrollment(Ctap2Session ctap, int modality) throws IOException, CommandException {
        if (!isSupported(ctap.getCachedInfo())) {
            throw new IllegalStateException("Bio enrollment not supported");
        }

        this.ctap = ctap;
        this.modality = getModality();

        if (this.modality != modality) {
            throw new IllegalStateException("Device does not support modality " + modality);
        }
    }

    public static boolean isSupported(Ctap2Session.InfoData info) {
        final Map<String, ?> options = info.getOptions();
        if (options.containsKey("bioEnroll")) {
            return true;
        } else return info.getVersions().contains("FIDO_2_1_PRE") &&
                options.containsKey("userVerificationMgmtPreview");
    }

    public int getModality() throws IOException, CommandException {
        final Map<Integer, ?> result = ctap.bioEnrollment(
                null,
                null,
                null,
                null,
                null,
                Boolean.TRUE,
                null);
        return Objects.requireNonNull((Integer) result.get(RESULT_MODALITY));
    }
}
