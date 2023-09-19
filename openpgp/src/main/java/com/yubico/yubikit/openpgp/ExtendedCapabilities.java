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

package com.yubico.yubikit.openpgp;

import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

public class ExtendedCapabilities {
    private final EnumSet<ExtendedCapabilityFlag> flags;
    private final int smAlgorithm;
    private final int challengeMaxLength;
    private final int certificateMaxLength;
    private final int specialDoMaxLength;
    private final boolean pinBlock2Format;
    private final boolean mseCommand;

    public ExtendedCapabilities(
            EnumSet<ExtendedCapabilityFlag> flags,
            int smAlgorithm,
            int challengeMaxLength,
            int certificateMaxLength,
            int specialDoMaxLength,
            boolean pinBlock2Format,
            boolean mseCommand
    ) {
        this.flags = flags;
        this.smAlgorithm = smAlgorithm;
        this.challengeMaxLength = challengeMaxLength;
        this.certificateMaxLength = certificateMaxLength;
        this.specialDoMaxLength = specialDoMaxLength;
        this.pinBlock2Format = pinBlock2Format;
        this.mseCommand = mseCommand;
    }

    public EnumSet<ExtendedCapabilityFlag> getFlags() {
        return flags;
    }

    public int getSmAlgorithm() {
        return smAlgorithm;
    }

    public int getChallengeMaxLength() {
        return challengeMaxLength;
    }

    public int getCertificateMaxLength() {
        return certificateMaxLength;
    }

    public int getSpecialDoMaxLength() {
        return specialDoMaxLength;
    }

    public boolean isPinBlock2Format() {
        return pinBlock2Format;
    }

    public boolean isMseCommand() {
        return mseCommand;
    }

    static ExtendedCapabilities parse(byte[] encoded) {
        ByteBuffer buf = ByteBuffer.wrap(encoded);
        byte flags = buf.get();
        Set<ExtendedCapabilityFlag> flagSet = new HashSet<>();
        for (ExtendedCapabilityFlag flag : ExtendedCapabilityFlag.values()) {
            if ((flag.value & flags) != 0) {
                flagSet.add(flag);
            }
        }
        return new ExtendedCapabilities(
                EnumSet.copyOf(flagSet),
                0xffff & buf.get(),
                0xffff & buf.getShort(),
                0xffff & buf.getShort(),
                0xffff & buf.getShort(),
                buf.get() == 1,
                buf.get() == 1
        );
    }
}
