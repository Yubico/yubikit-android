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
import java.util.Arrays;
import java.util.Objects;

abstract class AlgorithmAttributes {
    private final byte algorithmId;

    AlgorithmAttributes(byte algorithmId) {
        this.algorithmId = algorithmId;
    }

    byte getAlgorithmId() {
        return algorithmId;
    }

    abstract byte[] getBytes();

    static AlgorithmAttributes parse(byte[] encoded) {
        ByteBuffer buf = ByteBuffer.wrap(encoded);
        byte algorithmId = buf.get();
        switch (algorithmId) {
            case 1:
                return Rsa.parse(algorithmId, buf);
            case 0x12:
            case 0x13:
            case 0x16:
                return Ec.parse(algorithmId, buf);
            default:
                throw new IllegalArgumentException("Unsupported algorithm ID");
        }
    }

    static class Rsa extends AlgorithmAttributes {
        enum ImportFormat {
            STANDARD((byte) 0),
            STANDARD_W_MOD((byte) 1),
            CRT((byte) 2),
            CRT_W_MOD((byte) 3);
            public final byte value;

            ImportFormat(byte value) {
                this.value = value;
            }

            static ImportFormat fromValue(int value) {
                for (ImportFormat type : ImportFormat.values()) {
                    if (type.value == value) {
                        return type;
                    }
                }
                throw new IllegalArgumentException("Not a valid ImportFormat:" + value);
            }
        }

        private final int nLen;
        private final int eLen;
        private final ImportFormat importFormat;

        Rsa(byte algorithmId, int nLen, int eLen, ImportFormat importFormat) {
            super(algorithmId);
            this.nLen = nLen;
            this.eLen = eLen;
            this.importFormat = importFormat;
        }

        int getNLen() {
            return nLen;
        }

        int getELen() {
            return eLen;
        }

        @Override
        byte[] getBytes() {
            return ByteBuffer.allocate(6)
                    .put(getAlgorithmId())
                    .putShort((short) nLen)
                    .putShort((short) eLen)
                    .put(importFormat.value)
                    .array();
        }

        static Rsa parse(byte algorithmId, ByteBuffer buf) {
            return new Rsa(
                    algorithmId,
                    0xffff & buf.getShort(),
                    0xffff & buf.getShort(),
                    ImportFormat.fromValue(buf.get())
            );
        }

        static Rsa create(int nLen, ImportFormat importFormat) {
            return new Rsa((byte) 1, nLen, 17, importFormat);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Rsa that = (Rsa) o;
            return nLen == that.nLen && eLen == that.eLen && importFormat == that.importFormat;
        }

        @Override
        public int hashCode() {
            return Objects.hash(nLen, eLen, importFormat);
        }

        @Override
        public String toString() {
            return "Rsa{" +
                    "algorithmId=" + getAlgorithmId() +
                    ", nLen=" + nLen +
                    ", eLen=" + eLen +
                    ", importFormat=" + importFormat +
                    '}';
        }
    }

    static class Ec extends AlgorithmAttributes {
        enum ImportFormat {
            STANDARD((byte) 0),
            STANDARD_W_PUBKEY((byte) 0xff);
            public final byte value;

            ImportFormat(byte value) {
                this.value = value;
            }

            static ImportFormat fromValue(int value) {
                for (ImportFormat type : ImportFormat.values()) {
                    if (type.value == value) {
                        return type;
                    }
                }
                throw new IllegalArgumentException("Not a valid ImportFormat:" + value);
            }
        }

        private final OpenPgpCurve curve;
        private final ImportFormat importFormat;

        Ec(byte algorithmId, OpenPgpCurve curve, ImportFormat importFormat) {
            super(algorithmId);
            this.curve = curve;
            this.importFormat = importFormat;
        }

        OpenPgpCurve getCurve() {
            return curve;
        }

        ImportFormat getImportFormat() {
            return importFormat;
        }

        @Override
        byte[] getBytes() {
            byte[] oidBytes = curve.getOid();
            byte[] bytes = ByteBuffer.allocate(1 + oidBytes.length)
                    .put(getAlgorithmId())
                    .put(oidBytes)
                    .array();
            if (importFormat == ImportFormat.STANDARD_W_PUBKEY) {
                bytes = Arrays.copyOf(bytes, bytes.length + 1);
                bytes[bytes.length - 1] = importFormat.value;
            }
            return bytes;
        }

        static Ec parse(byte algorithmId, ByteBuffer buf) {
            if (buf.get(buf.remaining()) == ImportFormat.STANDARD_W_PUBKEY.value) {
                return new Ec(
                        algorithmId,
                        OpenPgpCurve.fromOid(Arrays.copyOfRange(buf.array(), buf.position(), buf.limit() - 1)),
                        ImportFormat.STANDARD_W_PUBKEY
                );
            }
            // Standard is defined as "format byte not present"
            return new Ec(
                    algorithmId,
                    OpenPgpCurve.fromOid(Arrays.copyOfRange(buf.array(), buf.position(), buf.limit())),
                    ImportFormat.STANDARD
            );
        }

        static Ec create(KeyRef keyRef, OpenPgpCurve curve) {
            byte algId;
            if (curve == OpenPgpCurve.Ed25519) {
                algId = 0x16; // EdDSA
            } else if (keyRef == KeyRef.DEC) {
                algId = 0x12; // ECDH
            } else {
                algId = 0x13; // ECDSA
            }
            return new Ec(algId, curve, ImportFormat.STANDARD);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Ec that = (Ec) o;
            return curve == that.curve && importFormat == that.importFormat;
        }

        @Override
        public int hashCode() {
            return Objects.hash(curve, importFormat);
        }

        @Override
        public String toString() {
            return "Ec{" +
                    "algorithmId=" + getAlgorithmId() +
                    ", curve=" + curve +
                    ", importFormat=" + importFormat +
                    '}';
        }
    }
}
