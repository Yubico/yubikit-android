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

package com.yubico.yubikit.core.internal;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

public enum CurveParams {
    SECP256R1(
            new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07},
            256,
            "115792089210356248762697446949407573530086143415290314195533631308867097853948",
            "41058363725152142129326129780047268409114441015993725554835256314039467401291",
            new byte[]{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}
    ),
    SECP256K1(
            new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x0a},
            256,
            "0",
            "7",
            new byte[]{}
    ),
    SECP384R1(
            new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x22},
            384,
            "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316",
            "27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575",
            new byte[]{}
    ),
    SECP521R1(new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x23},
            521,
            "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148",
            "1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984",
            new byte[]{}
    ),
    BrainpoolP256R1(
            new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07},
            256,
            "56698187605326110043627228396178346077120614539475214109386828188763884139993",
            "17577232497321838841075697789794520262950426058923084567046852300633325438902",
            new byte[]{}
    ),
    BrainpoolP384R1(
            new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b},
            384,
            "19048979039598244295279281525021548448223459855185222892089532512446337024935426033638342846977861914875721218402342",
            "717131854892629093329172042053689661426642816397448020844407951239049616491589607702456460799758882466071646850065",
            new byte[]{}
    ),
    BrainpoolP512R1(
            new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d},
            512,
            "6294860557973063227666421306476379324074715770622746227136910445450301914281276098027990968407983962691151853678563877834221834027439718238065725844264138",
            "3245789008328967059274849584342077916531909009637501918328323668736179176583263496463525128488282611559800773506973771797764811498834995234341530862286627",
            new byte[]{}
    ),
    X25519(
            new byte[]{0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0x97, 0x55, 0x01, 0x05, 0x01},
            256,
            "",
            "",
            new byte[]{}
    ),
    Ed25519(
            new byte[]{0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0xda, 0x47, 0x0f, 0x01},
            256,
            "",
            "",
            new byte[]{}
    );

    private final byte[] oid;
    private final int bitLength;
    private final BigInteger a;
    private final BigInteger b;
    private final byte[] prefix;

    CurveParams(byte[] oid, int bitLength, String a, String b, byte[] prefix) {
        this.oid = oid;
        this.bitLength = bitLength;
        this.a = new BigInteger(a);
        this.b = new BigInteger(b);
        this.prefix = prefix;
    }

    public int getBitLength() {
        return bitLength;
    }

    public byte[] getOid() {
        return Arrays.copyOf(oid, oid.length);
    }

    public byte[] getPrefix() {
        return Arrays.copyOf(prefix, prefix.length);
    }

    public boolean matchesKey(ECKey key) {
        EllipticCurve target = ((ECKey) key).getParams().getCurve();
        return target.getField().getFieldSize() == bitLength && target.getA().equals(a) && target.getB().equals(b);
    }

    public static CurveParams fromKey(Key key) {
        if (key instanceof ECKey) {
            for (CurveParams match : CurveParams.values()) {
                if (match.matchesKey((ECKey) key)) {
                    return match;
                }
            }
        }
        throw new IllegalArgumentException("No curve found matching key");
    }

    public static CurveParams fromOid(byte[] oid) {
        for (CurveParams params : CurveParams.values()) {
            if (Arrays.equals(params.oid, oid)) {
                return params;
            }
        }
        throw new IllegalArgumentException("Not a supported curve OID");
    }
}
