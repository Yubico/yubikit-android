/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.demo.raw

import com.yubico.yubikit.demo.exceptions.InvalidCertDataException
import com.yubico.yubikit.utils.StringUtils
import java.security.*
import java.util.*
import javax.security.cert.CertificateException
import javax.security.cert.X509Certificate

class SecCertificate(keyData: ByteArray) {

    private val certificate: X509Certificate

    init {
        // 1. parse get_object tag that contains certificate_tag
        var mutableData = keyData.copyOf()
        var offset = 0


        val objectTlv = TLV(mutableData)
        if (mutableData.size < objectTlv.length + objectTlv.offset) {
            throw InvalidCertDataException("Invalid TLV format")
        }

        if (objectTlv.tag != TAG_OBJ_DATA) {
            throw InvalidCertDataException(String.format(Locale.ROOT, "Unexpected get object tag %02x", objectTlv.tag.toByte()))
        }

        offset += objectTlv.offset
        mutableData = mutableData.copyOfRange(objectTlv.offset, objectTlv.length + objectTlv.offset)

        // 2. get the actual certificate data.
        val certTlv = TLV(mutableData)
        if (mutableData.size < certTlv.length + certTlv.offset) {
            throw InvalidCertDataException("Invalid TLV format")
        }
        if (certTlv.tag != TAG_CERTIFICATE) {
            throw InvalidCertDataException(String.format(Locale.ROOT, "Unexpected certificate tag %02x", certTlv.tag.toByte()))
        }

        mutableData = mutableData.copyOfRange(certTlv.offset, certTlv.length + certTlv.offset)

        // 3. instantiates an X509Certificate object with provided byte array
        try {
            certificate = X509Certificate.getInstance(mutableData)
        } catch (e: CertificateException) {
            throw InvalidCertDataException("Can't parse certificate data", e)
        }
    }

    @Throws(InvalidCertDataException::class)
    fun verify(data: ByteArray, signature: ByteArray) : Boolean {
        try {
            val privateSignature = Signature.getInstance(certificate.sigAlgName)
            privateSignature.initVerify(certificate.publicKey)
            privateSignature.update(data)
            return privateSignature.verify(signature)
        } catch (e: NoSuchAlgorithmException) {
            throw InvalidCertDataException("Cert algorithm " + certificate.sigAlgName + " is not valid", e)
        } catch (e: InvalidKeyException) {
            throw InvalidCertDataException("Cert key " + StringUtils.convertBytesToString(certificate.publicKey.encoded) + " is not valid", e)
        } catch (e: SignatureException) {
            throw InvalidCertDataException("Signature " + StringUtils.convertBytesToString(signature) + " is not valid", e)
        }
    }

    private class TLV(data: ByteArray) {
        val length : Int
        val offset : Int
        val tag : Int

        init {
            val checkByte = data[1].toInt().and(0xff)
            if (checkByte < 0x81) {
                offset = 2
                length = data[1].toInt().and(0xff)
            } else if (checkByte.and(0x7f) == 0x01)  {
                offset = 3
                length = data[2].toInt().and(0xff)
            } else if (checkByte.and(0x7f) == 0x02) {
                offset = 4
                length = data[2].toInt().and(0xff).shl(8) + data[3].toInt().and(0xff)
            } else {
                length = 0
                offset = 0
            }
            tag = data[0].toInt().and(0xff)
        }
    }

    companion object {
        private const val TAG_CERTIFICATE: Int = 0x70
        private const val TAG_OBJ_DATA: Int = 0x53
    }
}

