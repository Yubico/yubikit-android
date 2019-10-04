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

import com.yubico.yubikit.apdu.Apdu
import com.yubico.yubikit.apdu.ApduCodeException
import com.yubico.yubikit.apdu.ApduException
import com.yubico.yubikit.transport.Iso7816Connection
import java.io.ByteArrayOutputStream

private const val SUCCESS_CODE: Short = 0x9000.toShort()
private const val HAS_MORE_DATA: Byte = 0x61.toByte()

/**
 * Methods that allow to send APDU commands that might have output that doesn't fit into 1 APDU blob
 * If you use that logic in your app
 * There is such method in yubikit that you can use without copying this code
 * sendAndReceiveWithRemaining(Iso7816Connection, Apdu, 0xC0)
 */
@Throws(ApduException::class)
fun Iso7816Connection.transceive(command : Apdu) : ByteArray {
    val readBuffer = ByteArrayOutputStream()
    var apdu = command
    var sendRemaining = true
    while (sendRemaining) {
        val readResponse = this.execute(apdu)
        val statusCode = readResponse.statusCode()
        val responseData = readResponse.responseData()
        when {
            readResponse.hasStatusCode(SUCCESS_CODE) -> {
                sendRemaining = false
            }
            readResponse.hasStatusCode(HAS_MORE_DATA) -> {
                apdu = Apdu(0x00, 0xC0, 0x00, 0x00, null, Apdu.Type.SHORT)
            }
            else -> {
                /**
                 * Smart Card Error Codes
                    Code	Description
                    General Error Codes
                    6400	No specific diagnosis
                    6700	Wrong length in Lc
                    6982	Security status not satisfied
                    6985	Conditions of use not satisfied
                    6a86	Incorrect P1 P2
                    6d00	Invalid instruction
                    6e00	Invalid class
                    Install Load Errors
                    6581	Memory Failure
                    6a80	Incorrect parameters in data field
                    6a84	Not enough memory space
                    6a88	Referenced data not found
                    Delete Errors
                    6200	Application has been logically deleted
                    6581	Memory failure
                    6985	Referenced data cannot be deleted
                    6a88	Referenced data not found
                    6a82	Application not found
                    6a80	Incorrect values in command data
                    Get Data Errors
                    6a88	Referenced data not found
                    Get Status Errors
                    6310	More data available
                    6a88	Referenced data not found
                    6a80	Incorrect values in command data
                    Load Errors
                    6581	Memory failure
                    6a84	Not enough memory space
                    6a86	Incorrect P1/P2
                    6985	Conditions of use not satisfied
                 */
                throw ApduCodeException(statusCode.toInt())
            }
        }
        readBuffer.write(responseData)
    }
    return readBuffer.toByteArray()
}
