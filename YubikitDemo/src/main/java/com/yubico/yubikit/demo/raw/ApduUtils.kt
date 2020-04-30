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
import com.yubico.yubikit.apdu.ApduUtils
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.transport.Iso7816Connection
import java.io.ByteArrayOutputStream

/**
 * Methods that allow to send APDU commands that might have output that doesn't fit into 1 APDU blob
 * If you use that logic in your app
 * There is such method in yubikit that you can use without copying this code
 * sendAndReceiveWithRemaining(Iso7816Connection, Apdu, 0xC0)
 */
@Throws(ApduException::class)
fun Iso7816Connection.transceive(command : Apdu) : ByteArray = ApduUtils.sendAndReceive(this, command)
