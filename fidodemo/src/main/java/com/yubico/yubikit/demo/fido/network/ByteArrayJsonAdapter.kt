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

package com.yubico.yubikit.demo.fido.network

import android.util.Base64
import com.squareup.moshi.*

/**
 * Converts ByteArray values to JSON and JSON values to ByteArray.
 */
class ByteArrayJsonAdapter: JsonAdapter<ByteArray>() {
    @FromJson
    override fun fromJson(reader: JsonReader): ByteArray? {
        val string = reader.nextString()
        return Base64.decode(string, Base64.DEFAULT)
    }

    @ToJson
    override fun toJson(writer: JsonWriter, value: ByteArray?) {
        var string: String? = null
        value?.run {
            string = Base64.encodeToString(value, Base64.DEFAULT)
        }
        writer.value(string)
    }
}