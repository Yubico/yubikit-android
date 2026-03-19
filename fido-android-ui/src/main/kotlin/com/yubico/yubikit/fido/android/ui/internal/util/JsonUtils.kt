/*
 * Copyright (C) 2025-2026 Yubico.
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

package com.yubico.yubikit.fido.android.ui.internal.util

import org.json.JSONArray
import org.json.JSONObject

internal fun JSONObject.toMap(): Map<String, *> =
    keys().asSequence().associateWith {
        when (val value = this[it]) {
            is JSONArray -> value.toList()
            is JSONObject -> value.toMap()
            JSONObject.NULL -> null
            else -> value
        }
    }

private fun JSONArray.toList(): List<*> =
    (0 until length()).map { index ->
        when (val element = this[index]) {
            is JSONArray -> element.toList()
            is JSONObject -> element.toMap()
            JSONObject.NULL -> null
            else -> element
        }
    }
