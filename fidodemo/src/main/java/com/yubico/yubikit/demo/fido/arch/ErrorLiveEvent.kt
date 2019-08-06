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

package com.yubico.yubikit.demo.fido.arch

import android.util.Log

class ErrorLiveEvent(private val tag: String) : SingleLiveEvent<Throwable>() {
    override fun setValue(t: Throwable?) {
        super.setValue(t)
        t?.run {
            Log.e(tag, t.message, t)
        }
    }
}