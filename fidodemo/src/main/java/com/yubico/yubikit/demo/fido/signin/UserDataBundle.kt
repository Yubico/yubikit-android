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

package com.yubico.yubikit.demo.fido.signin

import android.os.Bundle
import com.yubico.yubikit.demo.fido.communication.User

private const val ARG_USER_DATA = "user-data"

class UserDataBundle(private val userData: User) {

    val bundle: Bundle
        get() = Bundle().apply {
            putSerializable(ARG_USER_DATA, userData)
        }

    companion object {
        fun getUserData(arguments: Bundle?) : User {
            require(arguments != null) { "Use UserDataBundle and pass arguments to create this fragment" }
            return arguments.getSerializable(ARG_USER_DATA) as User
        }
    }
}