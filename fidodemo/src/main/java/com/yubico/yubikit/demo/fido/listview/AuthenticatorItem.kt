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

package com.yubico.yubikit.demo.fido.listview

import android.os.Parcel
import android.os.Parcelable
import com.yubico.yubikit.fido.AuthenticatorAttachment
import java.util.*

/**
 * An authenticator/key item representing a content in RecycleView.
 */
data class AuthenticatorItem (
        val id: String,
        val name: String,
        val deviceType: String,
        val lastUsed: Date,
        val registeredAt: Date,
        val type: String,
        val authenticatorAttachment: AuthenticatorAttachment?
) : Parcelable {
    constructor(parcel: Parcel) : this(
            parcel.readString()!!,
            parcel.readString()!!,
            parcel.readString()!!,
            Date(parcel.readLong()),
            Date(parcel.readLong()),
            parcel.readString()!!,
            parcel.readSerializable() as AuthenticatorAttachment)

    override fun writeToParcel(dest: Parcel?, flags: Int) {
        dest?.writeString(id)
        dest?.writeString(name)
        dest?.writeString(deviceType)
        dest?.writeLong(lastUsed.time)
        dest?.writeLong(registeredAt.time)
        dest?.writeString(type)
        dest?.writeSerializable(authenticatorAttachment)
    }

    override fun describeContents(): Int {
        return 0
    }

    companion object CREATOR : Parcelable.Creator<AuthenticatorItem> {
        override fun createFromParcel(parcel: Parcel): AuthenticatorItem {
            return AuthenticatorItem(parcel)
        }

        override fun newArray(size: Int): Array<AuthenticatorItem?> {
            return arrayOfNulls(size)
        }
    }

}