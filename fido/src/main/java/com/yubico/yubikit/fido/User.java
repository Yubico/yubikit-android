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

package com.yubico.yubikit.fido;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * User Account Parameters for Credential Generation
 * Entity that contains identity properties for MakeCredentialsOptions
 */
public class User implements Parcelable {

    /**
     * An ArrayBuffer containing an opaque user identifier (the user handle).
     */
    @NonNull final byte[] id;

    /**
     * Name (locale independent)
     */
    @NonNull final String name;

    /**
     * A human-palatable name for the user account, intended only for display.
     */
    @NonNull final String displayName;

    /**
     * Reference to icon
     */
    @Nullable final String icon;

    /**
     * Creates new instance of {@code User}
     * @param id    The user handle of the user account entity.
     *              To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id member,
     *              not the displayName nor name members
     * @param name  Name (locale independent)
     * @param displayName A human-palatable name for the user account, intended only for display.
     * @param icon  Reference to icon
     */
    public User(@NonNull byte[] id, @NonNull String name, @NonNull String displayName, @Nullable String icon) {
        this.id = id;
        this.name = name;
        this.displayName = displayName;
        this.icon = icon;
    }

    /**
     * Creates new instance of {@code User}
     * @param id    The user handle of the user account entity.
     *              To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id member,
     *              not the displayName nor name members
     * @param name  Name (locale independent)
     * @param displayName A human-palatable name for the user account, intended only for display.
     */
    public User(byte[] id, String name, String displayName) {
        this(id, name, displayName, null);
    }

    protected User(Parcel in) {
        id = in.createByteArray();
        name = in.readString();
        displayName = in.readString();
        icon = in.readString();
    }

    public static final Creator<User> CREATOR = new Creator<User>() {
        @Override
        public User createFromParcel(Parcel in) {
            return new User(in);
        }

        @Override
        public User[] newArray(int size) {
            return new User[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeByteArray(id);
        dest.writeString(name);
        dest.writeString(displayName);
        dest.writeString(icon);
    }
}
