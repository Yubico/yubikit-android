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
 * WebAuthn Relying Party. The entity whose web application utilizes the Web Authentication API to register and authenticate users.
 *
 * Note: An RP ID is based on a host's domain name. It does not itself include a scheme or port, as an origin does.
 * The RP ID of a public key credential determines its scope. I.e., it determines the set of origins on which the public key credential may be exercised, as follows:
 * The RP ID must be equal to the origin's effective domain, or a registrable domain suffix of the origin's effective domain.
 *
 * The origin's scheme must be https.
 * The origin's port is unrestricted.
 *
 * For example, given a Relying Party whose origin is https://login.example.com:1337,
 * then the following RP IDs are valid: login.example.com (default) and example.com, but not m.login.example.com and not com.
 */
public class RelyingParty implements Parcelable {

    /**
     * A valid domain string that identifies the WebAuthn Relying Party on whose behalf a given registration or authentication ceremony is being performed.
     * A public key credential can only be used for authentication with the same entity (as identified by RP ID) it was registered with.
     */
    @NonNull final String id;

    /**
     * Name (locale independent)
     */
    @NonNull final String name;

    /**
     * Reference to icon
     */
    @Nullable final String icon;

    /**
     * Creates an instance of {@code RelyingParty}
     * @param id A valid domain string that identifies the WebAuthn Relying Party on whose behalf a given registration or authentication ceremony is being performed.
     * @param name Name (locale independent)
     * @param icon Reference to icon
     */
    public RelyingParty(@NonNull String id, @NonNull String name, @Nullable String icon) {
        this.id = id;
        this.name = name;
        this.icon = icon;
    }

    /**
     * Creates an instance of {@code RelyingParty}
     * @param id A valid domain string that identifies the WebAuthn Relying Party on whose behalf a given registration or authentication ceremony is being performed.
     * @param name Name (locale independent)
     */
    public RelyingParty(String id, String name) {
        this(id, name, null);
    }

    protected RelyingParty(Parcel in) {
        id = in.readString();
        name = in.readString();
        icon = in.readString();
    }

    public static final Creator<RelyingParty> CREATOR = new Creator<RelyingParty>() {
        @Override
        public RelyingParty createFromParcel(Parcel in) {
            return new RelyingParty(in);
        }

        @Override
        public RelyingParty[] newArray(int size) {
            return new RelyingParty[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(id);
        dest.writeString(name);
        dest.writeString(icon);
    }
}
