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

import java.util.ArrayList;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * {@code GetAssertionOptions} represents request to authenticator from server to assert/authenticate key/fingerprint
 */
public class GetAssertionOptions implements Parcelable {

    /**
     * A valid domain string that identifies the WebAuthn Relying Party on whose behalf a given authentication ceremony is being performed
     */
    @NonNull final String rpId;

    /**
     * This member represents a challenge that the selected authenticator signs, along with other data, when producing an authentication assertion.
     */
    @NonNull final byte[] challenge;

    /**
     * This OPTIONAL member contains a list of objects representing public key credentials acceptable to the caller
     */
    @NonNull final List<byte[]> allowList;

    /**
     * This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
     * The value is treated as a hint, and MAY be overridden by the client.
     */
    long timeoutMs;

    /**
     *
     * @param rpId              The origin's effective domain.
     * @param challenge         This member represents a challenge that the selected authenticator signs,
     *                          along with other data, when producing an authentication assertion.
     * @param allowedCredentials This OPTIONAL member contains a list of objects representing public key credentials acceptable to the caller,
     *                           in descending order of the caller’s preference (the first item in the list is the most preferred credential,
     *                           and so on down the list).
     */
    public GetAssertionOptions(@NonNull String rpId, @NonNull byte[] challenge, @NonNull List<byte[]> allowedCredentials) {
        this.rpId = rpId;
        this.challenge = challenge;
        this.allowList = allowedCredentials;
    }

    /**
     * @param timeout This OPTIONAL member specifies a time, in seconds, that the caller is willing to wait for the call to complete.
     * The value is treated as a hint, and MAY be overridden by the client.
     * @return this object
     */
    public GetAssertionOptions timeoutMs(@Nullable long timeout) {
        this.timeoutMs = timeout;
        return this;
    }

    protected GetAssertionOptions(Parcel in) {
        rpId = in.readString();
        challenge = in.createByteArray();
        allowList = new ArrayList<>();
        for (int i = in.readInt(); i > 0; i--) {
            allowList.add(in.createByteArray());
        }
        timeoutMs = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(rpId);
        dest.writeByteArray(challenge);
        dest.writeInt(allowList.size());
        for (byte[] credentialId : allowList) {
            dest.writeByteArray(credentialId);
        }
        dest.writeLong(timeoutMs);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<GetAssertionOptions> CREATOR = new Creator<GetAssertionOptions>() {
        @Override
        public GetAssertionOptions createFromParcel(Parcel in) {
            return new GetAssertionOptions(in);
        }

        @Override
        public GetAssertionOptions[] newArray(int size) {
            return new GetAssertionOptions[size];
        }
    };
}
