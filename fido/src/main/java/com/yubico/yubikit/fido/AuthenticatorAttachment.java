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

import com.google.android.gms.fido.fido2.api.common.Attachment;
import java.util.Locale;
import androidx.annotation.NonNull;

/**
 *
 * This enumeration’s values describe authenticators' attachment modalities. Relying Parties use this for two purposes:
 * to express a preferred authenticator attachment modality when calling navigator.credentials.create() to create a credential, and
 * to inform the client of the Relying Party's best belief about how to locate the managing authenticators of the credentials listed in allowCredentials when calling navigator.credentials.get().
 *
 * platform
 * This value indicates platform attachment.
 *
 * cross-platform
 * This value indicates cross-platform attachment.
 */
public enum AuthenticatorAttachment {
    PLATFORM(Attachment.PLATFORM.toString()),
    CROSS_PLATFORM(Attachment.CROSS_PLATFORM.toString());

    @NonNull
    private final String value;

    AuthenticatorAttachment(String attachment) {
        value = attachment;
    }

    public String toString() {
        return value;
    }

    public static AuthenticatorAttachment fromString(@NonNull String attachment) throws UnsupportedAttachmentException {
        if (attachment != null) {
            for (AuthenticatorAttachment authenticatorAttachment : values()) {
                if (authenticatorAttachment.value.equals(attachment)) {
                    return authenticatorAttachment;
                }
            }
        }

        throw new UnsupportedAttachmentException(attachment);
    }

    Attachment toAttachment() {
        try {
            return Attachment.fromString(value);
        } catch (Attachment.UnsupportedAttachmentException e) {
            // this never happens because we check values on creation
            throw new IllegalStateException();
        }
    }

    public static class UnsupportedAttachmentException extends Exception {
        static final long serialVersionUID = 42L;

        public UnsupportedAttachmentException(String attachment) {
            super(String.format(Locale.ROOT, "Attachment %s not supported", attachment));
        }
    }
}
