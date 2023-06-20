/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.client;

/**
 * A subclass of {@link ClientError} used by {@link BasicWebAuthnClient} to indicate that makeCredential or
 * getAssertion was called without a PIN even though a PIN is required to complete the operation.
 * Client implementations may want to catch this and handle it differently than other ClientErrors.
 */
public class PinRequiredClientError extends ClientError {
    public PinRequiredClientError() {
        super(Code.BAD_REQUEST, "PIN required but not provided");
    }
}
