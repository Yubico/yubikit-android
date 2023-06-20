package com.yubico.yubikit.fido.client;

/**
 * A ClientError indicating that UserEntity information isn't available for assertions returned by the Authenticator.
 * This happens when {@link BasicWebAuthnClient#getAssertion}
 * is called without providing PIV or UV, when returning discoverable credentials.
 */
public class UserInformationNotAvailableError extends ClientError {
    public UserInformationNotAvailableError() {
        super(Code.OTHER_ERROR, "User information is not available unless PIN/UV is provided");
    }
}
