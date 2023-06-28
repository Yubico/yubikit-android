/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The request generated multiple assertions, and a choice must be made by the user.
 * Once selected, call {@link #select(int)} to get an assertion.
 */
public class MultipleAssertionsAvailable extends Throwable {
    private final byte[] clientDataJson;
    private final List<Ctap2Session.AssertionData> assertions;

    MultipleAssertionsAvailable(byte[] clientDataJson, List<Ctap2Session.AssertionData> assertions) {
        super("Request returned multiple assertions");

        this.clientDataJson = clientDataJson;
        this.assertions = assertions;
    }

    /**
     * Get the number of assertions returned by the Authenticators.
     *
     * @return the number of assertions available
     */
    public int getAssertionCount() {
        return assertions.size();
    }

    /**
     * The list of users for which credentials are stored by the Authenticator.
     * The indexes of the user objects correspond to the value which should be passed to select()
     * to select a response.
     * <p>
     * NOTE: If PIV/UV wasn't provided to the call to {@link BasicWebAuthnClient#getAssertion}
     * then user information may not be available, in which case this method will throw an exception.
     *
     * @return a list of available users.
     * @throws UserInformationNotAvailableError in case PIN/UV wasn't provided
     */
    public List<PublicKeyCredentialUserEntity> getUsers() throws UserInformationNotAvailableError {
        List<PublicKeyCredentialUserEntity> users = new ArrayList<>();
        for (Ctap2Session.AssertionData assertion : assertions) {
            try {
                users.add(ConversionUtils.PublicKeyCredentialUserEntityFromMap(Objects.requireNonNull(assertion.getUser())));
            } catch (NullPointerException e) {
                throw new UserInformationNotAvailableError();
            }
        }
        return users;
    }

    /**
     * Selects which assertion to use by index. These indices correspond to those of the List
     * returned by {@link #getUsers()}. This method can only be called once to get a single response.
     *
     * @param index The index of the assertion to return.
     * @return A WebAuthn assertion response.
     */
    public AuthenticatorAssertionResponse select(int index) {
        if (assertions.isEmpty()) {
            throw new IllegalStateException("Assertion has already been selected");
        }
        Ctap2Session.AssertionData assertion = assertions.get(index);
        assertions.clear();

        final Map<String, ?> user = Objects.requireNonNull(assertion.getUser());
        final Map<String, ?> credential = Objects.requireNonNull(assertion.getCredential());
        return new AuthenticatorAssertionResponse(
                assertion.getAuthencticatorData(),
                clientDataJson,
                assertion.getSignature(),
                Objects.requireNonNull((byte[]) user.get(PublicKeyCredentialUserEntity.ID)),
                Objects.requireNonNull((byte[]) credential.get(PublicKeyCredentialDescriptor.ID))
        );
    }
}
