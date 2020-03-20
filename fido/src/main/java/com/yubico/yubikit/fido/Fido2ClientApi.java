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

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.PackageManager;
import android.text.TextUtils;
import android.util.Log;

import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria;
import com.google.android.gms.fido.fido2.api.common.ErrorCode;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity;
import com.google.android.gms.tasks.OnCanceledListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.yubico.yubikit.fido.exceptions.FidoIOException;
import com.yubico.yubikit.fido.exceptions.FidoSecurityException;
import com.yubico.yubikit.fido.exceptions.FidoTimeoutException;
import com.yubico.yubikit.fido.exceptions.FidoUnknownException;
import com.yubico.yubikit.utils.Callback;
import com.yubico.yubikit.fido.exceptions.FidoException;
import com.yubico.yubikit.utils.OperationCanceledException;
import com.yubico.yubikit.utils.PackageUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/**
 * Api that represents communication with secure hardware for FIDO2
 * Uses Fido API {@link com.google.android.gms.fido.fido2.Fido2ApiClient}
 * Diagram how FIDO2/WebAuthN works: https://developers.yubico.com/FIDO2/
 */
public class Fido2ClientApi {

    public static final int MAKE_CREDENTIAL_REQUEST_CODE = 0xf1d0;
    public static final int GET_ASSERTION_REQUEST_CODE = 0xf1d0 + 1;
    private static final String TAG = "Fido2ClientApi";

    /**
     * Readiness to open activity that communicates with authenticator
     * 2 possible values: MAKE_CREDENTIAL_REQUEST_CODE or GET_ASSERTION_REQUEST_CODE
     */
    private Integer requestCode;
    private PendingIntent pendingIntent;

    private String rpId;

    private Fido2ApiClient fido2ApiClient;
    private Context context;

    public Fido2ClientApi(@NonNull Context context) {
        this.context = context;
        fido2ApiClient = Fido.getFido2ApiClient(context);
    }

    /**
     * Registration Ceremony
     * The ceremony where a user, a Relying Party, and the user’s client (containing at least one authenticator)
     * work in concert to create a public key credential and associate it with the user’s Relying Party account.
     * Note that this includes employing a test of user presence or user verification.
     * Invoke when you start registration process with data received from backend during registration_begin request
     *
     * @param options data received from backend
     * @param callback invoked with result of async operation
     */
    public void registerKey(@NonNull final MakeCredentialOptions options, @NonNull final Callback callback) {
        rpId = options.rp.id;
        if (!validateRpId(rpId)) {
            callback.onError(new IllegalArgumentException("The RP ID specified uses an invalid syntax: \"" + rpId + "\"."));
        }
        prepareMakeCredentialTask(options).addOnSuccessListener(new OnSuccessListener<PendingIntent>() {
            @Override
            public void onSuccess(PendingIntent fido2PendingIntent) {
                pendingIntent = fido2PendingIntent;
                requestCode = MAKE_CREDENTIAL_REQUEST_CODE;
                callback.onSuccess();
            }
        }).addOnFailureListener(new OnFailureListener() {
            @Override
            public void onFailure(@NonNull Exception e) {
                callback.onError(e);
            }
        }).addOnCanceledListener(new OnCanceledListener() {
            @Override
            public void onCanceled() {
                callback.onError(new OperationCanceledException());
            }
        });
    }

    /**
     * Launch User Verification Activity
     * where authenticator locally authorizes the invocation of the authenticatorMakeCredential and authenticatorGetAssertion operations.
     * User verification MAY be instigated through various authorization gesture modalities;
     * for example, through a touch plus pin code, password entry, or biometric recognition (e.g., presenting a fingerprint) [ISOBiometricVocabulary].
     * <p>
     * Invoke that when pending intent prepared and requestCode set to value
     *
     * @param parent activity that used to launch pending intent, it's going to stay on back stack when Authenticator activity is visible
     *               this activity should handle onActivityResult()
     * @throws IntentSender.SendIntentException if intent was not properly constructed
     */
    public void launch(Activity parent) throws IntentSender.SendIntentException {
        if (pendingIntent == null) {
            throw new IllegalStateException("This call needs to be invoked after registerKey or authenticateWithKey");
        }

        // Start a FIDO2 registration/authentication request.
        parent.startIntentSenderForResult(
                pendingIntent.getIntentSender(),
                requestCode,
                null,
                0,
                0,
                0,
                null);

    }

    /**
     * Launch User Verification Activity
     * where authenticator locally authorizes the invocation of the authenticatorMakeCredential and authenticatorGetAssertion operations.
     * User verification MAY be instigated through various authorization gesture modalities;
     * for example, through a touch plus pin code, password entry, or biometric recognition (e.g., presenting a fingerprint) [ISOBiometricVocabulary].
     * <p>
     * Invoke that when pending intent prepared and requestCode set to value
     *
     * @param parent fragment that used to launch pending intent, it's going to stay on back stack when Authenticator activity is visible
     *               this fragment should handle onActivityResult()
     * @throws IntentSender.SendIntentException if intent was not properly constructed
     */
    public void launch(Fragment parent) throws IntentSender.SendIntentException {
        if (pendingIntent == null) {
            throw new IllegalStateException("This call needs to be invoked after registerKey or authenticateWithKey");
        }

        // Start a FIDO2 registration/authentication request.
        parent.startIntentSenderForResult(
                pendingIntent.getIntentSender(),
                requestCode,
                null,
                0,
                0,
                0,
                null);
    }

    /**
     * Invoke when you start assertion/authentication process with data received from backend during authentication_begin request
     *
     * @param options data received from backend
     * @param callback invoked when prepared intent for FIDO activity
     */
    public void authenticateWithKey(@NonNull final GetAssertionOptions options, @NonNull final Callback callback) {
        rpId = options.rpId;
        if (!validateRpId(rpId)) {
            callback.onError(new IllegalArgumentException("The RP ID specified uses an invalid syntax: \"" + rpId + "\"."));
        }
        prepareGetAssertionTask(options).addOnSuccessListener(new OnSuccessListener<PendingIntent>() {
            @Override
            public void onSuccess(PendingIntent fido2PendingIntent) {
                pendingIntent = fido2PendingIntent;
                requestCode = GET_ASSERTION_REQUEST_CODE;
                callback.onSuccess();
            }
        }).addOnFailureListener(new OnFailureListener() {
            @Override
            public void onFailure(@NonNull Exception e) {
                callback.onError(e);
            }
        }).addOnCanceledListener(new OnCanceledListener() {
            @Override
            public void onCanceled() {
                callback.onError(new OperationCanceledException());
            }
        });
    }

    /**
     * Invoke when activity that you provided in launch method will get onActivityResult invoked
     * Pass all params that you've got with onActivityResult call
     *
     * @param requestCode only {@value MAKE_CREDENTIAL_REQUEST_CODE} and {@value GET_ASSERTION_REQUEST_CODE} will be handled
     * @param resultCode  RESULT_OK in case of success, RESULT_CANCELED when operation was cancelled, otherwise error
     * @param data        contains serialized data of response or error
     * @return results of key registration or authentication process on authenticator
     * @throws FidoException when received an error from authenticator or during communication with it
     * @throws OperationCanceledException when operation was canceled by user
     */
    public AuthenticatorResponse getAuthenticatorResponse(int requestCode, int resultCode, @Nullable Intent data) throws FidoException, OperationCanceledException {
        if (requestCode != MAKE_CREDENTIAL_REQUEST_CODE && requestCode != GET_ASSERTION_REQUEST_CODE) {
            // do nothing if request code is not related to Fido activity
            return null;
        }
        if (resultCode == Activity.RESULT_OK && data != null && data.hasExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)) {
            switch (requestCode) {
                case MAKE_CREDENTIAL_REQUEST_CODE:
                    AuthenticatorAttestationResponse attestationResponse = AuthenticatorAttestationResponse.deserializeFromBytes(data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA));
                    return new MakeCredentialResponse(attestationResponse);
                case GET_ASSERTION_REQUEST_CODE:
                    AuthenticatorAssertionResponse assertionResponse = AuthenticatorAssertionResponse.deserializeFromBytes(data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA));
                    return new GetAssertionResponse(assertionResponse);
            }
        } else if (resultCode == Activity.RESULT_CANCELED) {
            throw new OperationCanceledException();
        } else if (data.hasExtra(Fido.FIDO2_KEY_ERROR_EXTRA)) {
            parseError(data);
        }

        // this case should never be reached
        throw new FidoException("Unknown Error");
    }

    /**
     * Extracts error from intent and converts into proper exception, sets error {@code error} that needs to be observer
     *
     * @param data intent received from authenticator activity in onActivityResult
     */
    private void parseError(@NonNull Intent data) throws FidoException {
        AuthenticatorErrorResponse authError = AuthenticatorErrorResponse.deserializeFromBytes(data.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA));
        ErrorCode errorCode = authError.getErrorCode();
        Log.e(TAG, "Error code: " + errorCode + " error message: " + authError.getErrorMessage());
        // filtering low level error messages, because they don't look user friendly
        String message = (!TextUtils.isEmpty(authError.getErrorMessage()) && !authError.getErrorMessage().toLowerCase().contains("low level")) ? authError.getErrorMessage() : "";
        switch (errorCode) {
            case TIMEOUT_ERR:
                throw new FidoTimeoutException(authError.getErrorMessage());
            case NETWORK_ERR:
                throw new FidoIOException(authError.getErrorMessage());
            case UNKNOWN_ERR:
                throw new FidoUnknownException(message.isEmpty() ? "Key is not recognized or already added" : message);
            case SECURITY_ERR:
                printSignatureVerificationMessage();
                throw new FidoSecurityException(message.isEmpty() ? "Verify your signature whitelisted on webauthn server" : message);
            case INVALID_STATE_ERR:
            case NOT_SUPPORTED_ERR:
            case ABORT_ERR:
            case ENCODING_ERR:
            case CONSTRAINT_ERR:
            case DATA_ERR:
            case NOT_ALLOWED_ERR:
            case ATTESTATION_NOT_PRIVATE_ERR:
            default:
                throw new FidoException(authError.getErrorMessage());
        }
    }

    /**
     * This prints a message to developer in case if server misses assetlinks.json and gets Security Error response
     * {@see https://developers.google.com/identity/fido/android/native-apps}
     */
    private void printSignatureVerificationMessage() {
        PackageManager pm = context.getPackageManager();
        String packageName = context.getPackageName();
        List<String> signatures = PackageUtils.getCertSha256(pm, packageName);
        StringBuilder sb = new StringBuilder();
        sb.append("This error might be caused by a missing or incorrect 'assetlinks.json' file.\n");
        sb.append("This file must contain an entry for this app to be allowed, with the following values:\n");
        sb.append("  package_name: \"").append(packageName).append("\"\n");
        sb.append("  sha256_cert_fingerprint: [");
        String delim = "";
        for (String signature : signatures) {
            sb.append(delim).append("\"").append(signature).append("\"");
            delim = "\n";
        }
        sb.append("]\n");
        sb.append("The file must be reachable at https://").append(rpId).append("/.well-known/assetlinks.json\n");
        sb.append("sample: https://demo.yubico.com/.well-known/assetlinks.json\n");
        Log.e(TAG, sb.toString());
    }

    /**
     * Extra verification that rpId is valid server host without path
     *
     * @param rpId relying party id, has to be host name
     * @return true if it's valid, otherwise false
     */
    private boolean validateRpId(String rpId) {
        try {
            URL url = new URL("https://" + rpId);
            if (!rpId.equals(url.getHost()) || !url.getPath().isEmpty()) {
                return false;
            }
        } catch (MalformedURLException e) {
            return false;
        }
        return true;
    }

    /**
     * Converts {@link MakeCredentialOptions} into {@link  PublicKeyCredentialCreationOptions} and creates task to form pending intent
     *
     * @param options data received from backend (registration_begin request)
     * @return task that will provide pending intent of authenticator activity upon successful completion
     */
    private Task<PendingIntent> prepareMakeCredentialTask(@NonNull MakeCredentialOptions options) {

        PublicKeyCredentialCreationOptions.Builder builder = new PublicKeyCredentialCreationOptions.Builder()
                .setRp(new PublicKeyCredentialRpEntity(options.rp.id, options.rp.name, options.rp.icon))
                .setUser(new PublicKeyCredentialUserEntity(options.user.id, options.user.name, options.user.icon, options.user.displayName))
                .setChallenge(options.challenge)
                .setTimeoutSeconds(options.timeoutMs / 1000.0);

        if (options.excludeList != null && !options.excludeList.isEmpty()) {
            List<PublicKeyCredentialDescriptor> descriptors = new ArrayList<>();
            for (byte[] credentialId : options.excludeList) {
                descriptors.add(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY.toString(), credentialId, null));
            }
            builder.setExcludeList(descriptors);
        }

        List<PublicKeyCredentialParameters> parameters = new ArrayList<>();
        for (Integer algorithm : options.algorithms) {
            parameters.add(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY.toString(), algorithm));
        }
        builder.setParameters(parameters);

        if (options.attestation != null) {
            builder.setAttestationConveyancePreference(options.attestation.toAttestationConveyancePreference());
        }

        if (options.attachment != null) {
            builder.setAuthenticatorSelection(new AuthenticatorSelectionCriteria.Builder().setAttachment(options.attachment.toAttachment()).build());
        }

        return fido2ApiClient.getRegisterPendingIntent(builder.build());
    }

    /**
     * Converts {@link GetAssertionOptions} into {@link  PublicKeyCredentialCreationOptions} and creates task to form pending intent
     *
     * @param options data received from backend (authentication_begin request)
     * @return task that will provide pending intent of authenticator activity upon successful completion
     */
    private Task<PendingIntent> prepareGetAssertionTask(@NonNull GetAssertionOptions options) {

        PublicKeyCredentialRequestOptions.Builder builder = new PublicKeyCredentialRequestOptions.Builder()
                .setRpId(options.rpId)
                .setChallenge(options.challenge)
                .setTimeoutSeconds(options.timeoutMs / 1000.0);

        List<PublicKeyCredentialDescriptor> descriptors = new ArrayList<>();
        for (byte[] credentialId : options.allowList) {
            descriptors.add(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY.toString(), credentialId, null));
        }
        builder.setAllowList(descriptors);

        return fido2ApiClient.getSignPendingIntent(builder.build());
    }
}

