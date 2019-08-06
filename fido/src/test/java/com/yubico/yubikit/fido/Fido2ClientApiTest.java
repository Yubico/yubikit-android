package com.yubico.yubikit.fido;

import android.app.Activity;
import android.content.IntentSender;
import android.util.Base64;

import com.yubico.yubikit.fido.exceptions.FidoException;
import com.yubico.yubikit.utils.Callback;
import com.yubico.yubikit.utils.OperationCanceledException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;

import java.util.Arrays;

import androidx.annotation.NonNull;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

@RunWith(AndroidJUnit4.class)
public class Fido2ClientApiTest {

    Fido2ClientApi clientApi;
    public static final String RP_ID = "demo.yubico.com";

    @Test
    public void clientUsage() {
        clientApi = new Fido2ClientApi(ApplicationProvider.getApplicationContext());

        Callback clientApiCallback = new Callback() {
            @Override
            public void onSuccess() {
                try {
                    clientApi.launch(Mockito.mock(Activity.class));
                } catch (IntentSender.SendIntentException e) {
                    Assert.assertNull(e);
                }
            }

            @Override
            public void onError(@NonNull Throwable throwable) {
                Assert.assertNull(throwable);
            }
        };

        MakeCredentialOptions options = new MakeCredentialOptions(
                new RelyingParty(RP_ID, "Example site"),
                new User(new byte[8], "a_user@example.com", "A. User"),
                new byte[16]
        );
        clientApi.registerKey(options, clientApiCallback);

        final byte[] credentialId =
                Base64.decode("NSdQCZVymMgjD4Ij3P/IGwS1x5YHBjumiRJEen0uSjRAmlHNdJE9ri+jxbAdbgc3VzND8TthC4jJp0KTjB+Ahw==", Base64.DEFAULT);
        GetAssertionOptions assertOptions = new GetAssertionOptions(RP_ID, new byte[16], Arrays.asList(credentialId));
        clientApi.authenticateWithKey(assertOptions, clientApiCallback);
        try {
            AuthenticatorResponse response = clientApi.getAuthenticatorResponse(Fido2ClientApi.GET_ASSERTION_REQUEST_CODE, Activity.RESULT_CANCELED, null);
            if (response instanceof MakeCredentialResponse) {

            } else if (response instanceof GetAssertionOptions) {

            }
        } catch (FidoException e) {
            Assert.assertNull(e);
        } catch (OperationCanceledException e) {
            Assert.assertNotNull(e);
        }
    }
}
