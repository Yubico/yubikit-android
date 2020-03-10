package com.yubico.yubikit.demo.fido

import android.app.Activity
import android.content.Context
import android.util.Base64

import com.yubico.yubikit.fido.AuthenticatorAttachment
import com.yubico.yubikit.fido.Fido2ClientApi
import com.yubico.yubikit.fido.GetAssertionOptions
import com.yubico.yubikit.fido.MakeCredentialOptions
import com.yubico.yubikit.fido.RelyingParty
import com.yubico.yubikit.fido.User
import com.yubico.yubikit.utils.OperationCanceledException

import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config

import java.util.Arrays
import java.util.concurrent.CountDownLatch

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.yubico.yubikit.utils.Callback

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.mockito.*

@RunWith(AndroidJUnit4::class)
//@RunWith(RobolectricTestRunner.class)
//@Config(manifest = Config.NONE)
class Fido2ViewModelTest {

    private val fidoApi = Fido2ClientApi(ApplicationProvider.getApplicationContext<Context>())

    @Spy
    /**
     * Spy allows us to call all the normal methods of the object
     * while still tracking every interaction, just as we would with a mock.
     *
     * Note: we don't rely on annotation here because we're using it
     * before MockitoAnnotations.initMocks invoked
     */
    private val mockApi = Mockito.spy(fidoApi)

    /**
     * Captor for Response callbacks. Populated by MockitoAnnotations.initMocks().
     * You can also use ArgumentCaptor.forClass(Callback.class) but you'd have to
     * cast it due to the type parameter.
     */
    @Captor
    private lateinit var callbackCaptor: ArgumentCaptor<Callback>

    private val model = Fido2ViewModel(mockApi)

    private val signal = CountDownLatch(1)

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
    }

    @Test
    fun registerKey() {
        val options = MakeCredentialOptions(
                RelyingParty(RP_ID, "Example site"),
                User(ByteArray(8), "a_user@example.com", "A. User"),
                ByteArray(16)
        ).authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
        model.registerKey(options)

        model.requestCode.observeForever {
            integer -> assertEquals(integer as Int, Fido2ViewModel.REGISTER_KEY)
            signal.countDown()
        }

        Mockito.verify(mockApi).registerKey(Mockito.any(MakeCredentialOptions::class.java), callbackCaptor.capture())
        callbackCaptor.value.onSuccess()

        // this is just to verify that callback/observer was invoked
        signal.await()
    }

    @Test
    fun authenticateWithKey() {
        val credentialId = Base64.decode("NSdQCZVymMgjD4Ij3P/IGwS1x5YHBjumiRJEen0uSjRAmlHNdJE9ri+jxbAdbgc3VzND8TthC4jJp0KTjB+Ahw==", Base64.DEFAULT)
        val options = GetAssertionOptions(RP_ID, ByteArray(16), Arrays.asList(credentialId))
        model.authenticateWithKey(options)

        model.requestCode.observeForever {
            integer -> assertEquals(integer as Int, Fido2ViewModel.AUTHENTICATE_WITH_KEY)
            signal.countDown()
        }

        Mockito.verify(mockApi).authenticateWithKey(Mockito.any(GetAssertionOptions::class.java), callbackCaptor.capture())
        callbackCaptor.value.onSuccess()
        signal.await()
    }


    @Test
    fun makeCredentialsCanceled() {
        model.onActivityResult(Fido2ClientApi.MAKE_CREDENTIAL_REQUEST_CODE, Activity.RESULT_CANCELED, null)
        // we can't serialize AuthenticatorAttestationResponse to simulate successful response
        // and we can't serialize AuthenticatorErrorResponse as well to simulate failure cases
        model.makeCredentialResponse.observeForever { makeCredentialResponse -> assertNull(makeCredentialResponse) }
        model.error.observeForever { throwable ->
            assertNotNull("Expected OperationCanceledException", throwable)
            assertTrue(throwable is OperationCanceledException)
            signal.countDown()
        }
        signal.await()
    }

    @Test
    fun getAssertionCanceled() {
        assertEquals(1, signal.count)
        model.onActivityResult(Fido2ClientApi.GET_ASSERTION_REQUEST_CODE, Activity.RESULT_CANCELED, null)

        // we can't serialize AuthenticatorAssertionResponse to simulate successful response
        model.assertionResponse.observeForever { getAssertionResponse -> assertNull(getAssertionResponse) }
        model.error.observeForever { throwable ->
            assertNotNull("Expected OperationCanceledException", throwable)
            assertTrue(throwable is OperationCanceledException)
            signal.countDown()
        }
    }

    companion object {
        val RP_ID = "demo.yubico.com"
    }
}
