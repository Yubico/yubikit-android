# FIDO Module for YubiKit Android
**FIDO** is a lightweight wrapper around the existing [Android APIs](https://developers.google.com/android/reference/com/google/android/gms/fido/Fido).
It supports a subset of FIDO2. However, PIN is not yet supported in the Android platform.

## Prerequisites <a name="prerequisites"></a>

**YubiKit** requires at minimum Java 7 and Android 7.0. Future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

In order to allow an Android app to use the FIDO2 APIs to register and sign credentials, your WebAuthn server (relying party) needs to host an assetlinks.json file on https://<rp_id>/.well-known/assetlinks.json.  
[Here is a sample of assetlinks.json](https://demo.yubico.com/.well-known/assetlinks.json).  
The property `package_name` matches the `applicationId` in `build.gradle` and the `sha256_cert_fingerprints` matches the fingerprint of my signing key.

###Some of the ways to find the fingerprint:
#### Terminal 
Open Terminal and type the command:
```
keytool -list -v -keystore <your_keystore_name> -alias <your_alias_name>
```
 where:  
`your_keystore_name` is the path and name of the keystore, including the .keystore extension.  
`your_alias_name` is the alias that you assigned to the certificate when you created it.  
 Example for debug keystore:  
 
```
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
```
  
#### Android Studio
1. Open Android Studio.
2. Open Your Project.
3. Click on Gradle (From Right Side Panel, you will see Gradle Bar).
4. Click on Refresh (Click on Refresh from Gradle Bar, you will see List Gradle scripts of your Project).
5. Click on Your Project (Your Project Name form List).
6. Click on Tasks/Android.
7. Double Click on signingReport (You will get MD5, SHA1 and SHA-256 in Run Bar).

#### App signing    
If you are using [App Signing](https://support.google.com/googleplay/android-developer/answer/7384423?hl=en), you will find it on the app signing page of the Play Console.

## Integration steps <a name="integration_steps"></a>
###Download
####Gradle:

```gradle
dependencies {  
  // core library, connection detection, and raw commands communication with yubikey
  implementation 'com.yubico.yubikit:fido:$yubikitVersion'
  
  // google play services for FIDO
  implementation 'com.google.android.gms:play-services-fido:18.0.0'
}
```
And in `gradle.properties` set latest version. Example:
```gradle
yubikitVersion=1.0.0-beta04
```
####Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>fido</artifactId>
  <version>1.0.0-beta04</version>
</dependency>
```

###Using Library <a name="using_lib"></a>
1. Create an instance of `Fido2ClientApi` and provide the application context:
```java
    Fido2ClientApi clientApi = new Fido2ClientApi(context);
```
2. Invoke `registerKey` when received request from auth server to make credential
```java
    // this method should be invoked when received all properties from server:
    // userId, relying party, supported algorithms, etc
    private void onReceivedRequestFromServer(MakeCredentialOptions options) {
        // start registering key when received response from
        clientApi.registerKey(options, clientApiCallback);        
    }
```
3. Invoke `authenticateWithKey` when received request from auth server to get assertion
```java
    // this method should be invoked when all properties are received from server:
    // relying party, credentials id, challenge
    private void onReceivedRequestFromServer(GetAssertionOptions options) {
        // assert/authenticate key
        clientApi.authenticateWithKey(options, clientApiCallback);        
    }
```
4. Both methods `registerKey` and `authenticateWithKey` requires callback that needs to launch special Fido activity that will handle communication with authenticator (platform or cross-platform). Provide parent activity that is going to handle onActivityResult
```java
    private Callback clientApiCallback = new Callback() {
            @Override
            public void onSuccess() {
                try {
                    clientApi.launch(MyActivity.this);
                } catch (IntentSender.SendIntentException e) {
                    // handle error
                }
            }

            @Override
            public void onError(@NonNull Throwable throwable) {
                // handle error
            }
        };

```
5. Within `onActivityResult` handle results from Fido activity with method `getAuthenticatorResponse` and send it back to server
```java
    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        try {
            AuthenticatorResponse response = clientApi.getAuthenticatorResponse(Fido2ClientApi.GET_ASSERTION_REQUEST_CODE, Activity.RESULT_CANCELED, null);
            if (response instanceof MakeCredentialResponse) {
                // send all information to server to finish registration process
            } else if (response instanceof GetAssertionResponse) {
                // send all information to server to finish assertion process
            }
        } catch (FidoException e) {
            // show UI for error
        } catch (OperationCanceledException e) {
            // this happens if user clicked back button
        }

        super.onActivityResult(requestCode, resultCode, data);
    }
```

### Using the Demo Application <a name="using_demo"></a>
FIDO 2 demo shows a complete example of how to use the library and FIDO2 including requests from server and validation.

Just run app, select FIDO2 demo pivot in navigation drawer, create an account (this account lives only 24 hours) and tap FAB button to add 2nd factor authentication with fingerprint or YubiKey. On next login you will have to use that authenticator to be able to sign in.  
Our [demo web service](https://demo.yubico.com/webauthn) provides the same functionality

## Additional Resources <a name="additional_resources"></a>
Yubico - [What is FIDO2 and Web Authentication](https://developers.yubico.com/FIDO2/)  
W3C - [Web Authentication specification](https://www.w3.org/TR/webauthn)  
FIDO - [FIDO2](https://fidoalliance.org/fido2/)  
FIDO - [CTAP](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html)  
![]()
