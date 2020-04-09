# FIDO Module
The **FIDO** module is a lightweight wrapper around the existing [Android APIs](https://developers.google.com/android/reference/com/google/android/gms/fido/Fido).
The current Android APIs support a subset of FIDO2 specification. For example, PIN support for external authenticators is not yet available.

## Prerequisites <a name="prerequisites"></a>

**YubiKit** requires at minimum Java 7 and Android 7.0. Future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

### Interoperability with your WebAuthn server
Use the [Digital Asset Links JSON file](https://developers.google.com/identity/fido/android/native-apps) to enable users to share WebAuthn credentials across your website and Android app. You must declare an association by hosting the `assetlinks.json` on your WebAuthn server, and adding a link to the JSON file in your app's manifest.

For example, if you want to associate `https://demo.yubico.com` with the YubiKit demo app `com.yubico.yubikit.demo` you must create and host the JSON file at `https://demo.yubico.com/.well-known/assetlinks.json`. 

The property `package_name` must match the `applicationId` in `build.gradle` and the `sha256_cert_fingerprints` must match the fingerprint of the signing key. If you need help finding the app fingerprint then go to the `Find your application's fingerprint` section below.
    
See the following sample from `assetlinks.json` the Yubico demo site:
    
```json
[{
"relation": ["delegate_permission/common.handle_all_urls"],
"target": {
    "namespace": "android_app",
    "package_name": "com.yubico.yubikit.demo",
    "sha256_cert_fingerprints": [
    "4D:FF:F8:BA:C0:0C:6E:27:BC:C8:9C:64:DC:83:44:AE:A7:75:EE:38:BE:DB:0C:60:1F:A4:E1:66:4A:CD:C2:03"
    ]
}
}]
```

### Find the application fingerprint
You can find the app fingerprint in the terminal or in Android Studio.

#### Terminal 
Open the terminal and type the following command:
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
### Download
#### Gradle:

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
yubikitVersion=1.0.0-beta05
```
#### Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>fido</artifactId>
  <version>1.0.0-beta05</version>
</dependency>
```

### Using Library <a name="using_lib"></a>
1. Create an instance of `Fido2ClientApi` and provide the application context:
```java
    Fido2ClientApi clientApi = new Fido2ClientApi(context);
```
2. Invoke `registerKey` when the server requests to make a credential a.k.a. register.
```java
    // this method should be invoked when received all properties from server:
    // userId, relying party, supported algorithms, etc
    private void onReceivedRequestFromServer(MakeCredentialOptions options) {
        // start registering key when received response from
        clientApi.registerKey(options, clientApiCallback);        
    }
```
3. Invoke `authenticateWithKey` when the server requests an assertion a.k.a. authenticate
```java
    // this method should be invoked when all properties are received from server:
    // relying party, credentials id, challenge
    private void onReceivedRequestFromServer(GetAssertionOptions options) {
        // assert/authenticate key
        clientApi.authenticateWithKey(options, clientApiCallback);        
    }
```
4. Both methods `registerKey` and `authenticateWithKey` requires callback that needs to launch special Fido activity that will handle communication with the authenticator (platform or cross-platform). Provide parent activity that is going to handle onActivityResult.
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
5. Within `onActivityResult` method, get the `AuthenticatorResponse` from FIDO2 activity and send it back to the server to complete the WebAuthn operation.
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
The FIDO 2 demo shows a complete example of how to use the library and FIDO2 including server requests and validation.

1. Run app
1. Select FIDO2 demo pivot in navigation drawer
1. Create an account (this account lives only 24 hours) and tap FAB button to add 2nd factor authentication with a fingerprint or YubiKey. On the next login you must use that factor to sign in.  

Yubico's [WebAuthn demo site](https://demo.yubico.com/webauthn) provides similar functionality

## Additional Resources <a name="additional_resources"></a>
* [Yubico - What is FIDO2 and Web Authentication](https://developers.yubico.com/FIDO2/)  
* [W3C Web Authentication specification](https://www.w3.org/TR/webauthn)  
* [FIDO Alliance FIDO2 resources](https://fidoalliance.org/fido2/)  
* [FIDO Alliance CTAP2 specification](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html)  

