# OATH Module for YubiKit Android
**OATH** allows applications, such as an authenticator app, to store OATH TOTP and HOTP secrets on a YubiKey, and to retrieve one-time passwords.

**OATH** requires at minimum  Java 7 or Android 4.4, future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
###Download
####Gradle:

```gradle
dependencies {  
  // core library, connection detection, and raw commands communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // OATH
  implementation 'com.yubico.yubikit:oath:$yubikitVersion'
  
  // Optional: dependency required for  QR scan code functionality (QrActivity)
  implementation 'com.google.android.gms:play-services-vision:18.0.0'
}
```
And in `gradle.properties` set latest version. Example:  
```gradle
yubikitVersion=1.0.0-beta04
```
#### Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta04</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>oath</artifactId>
  <version>1.0.0-beta04</version>
</dependency>
```

###Using Library <a name="using_lib"></a>

This module requires usage of yubikit core library to detect `YubikeySession` (see [Using YubiKit](../yubikit/README.md))  
And use it to create `OathApplication` to select OATH applet on YubiKey  
```java

    OathApplication oathApplication = new OathApplication(session);
    // run provided command/operation (put/calculate/delete/etc)
    // example:
    //    try {
    //        oathApplication.putCredential(Credential.parseUri(uri), appInfo);
    //    } catch (ParseUriException | IOException | ApduException e) {
    //        // handle errors
    //    }
    
```

The `OathApplication` provides a method for every command from the [YK OATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html) to add, remove, list and calculate credentials. In addition to these requests, the `OathApplication` provides an interface for setting/validating a password on credential storage, calculating all credentials and resetting the OATH application to its default state. For the complete list of methods look at the `OathApplication` code level documentation.  
**OATH YubiKit** also provides a class for defining an OATH `Credential`, which has a convenience initializer `Credential.parseUri` which can parse the credential parameters from Uri of [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

Authenticators often use QR codes to pass the URL for setting up the credentials. The built-in QR Code reader from YubiKit can be used to read the credential URL.

```java
        startActivityForResult(new Intent(context, QrActivity.class), REQUEST_SCAN_QR);
    ...
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_SCAN_QR) {
            if (resultCode == Activity.RESULT_OK && data != null) {
                Uri uri = data.getData();
                if (uri != null) {
                    Credential credential = Credential.parseUri(uri);
                    // ask to provide yubikey if it's not plugged in, then set up connection,
                    // select application and add credential using putCredential method
                    // (see steps above)
                }
            }
        }
    }
```

### Using the Demo Application <a name="using_demo"></a>
Run demo app, select "OATH demo" pivot in navigation drawer. Plug in YubiKey and click + FAB button to add credential.  
To test, use one of the services that provides QR codes and authentication with TOTP as 2nd factor auth.  
For example, [https://demo.yubico.com/playground](https://demo.yubico.com/playground)  
Or such services as Facebook, Google, Amazon, Microsoft, etc. All provide 2nd factor authentication with Authenticator app. This demo can be used as such.

## Additional Resources <a name="additional_resources"></a>
OATH - [YK OATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
