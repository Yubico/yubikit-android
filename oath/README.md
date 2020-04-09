# OATH Module
The **OATH** module enables applications, such as an authenticator app, to store OATH TOTP and HOTP secrets on a YubiKey, and to retrieve one-time passwords.

It requires at minimum Java 7 or Android 4.4. Future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
### Download
#### Gradle:

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
yubikitVersion=1.0.0-beta05
```
#### Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta05</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>oath</artifactId>
  <version>1.0.0-beta05</version>
</dependency>
```

### Using Library <a name="using_lib"></a>

This module requires the yubikit core module to detect the `YubikeySession` (see [Using YubiKit](../yubikit/README.md))

First, create an `OathApplication` to select OATH applet on YubiKey.  
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

Next, use the `OathApplication` to add, remove, list, and calculate credentials.

The `OathApplication` implements the YKOATH protocol. Refer to the [YKOATH protocol specification](https://developers.yubico.com/OATH/YKOATH_Protocol.html) for more details. 

In addition, the `OathApplication` provides an interface for setting/validating a password on credential storage, calculating all credentials and resetting the OATH application to its default state. For the complete list of methods look at the [`OathApplication` class documentation](src/main/java/com/yubico/yubikit/oath/OathApplication.java).  

The **OATH** module also provides a class for defining an OATH `Credential`. Use its convenience initializer `Credential.parseUri` to parse the credential parameters from Uri of [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

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
1. Run demo app
2. Select "OATH demo" pivot in navigation drawer
3. Plug in YubiKey and click + FAB button to add credential.  
   To test, use one of the services that provides QR codes and authentication with TOTP as 2nd factor auth.  
   For example, [https://demo.yubico.com/playground](https://demo.yubico.com/playground)  
   Or such services as Facebook, Google, Amazon, Microsoft, etc. All provide 2nd factor authentication with Authenticator app. This demo can be used as such.

## Additional Resources <a name="additional_resources"></a>
* [YKOATH Protocol Specification](https://developers.yubico.com/OATH/YKOATH_Protocol.html)