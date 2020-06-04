# OATH Module
The **OATH** module enables applications such as an authenticator app to store OATH TOTP and HOTP secrets on a YubiKey, and to retrieve OTPs.

It requires at minimum Java 7 or Android 4.4. Versions earlier than Android 8.0 may have been tested to a lesser extent.

## Integrating OATH Module <a name="integration_steps"></a>
### Download
#### Gradle

```gradle
dependencies {
  // core library, connection detection, and raw APDU commands communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // OATH
  implementation 'com.yubico.yubikit:oath:$yubikitVersion'
}
```
And in `gradle.properties` set the latest version; for example:
```gradle
yubikitVersion=1.0.0-beta05
```
#### Maven
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

### Using OATH Library <a name="using_lib"></a>

This module requires the YubiKit core module to detect the `YubikeySession` (see the [YubiKit README](../yubikit/README.md)).

First, create an `OathApplication` to select the OATH applet on the YubiKey.
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

In addition, the `OathApplication` provides an interface for setting/validating a password on credential storage, calculating all credentials, and resetting the OATH application to its default state. For the complete list of methods look at the [`OathApplication` class documentation](src/main/java/com/yubico/yubikit/oath/OathApplication.java).

The **OATH** module also provides a class for defining an OATH `CredentialData`. Use its factory method `Credential.parseUri` to parse the credential parameters from the Uri of the [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

### Using Demo Application <a name="using_demo"></a>
1. Run the [demo app](../YubikitDemo).
2. Select "OATH demo" in the navigation drawer.
3. Plug in the YubiKey and click the + FAB button to add a credential.
4. To test, use one of the services that provides QR codes and authentication with TOTP as second factor authentication; for example, [https://demo.yubico.com/playground](https://demo.yubico.com/playground), or other services that provide second factor authentication with an authenticator app, such as Facebook, Google, Amazon, Microsoft, etc.

## Additional Resources <a name="additional_resources"></a>
* [YKOATH Protocol Specification](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
